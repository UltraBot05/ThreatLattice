-- =====================================================================
-- 03_routines.sql  ThreatLattice stored functions and procedures
-- Owner: Akshansh Agrawal (PES2UG24CS045)
--
-- DELIMITER: a routine body contains ';' between its statements. The
-- mysql client would otherwise send the CREATE at the first ';' and
-- cut the body in half. DELIMITER $$ makes '$$' the end of the whole
-- CREATE, and we switch back to ';' at the end.
--
-- DROP ... IF EXISTS before each CREATE makes this file re-runnable.
--
-- Binary logging is on by default in MySQL 8.0, so every function must
-- say whether it is DETERMINISTIC / NO SQL / READS SQL DATA, or MySQL
-- refuses to create it (error 1418). We declare it honestly instead of
-- turning on log_bin_trust_function_creators.
-- =====================================================================

DELIMITER $$


-- ---------------------------------------------------------------------
-- fn_severity_band(score) -> 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' |
--                             'CRITICAL' | NULL
-- Maps a CVSS base score to its official severity band (same bands in
-- CVSS 3.x and 4.0). Used by the cve triggers to fill a missing
-- severity, and usable in any SELECT.
-- - DETERMINISTIC: same input always gives the same output, so MySQL
--   can cache/replicate it safely.
-- - NO SQL: it reads no tables, it is pure arithmetic.
-- - Checks run from the top, so each WHEN only needs a lower bound
--   (a score that reaches '>= 7.0' already failed '>= 9.0').
-- - Why a function and not a lookup table: the bands are a fixed rule
--   of the CVSS spec, not data that changes.
-- ---------------------------------------------------------------------
DROP FUNCTION IF EXISTS fn_severity_band $$
CREATE FUNCTION fn_severity_band(p_score DECIMAL(3,1))
RETURNS VARCHAR(8)
DETERMINISTIC
NO SQL
BEGIN
    RETURN CASE
        WHEN p_score IS NULL  THEN NULL
        WHEN p_score >= 9.0   THEN 'CRITICAL'
        WHEN p_score >= 7.0   THEN 'HIGH'
        WHEN p_score >= 4.0   THEN 'MEDIUM'
        WHEN p_score >= 0.1   THEN 'LOW'
        ELSE 'NONE'                          -- exactly 0.0
    END;
END $$


-- ---------------------------------------------------------------------
-- fn_cwe_cve_count(cwe_id) -> number of CVEs tagged with that CWE.
-- - READS SQL DATA: it queries a table but changes nothing.
-- - Counts the junction table only (no join to cve): every cve_cwe row
--   is a real CVE because of the foreign key, so the join adds nothing.
-- - COUNT(*) on the idx_cvecwe_cwe index; it never reads the cve rows.
-- - Unknown CWE -> 0, not an error (COUNT always returns a row).
-- ---------------------------------------------------------------------
DROP FUNCTION IF EXISTS fn_cwe_cve_count $$
CREATE FUNCTION fn_cwe_cve_count(p_cwe VARCHAR(12))
RETURNS INT
READS SQL DATA
BEGIN
    DECLARE v_count INT;
    SELECT COUNT(*) INTO v_count
    FROM   cve_cwe
    WHERE  cwe_id = p_cwe;
    RETURN v_count;
END $$


-- ---------------------------------------------------------------------
-- sp_create_investigation
-- Creates an investigation after checking that the user is active and
-- that the start node really exists. Called by the investigations API
-- (Abhigyan, B5): keep the parameter order and the OUT parameter.
--
--   CALL sp_create_investigation(user_id, title, type, node_id, notes, @id);
--   SELECT @id;
--
-- Why a procedure and not a plain INSERT from the API:
-- start_node_id can point at four different tables, so it cannot have
-- a foreign key. The procedure is the integrity check the FK cannot
-- be, and it runs inside the database for every client (API, report,
-- console), so nobody can skip it.
--
-- Transaction:
-- - START TRANSACTION ... COMMIT: the checks, the INSERT and the audit
--   row written by trigger trg_inv_ai either all happen or none do.
-- - FOR SHARE on the user row: a shared lock, so an admin cannot
--   deactivate the user between our check and our INSERT. Shared (not
--   FOR UPDATE) because other readers are fine, only writers must wait.
-- - EXIT HANDLER FOR SQLEXCEPTION: on any error (our SIGNAL, a CHECK
--   failure, a lost connection) undo everything with ROLLBACK, then
--   RESIGNAL so the caller still gets the original error code and
--   message. Without RESIGNAL the error would be swallowed and the
--   API would think the call succeeded.
-- - SIGNAL SQLSTATE '45000' = "unhandled user-defined exception", the
--   standard code for business-rule errors. Messages are written for
--   the UI to show as they are.
-- - Callers must NOT wrap the CALL in their own transaction (e.g.
--   withTransaction): START TRANSACTION inside the procedure would
--   silently commit the caller's open transaction first.
-- ---------------------------------------------------------------------
DROP PROCEDURE IF EXISTS sp_create_investigation $$
CREATE PROCEDURE sp_create_investigation(
    IN  p_user_id          BIGINT,
    IN  p_title            VARCHAR(200),
    IN  p_type             VARCHAR(20),
    IN  p_node_id          VARCHAR(20),
    IN  p_notes            TEXT,
    OUT p_investigation_id BIGINT
)
MODIFIES SQL DATA
BEGIN
    DECLARE v_users  INT DEFAULT 0;
    DECLARE v_active INT DEFAULT 0;
    DECLARE v_found  INT DEFAULT 0;
    DECLARE v_msg    VARCHAR(128);

    DECLARE EXIT HANDLER FOR SQLEXCEPTION
    BEGIN
        ROLLBACK;
        RESIGNAL;
    END;

    SET p_investigation_id = NULL;

    START TRANSACTION;

    -- 1. The user must exist and be active. COUNT + MAX always return
    --    one row, so there is no "no data" warning for a missing user.
    SELECT COUNT(*), COALESCE(MAX(is_active), 0)
    INTO   v_users, v_active
    FROM   app_user
    WHERE  user_id = p_user_id
    FOR SHARE;

    IF v_users = 0 THEN
        SET v_msg = CONCAT('user ', COALESCE(p_user_id, 'NULL'), ' does not exist');
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = v_msg;
    END IF;
    IF v_active = 0 THEN
        SET v_msg = CONCAT('user ', p_user_id, ' is deactivated');
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = v_msg;
    END IF;

    -- 2. A title is required (NOT NULL alone would accept '   ').
    IF p_title IS NULL OR TRIM(p_title) = '' THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'title is required';
    END IF;

    -- 3. The start node must exist in the table for its type. The CHECK
    --    on investigation.start_node_type would also reject a bad type,
    --    but only with a generic "constraint violated" message.
    CASE p_type
        WHEN 'CVE'       THEN SELECT COUNT(*) INTO v_found FROM cve              WHERE cve_id       = p_node_id;
        WHEN 'CWE'       THEN SELECT COUNT(*) INTO v_found FROM cwe              WHERE cwe_id       = p_node_id;
        WHEN 'CAPEC'     THEN SELECT COUNT(*) INTO v_found FROM capec            WHERE capec_id     = p_node_id;
        WHEN 'TECHNIQUE' THEN SELECT COUNT(*) INTO v_found FROM attack_technique WHERE technique_id = p_node_id;
        ELSE
            SET v_msg = CONCAT('invalid start node type ', COALESCE(p_type, 'NULL'),
                               ' (expected CVE, CWE, CAPEC or TECHNIQUE)');
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = v_msg;
    END CASE;

    IF v_found = 0 THEN
        SET v_msg = CONCAT('start node ', COALESCE(p_node_id, 'NULL'), ' does not exist');
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = v_msg;
    END IF;

    -- 4. All checks passed: insert. trg_inv_ai writes the audit row in
    --    this same transaction.
    INSERT INTO investigation (user_id, title, start_node_type, start_node_id, notes)
    VALUES (p_user_id, TRIM(p_title), p_type, p_node_id, p_notes);

    -- LAST_INSERT_ID() is per connection, so another user's insert at
    -- the same moment cannot change it.
    SET p_investigation_id = LAST_INSERT_ID();

    COMMIT;
END $$


-- ---------------------------------------------------------------------
-- sp_severity_breakdown(year)
-- Result set: severity, cve_count, avg_score for CVEs published in
-- that year, or across all years when p_year is NULL. Used by the
-- dashboard API (/api/stats/overview) and the report.
-- - Date range instead of YEAR(published_date) = p_year: wrapping the
--   column in a function hides it from idx_cve_published (full scan).
--   A plain range on the bare column can use the index.
-- - 'p_year IS NULL OR ...' gives one procedure for both "one year" and
--   "all years" instead of two copies of the query.
-- - COALESCE labels unscored CVEs 'UNSCORED' (same as v_severity_by_year).
-- - ORDER BY FIELD(...) sorts worst-first; sorting the strings would
--   give alphabetical order (CRITICAL, HIGH, LOW, MEDIUM ...).
-- ---------------------------------------------------------------------
DROP PROCEDURE IF EXISTS sp_severity_breakdown $$
CREATE PROCEDURE sp_severity_breakdown(IN p_year INT)
READS SQL DATA
BEGIN
    SELECT COALESCE(cvss_severity, 'UNSCORED') AS severity,
           COUNT(*)                            AS cve_count,
           ROUND(AVG(cvss_base_score), 2)      AS avg_score
    FROM   cve
    WHERE  p_year IS NULL
       OR (published_date >= MAKEDATE(p_year, 1)
           AND published_date < MAKEDATE(p_year + 1, 1))
    GROUP BY severity
    ORDER BY FIELD(severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNSCORED');
END $$


DELIMITER ;


-- ---------------------------------------------------------------------
-- Test calls (run by hand; expected results in the comments)
--   SELECT fn_severity_band(9.8), fn_severity_band(7.0), fn_severity_band(6.9),
--          fn_severity_band(0.1), fn_severity_band(0.0), fn_severity_band(NULL);
--     -> CRITICAL, HIGH, MEDIUM, LOW, NONE, NULL
--   SELECT fn_cwe_cve_count('CWE-79');      -> number of XSS CVEs
--   SELECT fn_cwe_cve_count('CWE-999999');  -> 0
--
--   CALL sp_severity_breakdown(2026);
--   CALL sp_severity_breakdown(NULL);
--
--   CALL sp_create_investigation(1, 'PHP2Shell chain', 'CVE', 'CVE-2026-109618', NULL, @id);
--   SELECT @id;                                   -> new investigation_id
--   CALL sp_create_investigation(1, 'x', 'CVE', 'CVE-2099-1', NULL, @id);
--     -> ERROR 1644 (45000): start node CVE-2099-1 does not exist
--   CALL sp_create_investigation(1, 'x', 'HOST', 'web01', NULL, @id);
--     -> ERROR 1644 (45000): invalid start node type HOST (expected ...)
--   CALL sp_create_investigation(999, 'x', 'CVE', 'CVE-2026-109618', NULL, @id);
--     -> ERROR 1644 (45000): user 999 does not exist
--   CALL sp_create_investigation(1, '   ', 'CVE', 'CVE-2026-109618', NULL, @id);
--     -> ERROR 1644 (45000): title is required
--   SELECT COUNT(*) FROM investigation;  -> unchanged after each failed call
-- ---------------------------------------------------------------------
