-- =====================================================================
-- 04_triggers.sql  ThreatLattice triggers
-- Owner: Akshansh Agrawal (PES2UG24CS045)
--
-- A trigger is code the database runs automatically on INSERT, UPDATE
-- or DELETE of a table. Nobody has to remember to call it, and no
-- client (API, ETL, console) can skip it.
--   BEFORE triggers can still change the row being written (NEW.x).
--   AFTER triggers see the final row and are used for side effects
--   such as the audit log.
-- A trigger runs inside the same transaction as the statement that
-- fired it: if the statement rolls back, the trigger's work does too.
--
-- Needs fn_severity_band from 03_routines.sql (files run in order).
-- DROP ... IF EXISTS makes this file re-runnable.
--
-- Known MySQL limitation: triggers do NOT fire for rows changed by a
-- foreign key cascade. Deleting an app_user cascades to their
-- investigations without trg_inv_ad audit rows. Users are deactivated
-- (is_active = FALSE) instead of deleted, so this does not happen in
-- normal use.
-- =====================================================================

DELIMITER $$


-- ---------------------------------------------------------------------
-- trg_cve_bi  BEFORE INSERT ON cve
-- If the loader gives a score but no severity (NVD leaves it out for
-- some CVSS 4.0 records), derive it from the score so every scored CVE
-- has a band for filtering and charts.
-- BEFORE, not AFTER: only a BEFORE trigger may assign NEW.cvss_severity.
-- An explicit severity from NVD is kept as it is.
-- ---------------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_cve_bi $$
CREATE TRIGGER trg_cve_bi
BEFORE INSERT ON cve
FOR EACH ROW
BEGIN
    IF NEW.cvss_severity IS NULL AND NEW.cvss_base_score IS NOT NULL THEN
        SET NEW.cvss_severity = fn_severity_band(NEW.cvss_base_score);
    END IF;
END $$


-- ---------------------------------------------------------------------
-- trg_cve_bu  BEFORE UPDATE ON cve
-- Same rule on UPDATE, plus re-scoring: if the score changes and the
-- UPDATE did not set a new severity itself, the old severity is now
-- stale, so it is re-derived from the new score.
-- Example: UPDATE cve SET cvss_base_score = 9.8 WHERE ... on a HIGH
-- CVE turns it CRITICAL automatically.
-- '<=>' is MySQL's NULL-safe equals: NULL <=> NULL is TRUE, whereas
-- NULL = NULL is NULL, which would make a NULL->score change invisible.
-- ---------------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_cve_bu $$
CREATE TRIGGER trg_cve_bu
BEFORE UPDATE ON cve
FOR EACH ROW
BEGIN
    IF NEW.cvss_base_score IS NOT NULL
       AND (NEW.cvss_severity IS NULL
            OR (NOT (NEW.cvss_base_score <=> OLD.cvss_base_score)
                AND NEW.cvss_severity <=> OLD.cvss_severity)) THEN
        SET NEW.cvss_severity = fn_severity_band(NEW.cvss_base_score);
    END IF;
END $$


-- ---------------------------------------------------------------------
-- Investigation audit triggers (AFTER INSERT / UPDATE / DELETE)
-- Every change to an investigation leaves a row in audit_log, shown on
-- the admin audit page. AFTER, because the row must really have been
-- written (and on INSERT the AUTO_INCREMENT id only exists after).
-- user_id is the investigation's owner. details is JSON built with
-- JSON_OBJECT, which escapes quotes in titles correctly (building the
-- JSON with CONCAT would break on a title like  Say "hi").
-- ---------------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_inv_ai $$
CREATE TRIGGER trg_inv_ai
AFTER INSERT ON investigation
FOR EACH ROW
BEGIN
    INSERT INTO audit_log (user_id, action, entity, entity_id, details)
    VALUES (NEW.user_id, 'INSERT', 'investigation', NEW.investigation_id,
            JSON_OBJECT('title',           NEW.title,
                        'start_node_type', NEW.start_node_type,
                        'start_node_id',   NEW.start_node_id));
END $$

-- UPDATE: keeps before and after values of the editable fields, so the
-- audit page can show what changed.
DROP TRIGGER IF EXISTS trg_inv_au $$
CREATE TRIGGER trg_inv_au
AFTER UPDATE ON investigation
FOR EACH ROW
BEGIN
    INSERT INTO audit_log (user_id, action, entity, entity_id, details)
    VALUES (NEW.user_id, 'UPDATE', 'investigation', NEW.investigation_id,
            JSON_OBJECT(
                'before', JSON_OBJECT('title', OLD.title, 'notes', OLD.notes,
                                      'start_node_type', OLD.start_node_type,
                                      'start_node_id',   OLD.start_node_id),
                'after',  JSON_OBJECT('title', NEW.title, 'notes', NEW.notes,
                                      'start_node_type', NEW.start_node_type,
                                      'start_node_id',   NEW.start_node_id)));
END $$

-- DELETE: only OLD exists. The title is copied into details because the
-- row itself is gone after this.
DROP TRIGGER IF EXISTS trg_inv_ad $$
CREATE TRIGGER trg_inv_ad
AFTER DELETE ON investigation
FOR EACH ROW
BEGIN
    INSERT INTO audit_log (user_id, action, entity, entity_id, details)
    VALUES (OLD.user_id, 'DELETE', 'investigation', OLD.investigation_id,
            JSON_OBJECT('title',           OLD.title,
                        'start_node_type', OLD.start_node_type,
                        'start_node_id',   OLD.start_node_id));
END $$


-- ---------------------------------------------------------------------
-- trg_user_au  AFTER UPDATE ON app_user
-- Logs ROLE_CHANGE only when the role actually changed. Other updates
-- (last_login_at on every login) would flood the log otherwise.
-- '<=>' again for NULL safety, though role is NOT NULL today.
-- ---------------------------------------------------------------------
DROP TRIGGER IF EXISTS trg_user_au $$
CREATE TRIGGER trg_user_au
AFTER UPDATE ON app_user
FOR EACH ROW
BEGIN
    IF NOT (NEW.role <=> OLD.role) THEN
        INSERT INTO audit_log (user_id, action, entity, entity_id, details)
        VALUES (NEW.user_id, 'ROLE_CHANGE', 'app_user', NEW.user_id,
                JSON_OBJECT('username', NEW.username,
                            'from', OLD.role, 'to', NEW.role));
    END IF;
END $$


DELIMITER ;


-- ---------------------------------------------------------------------
-- Test calls (run by hand; expected results in the comments)
--   INSERT INTO cve (cve_id, description, published_date, cvss_base_score)
--   VALUES ('CVE-2026-900001', 'trigger test', '2026-10-01', 7.5);
--   SELECT cvss_severity FROM cve WHERE cve_id = 'CVE-2026-900001';   -> HIGH
--   UPDATE cve SET cvss_base_score = 9.8 WHERE cve_id = 'CVE-2026-900001';
--   SELECT cvss_severity FROM cve WHERE cve_id = 'CVE-2026-900001';   -> CRITICAL
--   UPDATE cve SET cvss_base_score = 5.0, cvss_severity = 'HIGH'
--   WHERE cve_id = 'CVE-2026-900001';                                 -> stays HIGH (explicit)
--
--   CALL sp_create_investigation(1, 'audit test', 'CVE', 'CVE-2026-900001', NULL, @id);
--   UPDATE investigation SET title = 'audit test 2' WHERE investigation_id = @id;
--   DELETE FROM investigation WHERE investigation_id = @id;
--   SELECT action, entity_id, details FROM audit_log ORDER BY log_id DESC LIMIT 3;
--     -> DELETE, UPDATE (before/after), INSERT
--
--   UPDATE app_user SET role = 'admin' WHERE user_id = 1;
--   SELECT action, details FROM audit_log ORDER BY log_id DESC LIMIT 1;  -> ROLE_CHANGE
--   UPDATE app_user SET last_login_at = NOW() WHERE user_id = 1;      -> no new audit row
--
--   SHOW TRIGGERS;
-- ---------------------------------------------------------------------
