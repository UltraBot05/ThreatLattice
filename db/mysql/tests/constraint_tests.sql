-- =====================================================================
-- tests/constraint_tests.sql  Database-level validation tests
-- Owner: Akshansh Agrawal (PES2UG24CS045)
--
-- Shows that the DATABASE itself rejects bad data, whatever client
-- sends it: CHECK, ENUM, NOT NULL, UNIQUE / PK, FOREIGN KEY, JSON
-- type, and the SIGNALs inside sp_create_investigation.
--
-- Each F-test is ONE statement that must FAIL; the expected error is
-- in its comment. Each P-test must SUCCEED, followed by a SELECT whose
-- `result` column must say PASS.
--
-- Run (needs 01-04 loaded; --force keeps going after each expected
-- error, --comments -vvv echoes every test with its comment):
--   mysql --force --comments -vvv -u root -p threatlattice < db/mysql/tests/constraint_tests.sql
--
-- Test rows use IDs that real data never has (CVE-2099-*, CWE-99900x,
-- T999x, users tl_test_*, event tl-test-*). The file cleans them up at
-- the start and at the end, so it can be run any number of times.
-- Strict SQL mode (MySQL 8.0 default) is assumed: without it, a bad
-- ENUM value is stored as '' with a warning instead of an error.
-- =====================================================================


-- ---------------------------------------------------------------------
-- Cleanup of earlier runs (also repeated at the end).
-- Audit rows first, then users: deleting a user cascades to their
-- investigations (FK cascades fire no triggers, so no new audit rows).
-- ---------------------------------------------------------------------
DELETE FROM audit_log WHERE user_id IN (SELECT user_id FROM app_user WHERE username LIKE 'tl\_test\_%');
DELETE FROM app_user  WHERE username LIKE 'tl\_test\_%';
DELETE FROM security_event   WHERE slug LIKE 'tl-test-%';
DELETE FROM cve              WHERE cve_id LIKE 'CVE-2099-%';
DELETE FROM cwe              WHERE cwe_id IN ('CWE-999001', 'CWE-999002');
DELETE FROM attack_technique WHERE technique_id LIKE 'T999_%' AND is_subtechnique = TRUE;
DELETE FROM attack_technique WHERE technique_id LIKE 'T999_%';
DELETE FROM capec            WHERE capec_id = 'CAPEC-99901';
DELETE FROM cpe              WHERE vendor = 'tl-test-vendor';


-- ---------------------------------------------------------------------
-- Fixtures: one valid row per table, used by the tests below.
-- ---------------------------------------------------------------------
INSERT INTO cwe (cwe_id, name) VALUES ('CWE-999001', 'Test weakness A'), ('CWE-999002', 'Test weakness B');
INSERT INTO cve (cve_id, description, published_date, cvss_base_score, cvss_source)
VALUES ('CVE-2099-0001', 'Test vulnerability', '2099-01-01', 5.0, 'NVD');
INSERT INTO attack_technique (technique_id, name) VALUES ('T9990', 'Test technique');
INSERT INTO cpe (vendor, product) VALUES ('tl-test-vendor', 'tl-test-product');
INSERT INTO app_user (username, email, password_hash)
VALUES ('tl_test_active',   'tl_test_active@example.com',   '$2b$12$testhashtesthashtesthashtesthashtesthashtesthashtesth'),
       ('tl_test_inactive', 'tl_test_inactive@example.com', '$2b$12$testhashtesthashtesthashtesthashtesthashtesthashtesth');
UPDATE app_user SET is_active = FALSE WHERE username = 'tl_test_inactive';
SELECT user_id INTO @u_active   FROM app_user WHERE username = 'tl_test_active';
SELECT user_id INTO @u_inactive FROM app_user WHERE username = 'tl_test_inactive';
INSERT INTO security_event (slug, name, starts_on, ends_on)
VALUES ('tl-test-event', 'Test event', '2099-10-01', '2099-10-31');
SELECT event_id INTO @ev FROM security_event WHERE slug = 'tl-test-event';


-- =====================================================================
-- F: statements that MUST FAIL
-- =====================================================================

-- ---- cve ------------------------------------------------------------
-- F01 CVE ID in the wrong format (year must be 4 digits).
-- Expected: ERROR 3819 Check constraint 'chk_cve_id' is violated.
INSERT INTO cve (cve_id, description, published_date) VALUES ('CVE-99-1', 'bad id', '2099-01-01');

-- F02 CVSS score above 10.0 (with a valid source, so only the range is wrong).
-- Expected: ERROR 3819 Check constraint 'chk_cvss_range' is violated.
INSERT INTO cve (cve_id, description, published_date, cvss_base_score, cvss_source) VALUES ('CVE-2099-0002', 'score 11', '2099-01-01', 11.0, 'NVD');

-- F03 Negative CVSS score.
-- Expected: ERROR 3819 Check constraint 'chk_cvss_range' is violated.
INSERT INTO cve (cve_id, description, published_date, cvss_base_score, cvss_source) VALUES ('CVE-2099-0003', 'score -1', '2099-01-01', -1.0, 'NVD');

-- F04 Severity that is not in the ENUM.
-- Expected: ERROR 1265 Data truncated for column 'cvss_severity'.
INSERT INTO cve (cve_id, description, published_date, cvss_severity) VALUES ('CVE-2099-0004', 'bad band', '2099-01-01', 'SEVERE');

-- F05 KEV flag without the date it was added.
-- Expected: ERROR 3819 Check constraint 'chk_kev_date' is violated.
INSERT INTO cve (cve_id, description, published_date, is_kev) VALUES ('CVE-2099-0005', 'kev no date', '2099-01-01', TRUE);

-- F06 KEV date on a CVE that is not in KEV.
-- Expected: ERROR 3819 Check constraint 'chk_kev_date' is violated.
UPDATE cve SET kev_date_added = '2099-01-02' WHERE cve_id = 'CVE-2099-0001';

-- F07 Ransomware flag on a CVE that is not in KEV.
-- Expected: ERROR 3819 Check constraint 'chk_kev_ransomware' is violated.
UPDATE cve SET kev_ransomware = TRUE WHERE cve_id = 'CVE-2099-0001';

-- F08 CVSS version we do not load (v2 is not in the pick order).
-- Expected: ERROR 3819 Check constraint 'chk_cvss_version' is violated.
UPDATE cve SET cvss_version = '2.0' WHERE cve_id = 'CVE-2099-0001';

-- F09 Duplicate primary key.
-- Expected: ERROR 1062 Duplicate entry 'CVE-2099-0001' for key 'cve.PRIMARY'.
INSERT INTO cve (cve_id, description, published_date) VALUES ('CVE-2099-0001', 'dup', '2099-01-01');

-- F10 Missing description (NOT NULL).
-- Expected: ERROR 1048 Column 'description' cannot be null.
INSERT INTO cve (cve_id, description, published_date) VALUES ('CVE-2099-0010', NULL, '2099-01-01');

-- ---- cwe and junctions ---------------------------------------------
-- F11 CWE ID that is not CWE-<number>.
-- Expected: ERROR 3819 Check constraint 'chk_cwe_id' is violated.
INSERT INTO cwe (cwe_id, name) VALUES ('XSS', 'bad id');

-- F12 Link a CVE to a CWE that does not exist (foreign key).
-- Expected: ERROR 1452 Cannot add or update a child row: a foreign key constraint fails.
INSERT INTO cve_cwe (cve_id, cwe_id) VALUES ('CVE-2099-0001', 'CWE-999999');

-- F13 A weakness that is its own parent.
-- Expected: ERROR 3819 Check constraint 'chk_no_self_ref' is violated.
INSERT INTO cwe_relationship (parent_cwe_id, child_cwe_id) VALUES ('CWE-999001', 'CWE-999001');

-- F14 Same product listed twice. version defaults to '*', so this is
-- a duplicate of the fixture row (with NULL versions it would slip in).
-- Expected: ERROR 1062 Duplicate entry 'tl-test-vendor-tl-test-product-*' for key 'cpe.uq_cpe'.
INSERT INTO cpe (vendor, product) VALUES ('tl-test-vendor', 'tl-test-product');

-- ---- capec / ATT&CK -------------------------------------------------
-- F15 CVSS-style severity on CAPEC (CAPEC uses VERY LOW .. VERY HIGH).
-- Expected: ERROR 1265 Data truncated for column 'typical_severity'.
INSERT INTO capec (capec_id, name, typical_severity) VALUES ('CAPEC-99901', 'test', 'CRITICAL');

-- F16 Technique ID that is not T + 4 digits.
-- Expected: ERROR 3819 Check constraint 'chk_technique_id' is violated.
INSERT INTO attack_technique (technique_id, name) VALUES ('X123', 'bad id');

-- F17 Sub-technique whose parent does not exist (self foreign key).
-- Expected: ERROR 1452 Cannot add or update a child row: a foreign key constraint fails.
INSERT INTO attack_technique (technique_id, name, is_subtechnique, parent_technique_id)
VALUES ('T9991.001', 'orphan', TRUE, 'T9991');

-- F18 Tactic written as a display name instead of the ATT&CK short name.
-- Expected: ERROR 3819 Check constraint 'chk_tactic' is violated.
INSERT INTO technique_tactic (technique_id, tactic) VALUES ('T9990', 'Initial Access');

-- F19 platforms is a JSON column, so text that is not JSON is refused.
-- Expected: ERROR 3140 Invalid JSON text.
UPDATE attack_technique SET platforms = 'Windows, Linux' WHERE technique_id = 'T9990';

-- ---- app_user -------------------------------------------------------
-- F20 Email without @ and domain.
-- Expected: ERROR 3819 Check constraint 'chk_email' is violated.
INSERT INTO app_user (username, email, password_hash) VALUES ('tl_test_x', 'not-an-email', 'h');

-- F21 Username that is already taken.
-- Expected: ERROR 1062 Duplicate entry 'tl_test_active' for key 'app_user.username'.
INSERT INTO app_user (username, email, password_hash) VALUES ('tl_test_active', 'tl_test_other@example.com', 'h');

-- F22 Role outside analyst/admin.
-- Expected: ERROR 1265 Data truncated for column 'role'.
INSERT INTO app_user (username, email, password_hash, role) VALUES ('tl_test_root', 'tl_test_root@example.com', 'h', 'root');

-- ---- investigation and sp_create_investigation ----------------------
-- F23 Start node type outside CVE/CWE/CAPEC/TECHNIQUE (direct INSERT).
-- Expected: ERROR 3819 Check constraint 'chk_start_type' is violated.
INSERT INTO investigation (user_id, title, start_node_type, start_node_id) VALUES (@u_active, 't', 'HOST', 'web01');

-- F24 Investigation for a user that does not exist (foreign key).
-- Expected: ERROR 1452 Cannot add or update a child row: a foreign key constraint fails.
INSERT INTO investigation (user_id, title, start_node_type, start_node_id) VALUES (999999999, 't', 'CVE', 'CVE-2099-0001');

-- F25 Procedure: start node that does not exist.
-- Expected: ERROR 1644 (45000) start node CVE-2099-9999 does not exist
CALL sp_create_investigation(@u_active, 'missing node', 'CVE', 'CVE-2099-9999', NULL, @inv);

-- F26 Procedure: deactivated user.
-- Expected: ERROR 1644 (45000) user <id> is deactivated
CALL sp_create_investigation(@u_inactive, 'inactive user', 'CVE', 'CVE-2099-0001', NULL, @inv);

-- F27 Procedure: blank title.
-- Expected: ERROR 1644 (45000) title is required
CALL sp_create_investigation(@u_active, '   ', 'CVE', 'CVE-2099-0001', NULL, @inv);

-- F28 Procedure: unknown start node type.
-- Expected: ERROR 1644 (45000) invalid start node type HOST (expected CVE, CWE, CAPEC or TECHNIQUE)
CALL sp_create_investigation(@u_active, 'bad type', 'HOST', 'web01', NULL, @inv);

-- ---- audit_log ------------------------------------------------------
-- F29 Action outside the allowed list.
-- Expected: ERROR 3819 Check constraint 'chk_audit_action' is violated.
INSERT INTO audit_log (action, entity) VALUES ('HACK', 'investigation');

-- F30 details must be valid JSON.
-- Expected: ERROR 3140 Invalid JSON text.
INSERT INTO audit_log (action, entity, details) VALUES ('LOGIN', 'app_user', '{title: oops');

-- ---- security_event / event_cve -------------------------------------
-- F31 Event that ends before it starts.
-- Expected: ERROR 3819 Check constraint 'chk_event_dates' is violated.
INSERT INTO security_event (slug, name, starts_on, ends_on) VALUES ('tl-test-backwards', 'x', '2099-10-31', '2099-10-01');

-- F32 Slug with capitals and spaces (not URL-safe).
-- Expected: ERROR 3819 Check constraint 'chk_event_slug' is violated.
INSERT INTO security_event (slug, name, starts_on, ends_on) VALUES ('Tl Test Event', 'x', '2099-10-01', '2099-10-31');

-- F33 Duplicate slug.
-- Expected: ERROR 1062 Duplicate entry 'tl-test-event' for key 'security_event.slug'.
INSERT INTO security_event (slug, name, starts_on, ends_on) VALUES ('tl-test-event', 'x', '2099-10-01', '2099-10-31');

-- F34 Event CVE that is not a CVE ID (no FK to cve, but the format is checked).
-- Expected: ERROR 3819 Check constraint 'chk_event_cve_id' is violated.
INSERT INTO event_cve (event_id, cve_id) VALUES (@ev, 'GITLAB-2026-1');

-- F35 Event CVE for an event that does not exist (foreign key).
-- Expected: ERROR 1452 Cannot add or update a child row: a foreign key constraint fails.
INSERT INTO event_cve (event_id, cve_id) VALUES (999999999, 'CVE-2099-0001');

-- ---- cve.cvss_source (added after HANDOFF v2) -----------------------
-- F36 A score with no source (who scored it must be known).
-- Expected: ERROR 3819 Check constraint 'chk_cvss_source' is violated.
INSERT INTO cve (cve_id, description, published_date, cvss_base_score) VALUES ('CVE-2099-0036', 'no source', '2099-01-01', 7.5);

-- F37 A source on an unscored CVE.
-- Expected: ERROR 3819 Check constraint 'chk_cvss_source' is violated.
INSERT INTO cve (cve_id, description, published_date, cvss_source) VALUES ('CVE-2099-0037', 'source only', '2099-01-01', 'CNA');

-- F38 A source outside NVD/CNA/ADP.
-- Expected: ERROR 1265 Data truncated for column 'cvss_source'.
INSERT INTO cve (cve_id, description, published_date, cvss_base_score, cvss_source) VALUES ('CVE-2099-0038', 'bad source', '2099-01-01', 7.5, 'VENDOR');


-- =====================================================================
-- P: statements that MUST SUCCEED (each followed by a PASS/FAIL check)
-- =====================================================================

-- P01 Valid CVE with a score (and its source) but no severity: trg_cve_bi fills it.
INSERT INTO cve (cve_id, description, published_date, cvss_base_score, cvss_version, cvss_source)
VALUES ('CVE-2099-0100', 'valid scored CVE', '2099-01-01', 9.8, '3.1', 'CNA');
SELECT 'P01' AS test, cvss_severity AS actual, 'CRITICAL' AS expected,
       IF(cvss_severity = 'CRITICAL', 'PASS', 'FAIL') AS result
FROM cve WHERE cve_id = 'CVE-2099-0100';

-- P02 Re-scoring: trg_cve_bu re-derives the band (CRITICAL -> MEDIUM).
UPDATE cve SET cvss_base_score = 5.5 WHERE cve_id = 'CVE-2099-0100';
SELECT 'P02' AS test, cvss_severity AS actual, 'MEDIUM' AS expected,
       IF(cvss_severity = 'MEDIUM', 'PASS', 'FAIL') AS result
FROM cve WHERE cve_id = 'CVE-2099-0100';

-- P03 Valid KEV entry: flag, date and ransomware together.
UPDATE cve SET is_kev = TRUE, kev_date_added = '2099-01-05', kev_ransomware = TRUE
WHERE cve_id = 'CVE-2099-0100';
SELECT 'P03' AS test, CONCAT(is_kev, '/', kev_date_added, '/', kev_ransomware) AS actual,
       '1/2099-01-05/1' AS expected,
       IF(is_kev AND kev_date_added = '2099-01-05' AND kev_ransomware, 'PASS', 'FAIL') AS result
FROM cve WHERE cve_id = 'CVE-2099-0100';

-- P04 Valid sub-technique + tactic (parent exists, short-name tactic).
INSERT INTO attack_technique (technique_id, name, is_subtechnique, parent_technique_id, platforms)
VALUES ('T9990.001', 'Test sub-technique', TRUE, 'T9990', JSON_ARRAY('Windows', 'Linux'));
INSERT INTO technique_tactic (technique_id, tactic) VALUES ('T9990', 'initial-access');
SELECT 'P04' AS test, COUNT(*) AS actual, 2 AS expected,
       IF(COUNT(*) = 2, 'PASS', 'FAIL') AS result
FROM attack_technique WHERE technique_id IN ('T9990', 'T9990.001');

-- P05 Procedure, valid call: returns the new id and writes exactly one
-- audit row in the same transaction.
CALL sp_create_investigation(@u_active, 'Test chain', 'CVE', 'CVE-2099-0100', 'notes', @inv);
SELECT 'P05' AS test,
       CONCAT('id=', @inv, ', audit rows=',
              (SELECT COUNT(*) FROM audit_log
               WHERE entity = 'investigation' AND entity_id = @inv AND action = 'INSERT')) AS actual,
       'id not NULL, audit rows=1' AS expected,
       IF(@inv IS NOT NULL
          AND (SELECT COUNT(*) FROM audit_log
               WHERE entity = 'investigation' AND entity_id = @inv AND action = 'INSERT') = 1,
          'PASS', 'FAIL') AS result;

-- P06 Failed procedure calls F25-F28 left nothing behind (ROLLBACK):
-- the test user owns exactly the one investigation from P05.
SELECT 'P06' AS test, COUNT(*) AS actual, 1 AS expected,
       IF(COUNT(*) = 1, 'PASS', 'FAIL') AS result
FROM investigation WHERE user_id IN (@u_active, @u_inactive);

-- P07 Event CVE that is not in the cve table yet (Black October case)
-- and a one-day event (ends_on = starts_on) are both allowed.
INSERT INTO event_cve (event_id, cve_id, note) VALUES (@ev, 'CVE-2099-0999', 'awaiting NVD data');
INSERT INTO security_event (slug, name, starts_on, ends_on) VALUES ('tl-test-one-day', 'One day', '2099-10-15', '2099-10-15');
SELECT 'P07' AS test,
       CONCAT((SELECT COUNT(*) FROM event_cve WHERE event_id = @ev), ' event_cve, ',
              (SELECT COUNT(*) FROM security_event WHERE slug = 'tl-test-one-day'), ' one-day event') AS actual,
       '1 event_cve, 1 one-day event' AS expected,
       IF((SELECT COUNT(*) FROM event_cve WHERE event_id = @ev) = 1
          AND (SELECT COUNT(*) FROM security_event WHERE slug = 'tl-test-one-day') = 1,
          'PASS', 'FAIL') AS result;


-- ---------------------------------------------------------------------
-- Cleanup: remove every test row so real data is untouched.
-- ---------------------------------------------------------------------
DELETE FROM audit_log WHERE user_id IN (SELECT user_id FROM app_user WHERE username LIKE 'tl\_test\_%');
DELETE FROM app_user  WHERE username LIKE 'tl\_test\_%';
DELETE FROM security_event   WHERE slug LIKE 'tl-test-%';
DELETE FROM cve              WHERE cve_id LIKE 'CVE-2099-%';
DELETE FROM cwe              WHERE cwe_id IN ('CWE-999001', 'CWE-999002');
DELETE FROM attack_technique WHERE technique_id LIKE 'T999_%' AND is_subtechnique = TRUE;
DELETE FROM attack_technique WHERE technique_id LIKE 'T999_%';
DELETE FROM capec            WHERE capec_id = 'CAPEC-99901';
DELETE FROM cpe              WHERE vendor = 'tl-test-vendor';
