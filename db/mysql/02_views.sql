-- =====================================================================
-- 02_views.sql  ThreatLattice views (MySQL 8.0)
-- Owner: Akshansh Agrawal (PES2UG24CS045)
--
-- A view is a stored SELECT with a name. It holds no data of its own:
-- every read re-runs the query on the current tables, so it can never
-- go stale (unlike a summary table we would have to keep in sync).
-- We use views to (1) give the API and report one place for queries
-- that would otherwise be copy-pasted, and (2) hide join details.
--
-- CREATE OR REPLACE makes this file safe to re-run without dropping
-- anything first.
-- =====================================================================


-- ---------------------------------------------------------------------
-- v_critical_cve (from Deliverable 1, unchanged)
-- Every CRITICAL CVE with each weakness it is tagged with.
-- One row per (CVE, CWE) pair, so a CVE with two CWEs appears twice.
-- INNER JOIN on purpose: the view answers "which weaknesses produce
-- critical bugs", so a critical CVE with no CWE has nothing to say here.
-- Simple SELECT + JOIN + WHERE, no GROUP BY, so MySQL can MERGE it into
-- the outer query and still use idx_cve_severity.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW v_critical_cve AS
SELECT c.cve_id,
       c.cvss_base_score,
       w.cwe_id,
       w.name AS cwe_name
FROM   cve c
JOIN   cve_cwe cc ON cc.cve_id = c.cve_id
JOIN   cwe w      ON w.cwe_id  = cc.cwe_id
WHERE  c.cvss_severity = 'CRITICAL';


-- ---------------------------------------------------------------------
-- v_cve_summary
-- One row per CVE with its CWE IDs folded into one string
-- ('CWE-79,CWE-89'). This is the CveRow shape the search API and
-- tables show.
-- - LEFT JOIN, not JOIN: CVEs with no CWE must still appear (cwe_ids
--   is NULL for them). An inner join would silently drop them.
-- - GROUP_CONCAT(... ORDER BY ...) gives a stable, sorted list.
--   Alternative: return one row per pair and fold in the app, which
--   moves rows over the wire only to merge them again.
-- - GROUP BY c.cve_id alone is valid under ONLY_FULL_GROUP_BY because
--   cve_id is the PK, so every other c.* column depends on it.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW v_cve_summary AS
SELECT c.cve_id,
       c.description,
       c.published_date,
       c.cvss_base_score,
       c.cvss_severity,
       c.cvss_version,
       c.is_kev,
       c.kev_date_added,
       GROUP_CONCAT(cc.cwe_id ORDER BY cc.cwe_id SEPARATOR ',') AS cwe_ids
FROM   cve c
LEFT JOIN cve_cwe cc ON cc.cve_id = c.cve_id
GROUP BY c.cve_id;


-- ---------------------------------------------------------------------
-- v_cwe_stats
-- Per weakness: how many CVEs, average and worst score, how many are
-- known exploited. Feeds the dashboard's "Top weaknesses" table.
-- - LEFT JOINs so every CWE appears, including ones with 0 CVEs
--   (COUNT(c.cve_id) counts only matched rows, so they get 0, whereas
--   COUNT(*) would wrongly count the NULL row as 1).
-- - AVG and MAX skip NULL scores automatically (unscored CVEs do not
--   drag the average to 0).
-- - SUM(c.is_kev): BOOLEAN is TINYINT(1), so summing 1/0 counts KEV
--   rows. COALESCE turns the NULL sum of a CWE with no CVEs into 0.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW v_cwe_stats AS
SELECT w.cwe_id,
       w.name,
       COUNT(c.cve_id)                 AS cve_count,
       ROUND(AVG(c.cvss_base_score), 2) AS avg_score,
       MAX(c.cvss_base_score)          AS max_score,
       COALESCE(SUM(c.is_kev), 0)      AS kev_count
FROM   cwe w
LEFT JOIN cve_cwe cc ON cc.cwe_id = w.cwe_id
LEFT JOIN cve c      ON c.cve_id  = cc.cve_id
GROUP BY w.cwe_id, w.name;


-- ---------------------------------------------------------------------
-- v_severity_by_year
-- CVE count per publication year and severity band (dashboard chart,
-- report GROUP BY example).
-- - CVEs with no score yet have NULL severity; COALESCE labels them
--   'UNSCORED' so they show up as their own band instead of a blank
--   group.
-- - Grouping by the expressions' aliases is allowed in MySQL and keeps
--   the SELECT and GROUP BY in sync.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW v_severity_by_year AS
SELECT YEAR(c.published_date)                AS year,
       COALESCE(c.cvss_severity, 'UNSCORED') AS severity,
       COUNT(*)                              AS cve_count
FROM   cve c
GROUP BY year, severity;


-- ---------------------------------------------------------------------
-- Test calls (run by hand after the loaders):
--   SELECT * FROM v_critical_cve ORDER BY cvss_base_score DESC LIMIT 10;
--   SELECT * FROM v_cve_summary WHERE cve_id = 'CVE-2026-109618';
--   SELECT * FROM v_cwe_stats ORDER BY cve_count DESC LIMIT 10;
--   SELECT * FROM v_severity_by_year WHERE year = 2026;
--   SHOW FULL TABLES WHERE Table_type = 'VIEW';
-- ---------------------------------------------------------------------
