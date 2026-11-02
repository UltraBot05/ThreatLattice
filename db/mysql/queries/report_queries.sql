-- =====================================================================
-- queries/report_queries.sql  Queries for the report (section "Queries")
-- Owner: Akshansh Agrawal (PES2UG24CS045)
--
-- Each query has a header:
--   Purpose  what question it answers
--   Clauses  why each clause is there
--   Not used the obvious alternative and why we did not pick it
--   Remove   what breaks if a key clause is removed
--
-- Needs: 01-04 + 06 loaded, then load_cwe, load_nvd, load_kev.
-- Every query that changes data runs inside a transaction that ends in
-- ROLLBACK, so the file can be run any number of times and the data
-- stays exactly as NVD/CISA published it.
-- Lines like  -- [q01_group_by_having]  mark where each query starts;
-- they name the matching screenshot in docs/screenshots/sql/.
-- Run:  mysql -t -u root -p threatlattice < db/mysql/queries/report_queries.sql
-- =====================================================================


-- [q01_group_by_having]
-- ---------------------------------------------------------------------
-- Q1  GROUP BY + HAVING + aggregates
-- Purpose  Which weaknesses are both common and severe? CWEs with at
--          least 50 CVEs and an average CVSS score of 7.0 or more.
-- Clauses  JOIN cve_cwe / cve: one row per (CWE, CVE) pair.
--          GROUP BY w.cwe_id, w.name: one output row per weakness.
--          COUNT(*): CVEs per weakness. AVG(score): ignores NULL
--          scores, so unscored CVEs do not drag the average to 0.
--          SUM(is_kev): BOOLEAN is 0/1, so the sum counts KEV CVEs.
--          HAVING: filters groups AFTER aggregation. WHERE runs before
--          grouping and cannot see COUNT/AVG, so the thresholds must be
--          in HAVING.
--          ORDER BY cve_count DESC: most common first.
-- Not used Computing per-CWE counts in the app: would ship 180k rows
--          over the wire to produce 96 (LIMIT 15 shows the top 15).
-- Remove   HAVING -> every CWE with at least one CVE (737 groups).
--          GROUP BY -> error under ONLY_FULL_GROUP_BY (name not aggregated).
-- ---------------------------------------------------------------------
SELECT w.cwe_id,
       w.name,
       COUNT(*)                         AS cve_count,
       ROUND(AVG(c.cvss_base_score), 2) AS avg_score,
       SUM(c.is_kev)                    AS kev_count
FROM   cwe w
JOIN   cve_cwe cc ON cc.cwe_id = w.cwe_id
JOIN   cve c      ON c.cve_id  = cc.cve_id
GROUP BY w.cwe_id, w.name
HAVING COUNT(*) >= 50
   AND AVG(c.cvss_base_score) >= 7.0
ORDER BY cve_count DESC
LIMIT 15;


-- [q02_correlated_subquery]
-- ---------------------------------------------------------------------
-- Q2  Correlated subquery
-- Purpose  Which Black October CVEs are worse than typical for their
--          weakness? (score above the average score of all CVEs that
--          share that CWE)
-- Clauses  Outer query: Black October CVEs (event -> event_cve -> cve)
--          with each of their CWEs (cve_cwe cc).
--          Subquery: AVG score of every CVE tagged with cc.cwe_id. It
--          references cc from the OUTER query, which makes it
--          correlated: MySQL re-runs it for every outer row, each time
--          with a different cwe_id.
-- Not used The same check over all 547 KEV CVEs took 33 s here, because
--          the subquery re-runs ~650 times and popular CWEs (CWE-79 has
--          22k CVEs) are averaged again every time. Q2b shows the
--          non-correlated rewrite that is ~10x faster at that scale.
-- Remove   The correlation (cc2.cwe_id = cc.cwe_id) -> the subquery
--          becomes the average of ALL CVEs, a different question.
-- ---------------------------------------------------------------------
SELECT c.cve_id,
       cc.cwe_id,
       c.cvss_base_score AS score,
       (SELECT ROUND(AVG(c2.cvss_base_score), 2)
        FROM   cve_cwe cc2
        JOIN   cve c2 ON c2.cve_id = cc2.cve_id
        WHERE  cc2.cwe_id = cc.cwe_id)        AS cwe_avg
FROM   security_event e
JOIN   event_cve ec ON ec.event_id = e.event_id
JOIN   cve c        ON c.cve_id    = ec.cve_id
JOIN   cve_cwe cc   ON cc.cve_id   = c.cve_id
WHERE  e.slug = 'black-october-2026'
  AND  c.cvss_base_score > (SELECT AVG(c2.cvss_base_score)
                            FROM   cve_cwe cc2
                            JOIN   cve c2 ON c2.cve_id = cc2.cve_id
                            WHERE  cc2.cwe_id = cc.cwe_id)
ORDER BY score DESC, c.cve_id, cc.cwe_id;


-- [q02b_derived_table_rewrite]
-- ---------------------------------------------------------------------
-- Q2b The same question for all known-exploited CVEs, rewritten
-- Purpose  Known-exploited CVEs that score furthest above their
--          weakness's average.
-- Clauses  Derived table `a`: every CWE's average, computed ONCE with
--          GROUP BY, then joined like a table. Not correlated, so it is
--          not re-run per row (2.9 s vs 33 s for the correlated form).
--          ORDER BY score - cwe_avg: biggest outliers first.
-- Not used The correlated form of Q2 (correct, but repeats the work).
-- Remove   GROUP BY inside `a` -> one average over all rows, and the
--          join on cwe_id no longer makes sense.
-- ---------------------------------------------------------------------
SELECT c.cve_id,
       cc.cwe_id,
       c.cvss_base_score AS score,
       a.cwe_avg
FROM   cve c
JOIN   cve_cwe cc ON cc.cve_id = c.cve_id
JOIN  (SELECT cc2.cwe_id, ROUND(AVG(c2.cvss_base_score), 2) AS cwe_avg
       FROM   cve_cwe cc2
       JOIN   cve c2 ON c2.cve_id = cc2.cve_id
       GROUP BY cc2.cwe_id) a ON a.cwe_id = cc.cwe_id
WHERE  c.is_kev = TRUE
  AND  c.cvss_base_score > a.cwe_avg
ORDER BY score - a.cwe_avg DESC, c.cve_id
LIMIT 10;


-- [q03_nested_subquery]
-- ---------------------------------------------------------------------
-- Q3  Nested subqueries (NOT IN), and the NOT EXISTS equivalent
-- Purpose  Weaknesses that appear in real CVEs but where NONE of those
--          CVEs is known to be exploited: common on paper, quiet in the
--          wild. Ranked by how many CVEs they have.
-- Clauses  IN (SELECT cwe_id FROM cve_cwe): the CWE has at least one CVE.
--          NOT IN (... IN (SELECT cve_id FROM cve WHERE is_kev)): three
--          levels deep. Innermost: KEV CVEs. Middle: CWEs of those CVEs.
--          Outer: CWEs not in that list. None of the subqueries refers
--          to the outer query, so each runs once (nested, not
--          correlated); MySQL turns them into semi/anti-joins.
--          fn_cwe_cve_count(): the stored function from 03_routines.sql.
-- NULL trap NOT IN is unsafe if the subquery can return a NULL:
--          x NOT IN (a, NULL) is UNKNOWN, never TRUE, so the whole query
--          would silently return no rows (demonstrated below). Here
--          cve_cwe.cwe_id is NOT NULL, so NOT IN is safe. NOT EXISTS
--          has no such trap and is the safer default.
-- Remove   The IN (... cve_cwe) line -> 678 more CWEs appear that have
--          zero CVEs and so trivially have "no KEV CVE".
-- ---------------------------------------------------------------------
SELECT w.cwe_id,
       w.name,
       fn_cwe_cve_count(w.cwe_id) AS cve_count
FROM   cwe w
WHERE  w.cwe_id IN (SELECT cwe_id FROM cve_cwe)
  AND  w.cwe_id NOT IN (SELECT cc.cwe_id
                        FROM   cve_cwe cc
                        WHERE  cc.cve_id IN (SELECT cve_id FROM cve WHERE is_kev = TRUE))
ORDER BY cve_count DESC, w.cwe_id
LIMIT 10;

-- Same question with NOT EXISTS (correlated, NULL-safe); same row count.
SELECT COUNT(*) AS cwes_with_cves_but_no_kev
FROM   cwe w
WHERE  EXISTS (SELECT 1 FROM cve_cwe cc WHERE cc.cwe_id = w.cwe_id)
  AND  NOT EXISTS (SELECT 1
                   FROM   cve_cwe cc
                   JOIN   cve c ON c.cve_id = cc.cve_id
                   WHERE  cc.cwe_id = w.cwe_id
                     AND  c.is_kev = TRUE);

-- The NULL trap in one line: NULL instead of 1 (TRUE).
SELECT 'CWE-79' NOT IN ('CWE-89', 'CWE-22')       AS without_null,
       'CWE-79' NOT IN ('CWE-89', 'CWE-22', NULL) AS with_null;


-- [q04_multi_table_join]
-- ---------------------------------------------------------------------
-- Q4  Multi-table JOIN + aggregate
-- Purpose  Top 10 vendors by number of CRITICAL CVEs.
-- Clauses  cve -> cve_cpe -> cpe: three tables, two joins through the
--          junction table (M:N between CVE and product).
--          WHERE severity = 'CRITICAL' before grouping (uses
--          idx_cve_severity, and is not an aggregate, so WHERE not HAVING).
--          COUNT(DISTINCT c.cve_id): one CVE often affects many products
--          or versions of the same vendor; COUNT(*) would count each
--          (CVE, product) pair and inflate vendors with many versions.
--          COUNT(DISTINCT p.product): how many of their products.
--          COUNT(DISTINCT CASE WHEN is_kev THEN cve_id END): conditional
--          count of distinct KEV CVEs. CASE gives NULL for non-KEV rows
--          and COUNT skips NULLs. SUM(is_kev) would count pairs again.
-- Not used GROUP BY vendor on cve_cpe alone: the vendor name lives in
--          cpe, so the join is required.
-- Remove   DISTINCT -> counts pairs; a vendor with one CVE across 200
--          versions would show 200.
-- ---------------------------------------------------------------------
SELECT p.vendor,
       COUNT(DISTINCT c.cve_id)                              AS critical_cves,
       COUNT(DISTINCT p.product)                             AS products_affected,
       COUNT(DISTINCT CASE WHEN c.is_kev THEN c.cve_id END)  AS kev_cves
FROM   cve c
JOIN   cve_cpe x ON x.cve_id = c.cve_id
JOIN   cpe p     ON p.cpe_id = x.cpe_id
WHERE  c.cvss_severity = 'CRITICAL'
GROUP BY p.vendor
ORDER BY critical_cves DESC, p.vendor
LIMIT 10;


-- [q05_update_trigger]
-- ---------------------------------------------------------------------
-- Q5  UPDATE (re-scoring) and the BEFORE UPDATE trigger
-- Purpose  Show that changing a score re-derives the severity band
--          automatically (trg_cve_bu calls fn_severity_band).
-- Clauses  UPDATE ... SET score, last_modified_date WHERE cve_id: a
--          single-row update by primary key. cvss_severity is NOT in the
--          SET list, so the trigger sees "score changed, band did not"
--          and recomputes it: 8.1 HIGH -> 9.0 CRITICAL.
--          START TRANSACTION ... ROLLBACK: the demo leaves NVD's real
--          score in place.
-- Not used Setting cvss_severity in the same UPDATE: easy to forget,
--          and the band would go stale. The trigger makes that impossible.
-- Remove   The WHERE clause -> every CVE gets score 9.0 (that is why the
--          demo is in a transaction).
-- ---------------------------------------------------------------------
START TRANSACTION;

SELECT cve_id, cvss_base_score, cvss_severity, last_modified_date
FROM   cve WHERE cve_id = 'CVE-2026-109619';

UPDATE cve
SET    cvss_base_score    = 9.0,
       last_modified_date = CURDATE()
WHERE  cve_id = 'CVE-2026-109619';

SELECT cve_id, cvss_base_score, cvss_severity, last_modified_date
FROM   cve WHERE cve_id = 'CVE-2026-109619';

ROLLBACK;

SELECT cve_id, cvss_base_score, cvss_severity AS after_rollback
FROM   cve WHERE cve_id = 'CVE-2026-109619';


-- [q06_delete_audit]
-- ---------------------------------------------------------------------
-- Q6  DELETE with a date condition, and the AFTER DELETE audit trigger
-- Purpose  Clean up a user's investigations older than 30 days; every
--          deleted row leaves a DELETE entry in audit_log (trg_inv_ad).
-- Clauses  Setup: a demo user and three investigations backdated 120,
--          45 and 2 days (trg_inv_ai logs each INSERT).
--          DELETE ... WHERE user_id = @u AND created_at < NOW() -
--          INTERVAL 30 DAY: only this user's old rows; the 2-day-old
--          one stays.
--          ROW_COUNT(): rows the DELETE removed.
--          details->>'$.title': JSON path, unquoted, from the audit row.
--          ROLLBACK at the end removes the demo data and its audit rows.
-- Not used Deleting in the app row by row: N round trips, and a crash
--          half-way leaves some rows deleted and some not.
-- Remove   user_id = @u -> deletes every user's old investigations.
-- ---------------------------------------------------------------------
START TRANSACTION;

INSERT INTO app_user (username, email, password_hash)
VALUES ('report_demo', 'report_demo@example.com', 'demo-not-a-real-hash');
SET @u = LAST_INSERT_ID();

INSERT INTO investigation (user_id, title, start_node_type, start_node_id, created_at)
VALUES (@u, 'PAN-OS GlobalProtect chain', 'CVE', 'CVE-2024-3400',   NOW() - INTERVAL 120 DAY),
       (@u, 'XSS weakness review',        'CWE', 'CWE-79',          NOW() - INTERVAL 45 DAY),
       (@u, 'PHP2Shell chain',            'CVE', 'CVE-2026-109618', NOW() - INTERVAL 2 DAY);

DELETE FROM investigation
WHERE  user_id = @u
  AND  created_at < NOW() - INTERVAL 30 DAY;
SELECT ROW_COUNT() AS rows_deleted;

SELECT investigation_id, title, DATE(created_at) AS created
FROM   investigation WHERE user_id = @u;

SELECT log_id, action, entity, entity_id, details->>'$.title' AS title
FROM   audit_log WHERE user_id = @u ORDER BY log_id;

ROLLBACK;


-- [q07a_fulltext_natural]
-- ---------------------------------------------------------------------
-- Q7a Full-text search, natural language mode, with relevance
-- Purpose  CVEs whose description is most about "remote code execution".
-- Clauses  MATCH(description) AGAINST(... IN NATURAL LANGUAGE MODE):
--          uses the FULLTEXT index idx_cve_fts (added by ALTER in
--          01_schema.sql). Returns a relevance score (words that are
--          rare across all descriptions weigh more).
--          The same MATCH in SELECT and WHERE is computed once.
--          ORDER BY relevance DESC: best matches first.
-- Not used description LIKE '%remote code execution%': cannot use any
--          index (leading %), scans all 164k rows, matches only the exact
--          phrase and gives no ranking.
-- Remove   ORDER BY -> matches come back in index order, not by relevance.
-- ---------------------------------------------------------------------
SELECT cve_id,
       cvss_severity,
       ROUND(MATCH(description) AGAINST ('remote code execution' IN NATURAL LANGUAGE MODE), 2) AS relevance,
       LEFT(description, 70) AS description
FROM   cve
WHERE  MATCH(description) AGAINST ('remote code execution' IN NATURAL LANGUAGE MODE)
ORDER BY relevance DESC, cve_id
LIMIT 10;

-- The plan shows type = fulltext, key = idx_cve_fts (no table scan).
EXPLAIN
SELECT cve_id FROM cve
WHERE  MATCH(description) AGAINST ('remote code execution' IN NATURAL LANGUAGE MODE);


-- [q07b_fulltext_boolean]
-- ---------------------------------------------------------------------
-- Q7b Full-text search, boolean mode (what the search page uses)
-- Purpose  PHP vulnerabilities that are not about WordPress.
-- Clauses  '+php -wordpress': + means the word must appear, - means it
--          must not. Boolean mode does not sort by relevance, so we
--          order by date (newest first).
--          The LIKE count next to it answers a slightly different
--          question (substrings, so 'phpMyAdmin' matches '%php%') and
--          has to read every row; compare the two timings.
-- Not used Natural mode for filters: it cannot express "must not".
-- Remove   -wordpress -> thousands of WordPress plugin CVEs flood the
--          results.
-- ---------------------------------------------------------------------
SELECT COUNT(*) AS php_not_wordpress
FROM   cve
WHERE  MATCH(description) AGAINST ('+php -wordpress' IN BOOLEAN MODE);

SELECT cve_id, published_date, cvss_severity, LEFT(description, 70) AS description
FROM   cve
WHERE  MATCH(description) AGAINST ('+php -wordpress' IN BOOLEAN MODE)
ORDER BY published_date DESC, cve_id
LIMIT 10;

SELECT COUNT(*) AS like_php_not_wordpress
FROM   cve
WHERE  description LIKE '%php%' AND description NOT LIKE '%wordpress%';


-- [q08_function_procedure]
-- ---------------------------------------------------------------------
-- Q8  Stored procedure and stored functions (03_routines.sql)
-- Purpose  Severity breakdown for 2026 (dashboard data), CVE counts per
--          weakness, and the score -> band function on real rows.
-- Clauses  CALL returns a result set like a SELECT.
--          fn_cwe_cve_count() is usable anywhere an expression is.
--          fn_severity_band() checked against the stored band: the
--          `matches` column must be 1 on every row.
-- Not used Repeating the CASE of fn_severity_band in every query: one
--          definition in the database means one place to fix.
-- ---------------------------------------------------------------------
CALL sp_severity_breakdown(2026);

SELECT fn_cwe_cve_count('CWE-79')  AS xss_cves,
       fn_cwe_cve_count('CWE-89')  AS sqli_cves,
       fn_cwe_cve_count('CWE-787') AS oob_write_cves;

SELECT cve_id, cvss_base_score,
       fn_severity_band(cvss_base_score)                  AS fn_band,
       cvss_severity                                      AS stored_band,
       fn_severity_band(cvss_base_score) = cvss_severity  AS matches
FROM   cve
WHERE  cve_id IN (SELECT cve_id FROM event_cve)
ORDER BY cvss_base_score DESC;


-- [q09_transaction]
-- ---------------------------------------------------------------------
-- Q9  Transaction: SAVEPOINT, ROLLBACK TO SAVEPOINT, ROLLBACK
-- Purpose  Show that work inside a transaction is invisible once it is
--          rolled back, and that a savepoint undoes only part of it.
-- Clauses  START TRANSACTION: from here nothing is permanent.
--          SAVEPOINT after_event: a named point inside the transaction.
--          ROLLBACK TO SAVEPOINT: undoes only the event_cve row.
--          ROLLBACK: undoes the rest. The last SELECT (outside the
--          transaction) finds nothing.
-- Not used autocommit (the default): every statement is committed at
--          once, so there is nothing to roll back.
-- ---------------------------------------------------------------------
SELECT COUNT(*) AS events_before FROM security_event;

START TRANSACTION;

INSERT INTO security_event (slug, name, starts_on, ends_on)
VALUES ('tx-demo', 'Transaction demo', '2026-11-01', '2026-11-02');
SET @demo = LAST_INSERT_ID();

SAVEPOINT after_event;

INSERT INTO event_cve (event_id, cve_id, note)
VALUES (@demo, 'CVE-2026-109618', 'demo link');

ROLLBACK TO SAVEPOINT after_event;

SELECT (SELECT COUNT(*) FROM security_event WHERE slug = 'tx-demo') AS demo_event_inside_tx,
       (SELECT COUNT(*) FROM event_cve WHERE event_id = @demo)     AS demo_links_after_savepoint;

ROLLBACK;

SELECT COUNT(*) AS events_after,
       (SELECT COUNT(*) FROM security_event WHERE slug = 'tx-demo') AS demo_event_after_rollback
FROM   security_event;


-- [q10_views]
-- ---------------------------------------------------------------------
-- Q10 Views (02_views.sql) used like tables
-- Purpose  Dashboard data straight from the views.
-- Clauses  v_severity_by_year: GROUP BY inside the view; the outer
--          WHERE and ORDER BY work on its result.
--          v_cwe_stats: per-weakness KEV counts, ranked.
--          v_cve_summary: one row per CVE with its CWE list folded.
-- Not used Copying these SELECTs into every API route: three copies to
--          keep in sync.
-- Cost     A view with GROUP BY cannot be merged into the outer query:
--          MySQL materializes it (EXPLAIN shows <derived2>), building
--          the whole result before joining. The third query reads 8 CVEs
--          but v_cve_summary still groups all 164k (about 3.7 s). Fine
--          for reports; the search API filters cve first instead.
-- ---------------------------------------------------------------------
SELECT year, severity, cve_count
FROM   v_severity_by_year
WHERE  year = 2026
ORDER BY FIELD(severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNSCORED');

SELECT cwe_id, name, cve_count, avg_score, kev_count
FROM   v_cwe_stats
ORDER BY kev_count DESC, cve_count DESC
LIMIT 10;

SELECT s.cve_id, s.cvss_severity, s.is_kev, s.cwe_ids
FROM   v_cve_summary s
JOIN   event_cve ec ON ec.cve_id = s.cve_id
ORDER BY s.cvss_base_score DESC, s.cve_id;
