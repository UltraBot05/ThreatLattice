# SQL query screenshots

Output of each block of [`db/mysql/queries/report_queries.sql`](../../../db/mysql/queries/report_queries.sql), run with `mysql -t -vvv` (statement echo, table output, timing). Each image is rendered from the captured console output of that block.

Data: NVD 2024–2026 feeds + CWE 5.0 + CISA KEV 2026.10.30, loaded 2026-11-02 (164,370 CVEs). MySQL 8.0.46. Timings are from a laptop.

| File | Query | Shows |
|---|---|---|
| `q01_group_by_having.png` | Q1 | GROUP BY + HAVING + COUNT/AVG/SUM: common and severe CWEs |
| `q02_correlated_subquery.png` | Q2 | Correlated subquery: Black October CVEs above their CWE's average |
| `q02b_derived_table_rewrite.png` | Q2b | Same question over all KEV CVEs as a derived table (2.5 s vs 33 s correlated) |
| `q03_nested_subquery.png` | Q3 | Nested NOT IN / IN, NOT EXISTS equivalent, the NOT IN NULL trap |
| `q04_multi_table_join.png` | Q4 | 3-table JOIN, COUNT(DISTINCT), conditional count: top vendors by critical CVEs |
| `q05_update_trigger.png` | Q5 | UPDATE re-scoring; `trg_cve_bu` re-derives HIGH to CRITICAL; ROLLBACK |
| `q06_delete_audit.png` | Q6 | DELETE older than 30 days; `trg_inv_ad` audit rows; JSON path `->>` |
| `q07a_fulltext_natural.png` | Q7a | FULLTEXT natural language mode with relevance + EXPLAIN (type fulltext) |
| `q07b_fulltext_boolean.png` | Q7b | FULLTEXT boolean mode `+php -wordpress` vs LIKE (0.02 s vs 1.26 s) |
| `q08_function_procedure.png` | Q8 | `CALL sp_severity_breakdown(2026)`, `fn_cwe_cve_count`, `fn_severity_band` |
| `q09_transaction.png` | Q9 | START TRANSACTION, SAVEPOINT, ROLLBACK TO SAVEPOINT, ROLLBACK |
| `q10_views.png` | Q10 | `v_severity_by_year`, `v_cwe_stats`, `v_cve_summary` |
