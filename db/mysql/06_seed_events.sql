-- =====================================================================
-- 06_seed_events.sql  Curated security events (Black October 2026)
-- Owner: Akshansh Agrawal (PES2UG24CS045)
--
-- Runs at container init, before any CVE data is loaded. That works
-- because event_cve has no foreign key to cve (see 01_schema.sql): the
-- curated IDs are stored now, and the spotlight page LEFT JOINs cve, so
-- a CVE that NVD has not published yet shows as "awaiting NVD data".
--
-- Safe to re-run: the event is upserted by its unique slug and the
-- event_cve rows by their (event_id, cve_id) primary key, so running it
-- again updates text instead of failing on duplicates.
-- Source: HANDOFF section 8; dates checked against NVD and CISA KEV
-- (catalogue 2026.10.30) on 2026-11-02.
-- =====================================================================


-- The event itself. `AS new` is the 8.0.19+ row alias that replaces the
-- deprecated VALUES(col) inside ON DUPLICATE KEY UPDATE.
INSERT INTO security_event (slug, name, starts_on, ends_on, summary)
VALUES ('black-october-2026', 'Black October 2026', '2026-10-01', '2026-10-31',
        'A cluster of critical disclosures in October 2026. PHP2Shell brought unauthenticated remote code execution to the PHP interpreter itself (patched 21 October), GitLab shipped a CVSS 10.0 RCE fix, and CISA added actively exploited flaws in Windows, FortiMail, BeyondTrust, VMware ESX and the Linux kernel to its KEV catalogue. The same month saw the LiteLLM supply-chain compromise and weak eMudhra CA keys.')
AS new
ON DUPLICATE KEY UPDATE
    name      = new.name,
    starts_on = new.starts_on,
    ends_on   = new.ends_on,
    summary   = new.summary;

-- Look the id up by slug instead of assuming LAST_INSERT_ID(): on a
-- re-run the upsert updates the existing row and inserts nothing.
SET @ev = (SELECT event_id FROM security_event WHERE slug = 'black-october-2026');

-- The CVEs linked to the event, in timeline order.
INSERT INTO event_cve (event_id, cve_id, note)
VALUES
    (@ev, 'CVE-2026-104286', 'Fortinet FortiMail path traversal, exploited (KEV 1 Oct), CVSS 9.8'),
    (@ev, 'CVE-2026-96951',  'Windows Shell security feature bypass, exploited zero-day (October Patch Tuesday, KEV 13 Oct)'),
    (@ev, 'CVE-2026-102764', 'BeyondTrust Remote Support authentication bypass zero-day (KEV 16 Oct)'),
    (@ev, 'CVE-2026-109618', 'PHP2Shell: RCE via out-of-memory corruption in PHP core (patched 21 Oct, KEV 26 Oct)'),
    (@ev, 'CVE-2026-109619', 'PHP2Shell: RCE via stale global request state in PHP core (patched 21 Oct, KEV 26 Oct)'),
    (@ev, 'CVE-2026-110264', 'GitLab CE/EE unauthenticated RCE, CVSS 10.0'),
    (@ev, 'CVE-2026-41709',  'VMware ESX insufficient logging, exploited despite a CVSS 2.7 score (KEV 28 Oct)'),
    (@ev, 'CVE-2026-46300',  'Linux kernel missing initialization, exploited (KEV 28 Oct)')
AS new
ON DUPLICATE KEY UPDATE note = new.note;


-- ---------------------------------------------------------------------
-- Test calls (after load_nvd.py and load_kev.py):
--   SELECT * FROM security_event WHERE slug = 'black-october-2026';
--   -- spotlight query: every curated CVE, with NVD/KEV data where present
--   SELECT ec.cve_id, ec.note, c.cvss_base_score, c.cvss_severity,
--          c.is_kev, c.kev_date_added,
--          (c.cve_id IS NULL) AS awaiting_nvd
--   FROM   security_event e
--   JOIN   event_cve ec ON ec.event_id = e.event_id
--   LEFT JOIN cve c     ON c.cve_id    = ec.cve_id
--   WHERE  e.slug = 'black-october-2026'
--   ORDER BY c.kev_date_added, ec.cve_id;
-- ---------------------------------------------------------------------
