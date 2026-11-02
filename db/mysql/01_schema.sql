-- =====================================================================
-- 01_schema.sql  ThreatLattice relational schema, v2 (MySQL 8.0)
-- Owner: Akshansh Agrawal (PES2UG24CS045)
--
-- How it runs: docker-compose mounts db/mysql/ into
-- /docker-entrypoint-initdb.d/, so this file runs first, already inside
-- the `threatlattice` database. To run it by hand:
--   mysql -u root -p threatlattice < db/mysql/01_schema.sql
-- There is no CREATE DATABASE / USE here on purpose: the database name
-- comes from MYSQL_DATABASE in .env, so hard-coding it would break the
-- moment someone renames it.
--
-- Changes from Deliverable 1 (agreed in HANDOFF 4.4), in short:
--   cve               NONE severity, cvss_version, KEV columns + CHECK
--   capec             five-level ENUMs (CAPEC's own scale)
--   attack_technique  ID format CHECK, tactic/platform moved out (1NF)
--   technique_tactic  NEW junction table (technique has many tactics)
--   cpe               version NOT NULL DEFAULT '*' (UNIQUE ignores NULL)
--   investigation     updated_at
--   app_user          is_active, last_login_at
--   audit_log         action CHECK, details JSON
--   security_event    NEW (Black October spotlight)
--   event_cve         NEW (curated CVEs per event, no FK to cve)
-- Views live in 02_views.sql, routines in 03, triggers in 04.
--
-- Storage engine is InnoDB and charset utf8mb4 (both MySQL 8.0 defaults).
-- InnoDB is required: MyISAM ignores foreign keys and has no
-- transactions, and the stored procedure relies on both.
-- =====================================================================


-- ---------------------------------------------------------------------
-- Catalogue tables (one row per catalogue entry)
-- Primary keys are the natural catalogue IDs (CWE-79, CVE-2021-44228)
-- instead of surrogate integers: every source file, URL and graph node
-- already uses them, so joins and the Neo4j sync need no lookup table.
-- ---------------------------------------------------------------------

-- cwe: kinds of weakness (Weaknesses AND Categories from the CWE XML,
-- because NVD sometimes tags a CVE with a category ID). Deprecated
-- entries are kept with their status so old CVEs still join.
CREATE TABLE cwe (
    cwe_id      VARCHAR(12)  PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    abstraction VARCHAR(20),              -- Pillar/Class/Base/Variant, or 'Category'
    status      VARCHAR(20),              -- Stable/Draft/Incomplete/Deprecated...
    description TEXT,
    -- REGEXP CHECK instead of trusting the loader: the database itself
    -- refuses 'XSS' or '79'; the app cannot bypass it.
    CONSTRAINT chk_cwe_id CHECK (cwe_id REGEXP '^CWE-[0-9]+$')
);

-- capec: attack patterns. Its links to CWE and ATT&CK live only in
-- Neo4j (EXPLOITS / ENABLES edges), which is why it has no FKs here.
CREATE TABLE capec (
    capec_id             VARCHAR(12)  PRIMARY KEY,
    name                 VARCHAR(255) NOT NULL,
    abstraction          VARCHAR(20),
    -- v2: CAPEC rates both fields on a five-level scale. Deliverable 1
    -- reused the CVSS ENUM (LOW..CRITICAL), which has no 'Very High'
    -- and would reject real CAPEC rows. ENUM over VARCHAR: closed set,
    -- 1 byte per row, and a typo like 'Hgh' is rejected. The loader
    -- upper-cases the source value ('Very High' -> 'VERY HIGH').
    likelihood_of_attack ENUM('VERY LOW','LOW','MEDIUM','HIGH','VERY HIGH'),
    typical_severity     ENUM('VERY LOW','LOW','MEDIUM','HIGH','VERY HIGH'),
    description          TEXT,
    CONSTRAINT chk_capec_id CHECK (capec_id REGEXP '^CAPEC-[0-9]+$')
);

-- attack_technique: MITRE ATT&CK Enterprise techniques and
-- sub-techniques. A sub-technique points at its parent through a
-- self-referencing FK (unary 1:N relationship).
CREATE TABLE attack_technique (
    technique_id        VARCHAR(12)  PRIMARY KEY,
    name                VARCHAR(255) NOT NULL,
    -- v2: the old `tactic` and `platform` columns are gone. One
    -- technique belongs to several tactics and runs on several
    -- platforms, so a single column would hold a list ('a,b,c') and
    -- break 1NF. Tactics are filtered and grouped -> own table
    -- (technique_tactic). Platforms are display-only -> JSON array,
    -- which keeps them as a real list without a fourth junction table.
    platforms           JSON NULL,
    is_subtechnique     BOOLEAN NOT NULL DEFAULT FALSE,
    parent_technique_id VARCHAR(12),
    description         TEXT,
    -- ON DELETE SET NULL, not CASCADE: deleting a parent should not
    -- silently wipe its sub-techniques. Loader inserts parents first.
    CONSTRAINT fk_attack_parent FOREIGN KEY (parent_technique_id)
        REFERENCES attack_technique(technique_id) ON DELETE SET NULL,
    -- v2: T + 4 digits, optional .3-digit sub-technique (T1190,
    -- T1059.001). '\\.' in a MySQL string becomes the regex '\.', a
    -- literal dot; a bare '.' would match any character.
    CONSTRAINT chk_technique_id CHECK (technique_id REGEXP '^T[0-9]{4}(\\.[0-9]{3})?$')
);

-- technique_tactic (v2, NEW): many-to-many between a technique and the
-- ATT&CK tactics (kill-chain phases) it serves. Tactic is stored as
-- its ATT&CK short name ('initial-access'); there are only 14 tactics
-- and they carry no attributes of their own, so a separate tactic
-- table would add a join and nothing else.
CREATE TABLE technique_tactic (
    technique_id VARCHAR(12) NOT NULL,
    tactic       VARCHAR(64) NOT NULL,
    -- Composite PK: the pair is the identity, and it stops the same
    -- tactic being listed twice for one technique.
    PRIMARY KEY (technique_id, tactic),
    -- CASCADE: a tactic link means nothing without its technique.
    CONSTRAINT fk_tt_technique FOREIGN KEY (technique_id)
        REFERENCES attack_technique(technique_id) ON DELETE CASCADE,
    -- ATT&CK short names are lower-case words joined by hyphens.
    CONSTRAINT chk_tactic CHECK (tactic REGEXP '^[a-z]+(-[a-z]+)*$')
);

-- cpe: affected products (vendor, product, version) parsed from the
-- NVD CPE 2.3 strings. Surrogate BIGINT key because the natural key is
-- three columns wide and cve_cpe would have to repeat all three.
CREATE TABLE cpe (
    cpe_id  BIGINT AUTO_INCREMENT PRIMARY KEY,
    vendor  VARCHAR(128) NOT NULL,
    product VARCHAR(128) NOT NULL,
    -- v2: NOT NULL DEFAULT '*'. A UNIQUE index treats NULLs as all
    -- different, so ('php','php',NULL) could be inserted many times.
    -- '*' is the CPE spec's own "any version" value, so no meaning is
    -- lost.
    version VARCHAR(64)  NOT NULL DEFAULT '*',
    CONSTRAINT uq_cpe UNIQUE (vendor, product, version)
);

-- cve: real vulnerabilities from the NVD 2024-2026 feeds, plus the
-- CISA KEV flag.
CREATE TABLE cve (
    cve_id             VARCHAR(20) PRIMARY KEY,   -- 2026 IDs reach 6+ digits; 20 chars is enough
    description        TEXT NOT NULL,
    published_date     DATE NOT NULL,
    last_modified_date DATE,
    -- DECIMAL(3,1), not FLOAT: scores are exact one-decimal values
    -- (9.8), and FLOAT would store 9.8 as 9.80000019 and break '='.
    -- NULLable because a freshly published CVE often has no score yet.
    cvss_base_score    DECIMAL(3,1),
    -- v2: 'NONE' added; NVD reports severity NONE for a 0.0 score.
    -- If the loader leaves this NULL, trigger trg_cve_bi derives it
    -- from the score (04_triggers.sql).
    cvss_severity      ENUM('NONE','LOW','MEDIUM','HIGH','CRITICAL'),
    -- v2: 255, was 128. NVD writes CVSS 4.0 vectors out in full (every
    -- optional metric, even 'X' = not defined), up to 178 characters;
    -- all 41,765 v4.0 vectors in the 2024-2026 feeds were over 128.
    cvss_vector        VARCHAR(255),
    -- v2: which CVSS version the score came from (3.1, 4.0, 3.0);
    -- scores from different versions are not strictly comparable.
    cvss_version       VARCHAR(4),
    -- v2: CISA Known Exploited Vulnerabilities. BOOLEAN NOT NULL
    -- DEFAULT FALSE (not NULL) so "not in KEV" is a clear FALSE and
    -- COUNT/SUM over it need no IFNULL.
    is_kev             BOOLEAN NOT NULL DEFAULT FALSE,
    kev_date_added     DATE NULL,
    kev_ransomware     BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT chk_cve_id      CHECK (cve_id REGEXP '^CVE-[0-9]{4}-[0-9]+$'),
    -- NULL passes a CHECK (it is not FALSE), so unscored CVEs are fine.
    CONSTRAINT chk_cvss_range  CHECK (cvss_base_score BETWEEN 0.0 AND 10.0),
    CONSTRAINT chk_cvss_version CHECK (cvss_version IN ('3.0','3.1','4.0')),
    -- v2: KEV date is present exactly when the CVE is in KEV. Written
    -- as two allowed states, so both "flag without date" and "date
    -- without flag" are rejected.
    CONSTRAINT chk_kev_date    CHECK ((is_kev = FALSE AND kev_date_added IS NULL)
                                   OR (is_kev = TRUE  AND kev_date_added IS NOT NULL)),
    -- Ransomware use is a KEV attribute, so it can only be TRUE on a
    -- KEV entry.
    CONSTRAINT chk_kev_ransomware CHECK (is_kev = TRUE OR kev_ransomware = FALSE)
);


-- ---------------------------------------------------------------------
-- Relationship (junction) tables
-- Composite PKs on the two FK columns: the pair is the identity and a
-- duplicate link is impossible. CASCADE on delete because a link row
-- has no meaning once either end is gone.
-- ---------------------------------------------------------------------

-- cve_cwe: M:N, a CVE can have several weaknesses and a weakness
-- appears in thousands of CVEs. Also copied to Neo4j as INSTANCE_OF,
-- the first hop of every chain.
CREATE TABLE cve_cwe (
    cve_id VARCHAR(20) NOT NULL,
    cwe_id VARCHAR(12) NOT NULL,
    PRIMARY KEY (cve_id, cwe_id),
    FOREIGN KEY (cve_id) REFERENCES cve(cve_id) ON DELETE CASCADE,
    FOREIGN KEY (cwe_id) REFERENCES cwe(cwe_id) ON DELETE CASCADE
);

-- cve_cpe: M:N, a CVE affects many products and a product has many CVEs.
CREATE TABLE cve_cpe (
    cve_id VARCHAR(20) NOT NULL,
    cpe_id BIGINT      NOT NULL,
    PRIMARY KEY (cve_id, cpe_id),
    FOREIGN KEY (cve_id) REFERENCES cve(cve_id) ON DELETE CASCADE,
    FOREIGN KEY (cpe_id) REFERENCES cpe(cpe_id) ON DELETE CASCADE
);

-- cwe_relationship: self-referencing M:N for the CWE hierarchy (a
-- weakness can have several parents across CWE views). One row =
-- child is ChildOf parent.
CREATE TABLE cwe_relationship (
    parent_cwe_id     VARCHAR(12) NOT NULL,
    child_cwe_id      VARCHAR(12) NOT NULL,
    relationship_type VARCHAR(20) NOT NULL DEFAULT 'ChildOf',
    PRIMARY KEY (parent_cwe_id, child_cwe_id),
    FOREIGN KEY (parent_cwe_id) REFERENCES cwe(cwe_id) ON DELETE CASCADE,
    FOREIGN KEY (child_cwe_id)  REFERENCES cwe(cwe_id) ON DELETE CASCADE,
    -- A weakness cannot be its own parent (would be a 1-node cycle).
    CONSTRAINT chk_no_self_ref CHECK (parent_cwe_id <> child_cwe_id)
);


-- ---------------------------------------------------------------------
-- Application tables (login, saved work, audit trail)
-- ---------------------------------------------------------------------

CREATE TABLE app_user (
    user_id       BIGINT AUTO_INCREMENT PRIMARY KEY,
    username      VARCHAR(50)  NOT NULL UNIQUE,
    email         VARCHAR(255) NOT NULL UNIQUE,
    -- Only a bcrypt hash is ever stored (60 chars; 255 leaves room for
    -- a future algorithm). The plain password never reaches MySQL.
    password_hash VARCHAR(255) NOT NULL,
    role          ENUM('analyst','admin') NOT NULL DEFAULT 'analyst',
    -- v2: deactivate instead of DELETE, so the user's investigations
    -- and audit history stay intact. sp_create_investigation refuses
    -- inactive users.
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMP NULL,              -- v2, set by the login API
    -- Basic shape check (something@something.tld). Full RFC validation
    -- is the API's job (zod); the DB just blocks obvious garbage.
    CONSTRAINT chk_email CHECK (email REGEXP '^[^@]+@[^@]+\\.[^@]+$')
);

-- investigation: an analyst's saved chain, starting from any node
-- type. start_node_id is not a FK because it can point at four
-- different tables; sp_create_investigation checks it exists instead.
CREATE TABLE investigation (
    investigation_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id          BIGINT NOT NULL,
    title            VARCHAR(200) NOT NULL,
    start_node_type  VARCHAR(20)  NOT NULL,
    start_node_id    VARCHAR(20)  NOT NULL,
    notes            TEXT,
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- v2: NULL until the first edit; MySQL sets it automatically on
    -- every UPDATE, so the API cannot forget to.
    updated_at       TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES app_user(user_id) ON DELETE CASCADE,
    CONSTRAINT chk_start_type CHECK (start_node_type IN ('CVE','CWE','CAPEC','TECHNIQUE'))
);

-- audit_log: written by triggers (04_triggers.sql) and the auth API.
-- user_id is NULLable + SET NULL so the log survives user deletion
-- (an audit trail that disappears with the user is useless).
CREATE TABLE audit_log (
    log_id    BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id   BIGINT,
    action    VARCHAR(20) NOT NULL,
    entity    VARCHAR(40) NOT NULL,
    entity_id VARCHAR(40),
    ts        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- v2: free-form context (title, before/after values on UPDATE).
    -- JSON instead of TEXT: MySQL validates it and can query into it.
    details   JSON NULL,
    FOREIGN KEY (user_id) REFERENCES app_user(user_id) ON DELETE SET NULL,
    -- v2: closed list of actions. CHECK + VARCHAR instead of ENUM so a
    -- new action is one ALTER of the constraint and existing rows are
    -- never rewritten.
    CONSTRAINT chk_audit_action CHECK (action IN
        ('INSERT','UPDATE','DELETE','LOGIN','LOGIN_FAIL','ROLE_CHANGE'))
);


-- ---------------------------------------------------------------------
-- Security events (v2, NEW): curated incidents such as Black October
-- 2026, each linked to its CVEs, for the spotlight page.
-- ---------------------------------------------------------------------

CREATE TABLE security_event (
    event_id  BIGINT AUTO_INCREMENT PRIMARY KEY,
    -- slug is the URL key (/spotlight/black-october-2026). Lower-case
    -- letters, digits and hyphens only, so it is always URL-safe.
    slug      VARCHAR(64)  NOT NULL UNIQUE,
    name      VARCHAR(120) NOT NULL,
    starts_on DATE NOT NULL,
    ends_on   DATE NOT NULL,
    summary   TEXT,
    CONSTRAINT chk_event_slug  CHECK (slug REGEXP '^[a-z0-9-]+$'),
    -- A one-day event (start = end) is allowed; ending before it
    -- starts is not.
    CONSTRAINT chk_event_dates CHECK (ends_on >= starts_on)
);

-- event_cve: M:N between events and CVEs.
CREATE TABLE event_cve (
    event_id BIGINT      NOT NULL,
    -- Deliberately NO foreign key to cve: an event is curated from the
    -- news, often before NVD publishes the CVE. A FK would block those
    -- rows. The spotlight page LEFT JOINs cve and shows missing ones
    -- as "awaiting NVD data". The CHECK still guarantees a real ID shape.
    cve_id   VARCHAR(20) NOT NULL,
    note     VARCHAR(255),
    PRIMARY KEY (event_id, cve_id),
    FOREIGN KEY (event_id) REFERENCES security_event(event_id) ON DELETE CASCADE,
    CONSTRAINT chk_event_cve_id CHECK (cve_id REGEXP '^CVE-[0-9]{4}-[0-9]+$')
);


-- ---------------------------------------------------------------------
-- ALTER: add the full-text index on CVE descriptions.
-- Done as a separate ALTER (not inline in CREATE TABLE) to demonstrate
-- ALTER in the report. Needed by MATCH(description) AGAINST(...) in the
-- search API: LIKE '%rce%' cannot use any index and scans every row,
-- and it has no relevance ranking.
-- ---------------------------------------------------------------------
ALTER TABLE cve ADD FULLTEXT INDEX idx_cve_fts (description);


-- ---------------------------------------------------------------------
-- Secondary indexes, one per real query pattern. PKs, UNIQUE columns
-- and FK columns are already indexed by InnoDB, so they are not
-- repeated here.
-- ---------------------------------------------------------------------
CREATE INDEX idx_cve_published ON cve(published_date);   -- date range filter, per-year/month stats
CREATE INDEX idx_cve_score     ON cve(cvss_base_score);  -- sort=score, score thresholds
CREATE INDEX idx_cve_severity  ON cve(cvss_severity);    -- severity filter and GROUP BY
CREATE INDEX idx_cve_kev       ON cve(is_kev);           -- v2: "known exploited only" filter, KEV KPI
-- cve_cwe / cve_cpe: the PK (cve_id, x) serves lookups by cve_id only;
-- these serve the reverse direction (all CVEs of a CWE / product).
CREATE INDEX idx_cvecwe_cwe    ON cve_cwe(cwe_id);
CREATE INDEX idx_cvecpe_cpe    ON cve_cpe(cpe_id);
-- v2: reverse lookups for the new junctions.
CREATE INDEX idx_tt_tactic     ON technique_tactic(tactic);  -- techniques per tactic
CREATE INDEX idx_eventcve_cve  ON event_cve(cve_id);         -- events for a CVE (CVE detail page)
-- v2: admin audit page filters by action and lists newest first.
CREATE INDEX idx_audit_action_ts ON audit_log(action, ts);
CREATE INDEX idx_audit_ts        ON audit_log(ts);


-- ---------------------------------------------------------------------
-- Teardown (DROP demonstration). Run only to reset the schema.
-- Views first (they depend on tables). FOREIGN_KEY_CHECKS = 0 lets the
-- tables drop in any order; the normal alternative is dropping
-- children before parents. With Docker the simpler reset is
--   docker compose down -v && docker compose up -d
-- ---------------------------------------------------------------------
-- DROP VIEW IF EXISTS v_critical_cve, v_cve_summary, v_cwe_stats, v_severity_by_year;
-- SET FOREIGN_KEY_CHECKS = 0;
-- DROP TABLE IF EXISTS event_cve, security_event,
--   audit_log, investigation, app_user,
--   cwe_relationship, cve_cpe, cve_cwe, cve, cpe,
--   technique_tactic, attack_technique, capec, cwe;
-- SET FOREIGN_KEY_CHECKS = 1;
