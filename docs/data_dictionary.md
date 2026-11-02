# ThreatLattice data dictionary (MySQL schema v2)

Source of truth: [`db/mysql/01_schema.sql`](../db/mysql/01_schema.sql). ER diagram: [`docs/diagrams/er_v2.png`](diagrams/er_v2.png) (source `er_v2.drawio`).

MySQL 8.0, InnoDB, utf8mb4. 14 tables in three groups:

| Group | Tables |
|---|---|
| Catalogue | `cwe`, `cve`, `capec`, `attack_technique`, `cpe` |
| Relationship (junction) | `cve_cwe`, `cve_cpe`, `cwe_relationship`, `technique_tactic`, `event_cve` |
| Application | `app_user`, `investigation`, `audit_log`, `security_event` |

Key column: **PK** primary key, **FK** foreign key, **UQ** unique. Rows marked *v2* are new or changed since Deliverable 1.

---

## Catalogue tables

### `cwe` — weakness types (CWE Weaknesses and Categories)
| Column | Type | Key | Null | Default | Constraints / notes |
|---|---|---|---|---|---|
| cwe_id | VARCHAR(12) | PK | no | | `chk_cwe_id`: `^CWE-[0-9]+$` |
| name | VARCHAR(255) | | no | | |
| abstraction | VARCHAR(20) | | yes | | Pillar, Class, Base, Variant, Compound, or `Category` |
| status | VARCHAR(20) | | yes | | Stable, Draft, Incomplete, Deprecated, ... (deprecated rows are kept) |
| description | TEXT | | yes | | |

### `cve` — vulnerabilities (NVD 2024–2026) with CISA KEV flag
| Column | Type | Key | Null | Default | Constraints / notes |
|---|---|---|---|---|---|
| cve_id | VARCHAR(20) | PK | no | | `chk_cve_id`: `^CVE-[0-9]{4}-[0-9]+$` |
| description | TEXT | | no | | FULLTEXT index `idx_cve_fts` (added by ALTER) |
| published_date | DATE | | no | | index `idx_cve_published` |
| last_modified_date | DATE | | yes | | |
| cvss_base_score | DECIMAL(3,1) | | yes | | `chk_cvss_range`: 0.0–10.0; NULL = not scored yet; index `idx_cve_score` |
| cvss_severity | ENUM('NONE','LOW','MEDIUM','HIGH','CRITICAL') | | yes | | *v2* adds `NONE`. Filled from the score by trigger `trg_cve_bi`/`trg_cve_bu` when NULL; index `idx_cve_severity` |
| cvss_vector | VARCHAR(255) | | yes | | *v2*: was 128; CVSS 4.0 vectors from NVD reach 178 chars. e.g. `CVSS:3.1/AV:N/AC:L/...` |
| cvss_version | VARCHAR(4) | | yes | | *v2*. `chk_cvss_version`: `3.0`, `3.1` or `4.0` |
| is_kev | BOOLEAN | | no | FALSE | *v2*. In CISA KEV; index `idx_cve_kev` |
| kev_date_added | DATE | | yes | | *v2*. `chk_kev_date`: set if and only if `is_kev` is TRUE |
| kev_ransomware | BOOLEAN | | no | FALSE | *v2*. `chk_kev_ransomware`: can be TRUE only when `is_kev` is TRUE |

### `capec` — attack patterns
| Column | Type | Key | Null | Default | Constraints / notes |
|---|---|---|---|---|---|
| capec_id | VARCHAR(12) | PK | no | | `chk_capec_id`: `^CAPEC-[0-9]+$` |
| name | VARCHAR(255) | | no | | |
| abstraction | VARCHAR(20) | | yes | | Meta, Standard, Detailed |
| likelihood_of_attack | ENUM('VERY LOW','LOW','MEDIUM','HIGH','VERY HIGH') | | yes | | *v2*: was VARCHAR(20) |
| typical_severity | ENUM('VERY LOW','LOW','MEDIUM','HIGH','VERY HIGH') | | yes | | *v2*: was the CVSS scale (LOW–CRITICAL) |
| description | TEXT | | yes | | |

CAPEC→CWE (`EXPLOITS`) and CAPEC→Technique (`ENABLES`) links exist only in Neo4j, so `capec` has no foreign keys.

### `attack_technique` — MITRE ATT&CK Enterprise techniques
| Column | Type | Key | Null | Default | Constraints / notes |
|---|---|---|---|---|---|
| technique_id | VARCHAR(12) | PK | no | | *v2* `chk_technique_id`: `^T[0-9]{4}(\.[0-9]{3})?$` (T1190, T1059.001) |
| name | VARCHAR(255) | | no | | |
| platforms | JSON | | yes | | *v2*: list such as `["Windows","Linux"]`, display only. Replaces `platform` |
| is_subtechnique | BOOLEAN | | no | FALSE | |
| parent_technique_id | VARCHAR(12) | FK → attack_technique.technique_id | yes | | `fk_attack_parent`, ON DELETE SET NULL |
| description | TEXT | | yes | | |

*v2*: the `tactic` and `platform` columns were removed. A technique has many of each, so one column would hold a list and break 1NF. Tactics moved to `technique_tactic`.

### `cpe` — affected products
| Column | Type | Key | Null | Default | Constraints / notes |
|---|---|---|---|---|---|
| cpe_id | BIGINT AUTO_INCREMENT | PK | no | | surrogate key |
| vendor | VARCHAR(128) | UQ (with product, version) | no | | |
| product | VARCHAR(128) | UQ | no | | |
| version | VARCHAR(64) | UQ | no | `'*'` | *v2*: was NULLable. `uq_cpe (vendor, product, version)` |

---

## Relationship (junction) tables

| Table | Columns | Keys | On delete | Purpose / constraints |
|---|---|---|---|---|
| `cve_cwe` | cve_id VARCHAR(20), cwe_id VARCHAR(12) | PK (cve_id, cwe_id); FK → cve, FK → cwe | CASCADE both | CVE M:N CWE. Index `idx_cvecwe_cwe` for the reverse lookup. NVD placeholders (`NVD-CWE-*`) are never stored |
| `cve_cpe` | cve_id VARCHAR(20), cpe_id BIGINT | PK (cve_id, cpe_id); FK → cve, FK → cpe | CASCADE both | CVE M:N product. Index `idx_cvecpe_cpe` |
| `cwe_relationship` | parent_cwe_id, child_cwe_id VARCHAR(12), relationship_type VARCHAR(20) DEFAULT 'ChildOf' | PK (parent, child); FK → cwe (twice) | CASCADE both | CWE hierarchy (self M:N). `chk_no_self_ref`: parent ≠ child |
| `technique_tactic` *v2* | technique_id VARCHAR(12), tactic VARCHAR(64) | PK (technique_id, tactic); FK → attack_technique | CASCADE | Technique M:N tactic. `chk_tactic`: `^[a-z]+(-[a-z]+)*$` (`initial-access`). Index `idx_tt_tactic` |
| `event_cve` *v2* | event_id BIGINT, cve_id VARCHAR(20), note VARCHAR(255) | PK (event_id, cve_id); FK → security_event | CASCADE | Event M:N CVE. **No FK to `cve`**, so curated IDs can be stored before NVD publishes them. `chk_event_cve_id` checks the format. Index `idx_eventcve_cve` |

---

## Application tables

### `app_user`
| Column | Type | Key | Null | Default | Constraints / notes |
|---|---|---|---|---|---|
| user_id | BIGINT AUTO_INCREMENT | PK | no | | |
| username | VARCHAR(50) | UQ | no | | |
| email | VARCHAR(255) | UQ | no | | `chk_email`: `^[^@]+@[^@]+\.[^@]+$` |
| password_hash | VARCHAR(255) | | no | | bcrypt hash only |
| role | ENUM('analyst','admin') | | no | `'analyst'` | |
| is_active | BOOLEAN | | no | TRUE | *v2*: users are deactivated, not deleted |
| created_at | TIMESTAMP | | no | CURRENT_TIMESTAMP | |
| last_login_at | TIMESTAMP | | yes | | *v2*: set by the login API |

### `investigation` — saved chain analyses
| Column | Type | Key | Null | Default | Constraints / notes |
|---|---|---|---|---|---|
| investigation_id | BIGINT AUTO_INCREMENT | PK | no | | |
| user_id | BIGINT | FK → app_user | no | | ON DELETE CASCADE |
| title | VARCHAR(200) | | no | | |
| start_node_type | VARCHAR(20) | | no | | `chk_start_type`: CVE, CWE, CAPEC, TECHNIQUE |
| start_node_id | VARCHAR(20) | | no | | Not a FK (can point at four tables). `sp_create_investigation` checks that it exists |
| notes | TEXT | | yes | | |
| created_at | TIMESTAMP | | no | CURRENT_TIMESTAMP | |
| updated_at | TIMESTAMP | | yes | NULL | *v2*: `ON UPDATE CURRENT_TIMESTAMP` |

### `audit_log`
| Column | Type | Key | Null | Default | Constraints / notes |
|---|---|---|---|---|---|
| log_id | BIGINT AUTO_INCREMENT | PK | no | | |
| user_id | BIGINT | FK → app_user | yes | | ON DELETE SET NULL (the log survives user deletion) |
| action | VARCHAR(20) | | no | | *v2* `chk_audit_action`: INSERT, UPDATE, DELETE, LOGIN, LOGIN_FAIL, ROLE_CHANGE |
| entity | VARCHAR(40) | | no | | e.g. `investigation`, `app_user` |
| entity_id | VARCHAR(40) | | yes | | |
| ts | TIMESTAMP | | no | CURRENT_TIMESTAMP | indexes `idx_audit_ts`, `idx_audit_action_ts (action, ts)` |
| details | JSON | | yes | | *v2*: title, before/after values |

Written by triggers `trg_inv_ai/au/ad` and `trg_user_au` (04_triggers.sql) and by the auth API (LOGIN, LOGIN_FAIL).

### `security_event` *v2* — curated incidents (Black October 2026)
| Column | Type | Key | Null | Default | Constraints / notes |
|---|---|---|---|---|---|
| event_id | BIGINT AUTO_INCREMENT | PK | no | | |
| slug | VARCHAR(64) | UQ | no | | `chk_event_slug`: `^[a-z0-9-]+$`, used in `/spotlight/<slug>` |
| name | VARCHAR(120) | | no | | |
| starts_on | DATE | | no | | |
| ends_on | DATE | | no | | `chk_event_dates`: ends_on ≥ starts_on |
| summary | TEXT | | yes | | |

---

## Relationships (cardinality)

| Relationship | Type | Implemented by |
|---|---|---|
| CVE has weakness CWE | M:N | `cve_cwe` |
| CVE affects product CPE | M:N | `cve_cpe` |
| CWE is child of CWE | M:N (recursive) | `cwe_relationship` |
| Technique is sub-technique of Technique | 1:N (recursive) | `attack_technique.parent_technique_id` |
| Technique belongs to tactic | M:N (multivalued attribute) | `technique_tactic` |
| Event includes CVE | M:N | `event_cve` (no FK on `cve_id`) |
| User owns investigation | 1:N | `investigation.user_id` |
| User appears in audit log | 1:N (optional) | `audit_log.user_id` |
| CAPEC exploits CWE, CAPEC enables Technique | M:N | Neo4j only (`EXPLOITS`, `ENABLES`) |

## Indexes

| Index | Table (columns) | Serves |
|---|---|---|
| `idx_cve_fts` FULLTEXT | cve (description) | keyword search (`MATCH ... AGAINST`) |
| `idx_cve_published` | cve (published_date) | date range filter, per-year/month stats |
| `idx_cve_score` | cve (cvss_base_score) | sort by score |
| `idx_cve_severity` | cve (cvss_severity) | severity filter / GROUP BY |
| `idx_cve_kev` | cve (is_kev) | KEV-only filter, KEV count |
| `idx_cvecwe_cwe` | cve_cwe (cwe_id) | all CVEs of a CWE |
| `idx_cvecpe_cpe` | cve_cpe (cpe_id) | all CVEs of a product |
| `idx_tt_tactic` | technique_tactic (tactic) | techniques per tactic |
| `idx_eventcve_cve` | event_cve (cve_id) | events a CVE belongs to |
| `idx_audit_action_ts` | audit_log (action, ts) | audit filter by action, newest first |
| `idx_audit_ts` | audit_log (ts) | audit list newest first |

Primary keys, UNIQUE columns and foreign key columns are indexed automatically by InnoDB.
