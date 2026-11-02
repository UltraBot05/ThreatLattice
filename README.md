# ThreatLattice

A security knowledge graph that links four public catalogues, **CVE** (real vulnerabilities), **CWE** (weakness types), **CAPEC** (attack patterns) and **MITRE ATT&CK** (attacker techniques), so one query walks from a vulnerability to the attacks it enables:

```
CVE  --INSTANCE_OF-->  CWE  <--EXPLOITS--  CAPEC  --ENABLES-->  ATT&CK technique
```

PES University, DBMS Experiential Learning (Level 3), Section 5A CSE.
Abhigyan Dutta (PES2UG24CS019) and Akshansh Agrawal (PES2UG24CS045).

## Stack

| Layer | Technology | Why |
|---|---|---|
| Relational DB | MySQL 8.0 | attribute-heavy records: filter, sort, group, full-text search, users, investigations, audit |
| Graph DB | Neo4j 5 | cross-catalogue links: multi-hop chain traversal and shortest path |
| Web + API | Next.js 16 (App Router, route handlers), TypeScript | UI and the API layer between the browser and both databases |
| UI | Tailwind 4, GSAP 3.15, Lenis, Recharts, React Flow | "Declassified" design system |
| Data loading | Python 3.12 (PyMySQL, neo4j driver) | download and load NVD, CWE, CAPEC, ATT&CK and CISA KEV |

## Repository layout

```
docker-compose.yml   MySQL (host port 3307) + Neo4j (7474 browser, 7687 bolt)
.env.example         every setting; copy to .env (never commit .env)
db/mysql/            DDL, views, routines, triggers, grants (run at container init in name order)
  queries/           report queries        tests/  constraint tests
db/neo4j/            constraints and Cypher queries
etl/                 Python loaders (common/ = config + connections)
web/                 Next.js app
  app/               pages and app/api route handlers
  components/ui      shared components      components/motion  GSAP primitives
  lib/db             MySQL + Neo4j access    lib/auth  sessions + passwords
docs/                report material, ER diagram, data dictionary, testing
```

## Setup

Requirements: Docker Desktop, Python 3.12+, Node.js 22+.

```bash
# 1. settings
cp .env.example .env            # then change every password and AUTH_SECRET

# 2. databases (first start runs db/mysql/*.sql and 05_grants.sh)
docker compose up -d
docker compose ps               # both should become "healthy"

# 3. data
python -m venv .venv
.venv/Scripts/activate          # Windows; on macOS/Linux: source .venv/bin/activate
pip install -r etl/requirements.txt
python -m etl.download          # ~100 MB into data/raw/
python -m etl.load_cwe
python -m etl.load_nvd          # ~90 s
python -m etl.load_kev

# 4. web app
cd web
npm install
npm run dev                     # http://localhost:3000
```

Reset the databases completely: `docker compose down -v && docker compose up -d`.

Check both databases from the app: `http://localhost:3000/api/health`.

## Security notes

- No credentials in code: everything comes from `.env` (ignored by git).
- The web app connects as `tl_app`, which can only SELECT, INSERT, UPDATE, DELETE and EXECUTE. Only the ETL uses root.
- Passwords are stored as bcrypt hashes. Sessions are signed, httpOnly cookies, and every protected route re-checks the user in MySQL.
- All SQL uses placeholders; all Cypher uses parameters.

## Contributing

Every change goes through a pull request into `main` (protected: 1 approval, rebase merge only). Branch names: `feat/<issue>-<slug>`. Commit messages: `feat(db): ...`, `fix(etl): ...`, `docs: ...`.
