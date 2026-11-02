// ThreatLattice graph schema (Neo4j 5). Run by: python -m etl.neo4j_schema
// The graph has no DDL like MySQL; these constraints are its equivalent.
// A uniqueness constraint also creates the index used to look a node up by id,
// which is where every traversal starts (MATCH (c:CVE {id: $id}) ...).

CREATE CONSTRAINT cve_id   IF NOT EXISTS FOR (n:CVE)       REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT cwe_id   IF NOT EXISTS FOR (n:CWE)       REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT capec_id IF NOT EXISTS FOR (n:CAPEC)     REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT tech_id  IF NOT EXISTS FOR (n:Technique) REQUIRE n.id IS UNIQUE;

// Extra index for the dashboard-style graph queries (critical CVEs first).
CREATE INDEX cve_severity IF NOT EXISTS FOR (n:CVE) ON (n.severity);
