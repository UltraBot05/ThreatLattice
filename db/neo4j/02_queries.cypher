// ThreatLattice graph queries (Neo4j 5). Parameters are written $name.
// Run in the Neo4j browser (http://localhost:7474) with :param, e.g.
//   :param cve => 'CVE-2026-109618'
// The app (B4) runs the same patterns through lib/db/neo4j.ts.
//
// Model: (CVE)-[:INSTANCE_OF]->(CWE)-[:CHILD_OF]->(CWE)
//        (CAPEC)-[:EXPLOITS]->(CWE)   (CAPEC)-[:ENABLES]->(Technique)
//        (Technique)-[:SUBTECHNIQUE_OF]->(Technique)

// ---------------------------------------------------------------------------
// Q1. Attack chain from one CVE (the core question of the project).
// Why CHILD_OF*0..2: CVEs are often tagged with a very specific weakness
// (CWE-416 Use After Free) while attack patterns are written against its
// parents (CWE-825, CWE-672). Walking up to two levels finds them; *0 keeps
// the direct match. Bounded (not *) so the expansion stays small.
MATCH (v:CVE {id: $cve})-[:INSTANCE_OF]->(w:CWE)
OPTIONAL MATCH p = (w)-[:CHILD_OF*0..2]->(anc:CWE)<-[:EXPLOITS]-(a:CAPEC)-[:ENABLES]->(t:Technique)
RETURN v.id AS cve, w.id AS cwe, coalesce(w.common_name, w.name) AS weakness,
       [n IN nodes(p) WHERE n:CWE | n.id] AS cwe_path,
       a.id AS capec, a.name AS pattern, t.id AS technique, t.name AS technique_name, t.tactics AS tactics
ORDER BY cwe, size(cwe_path), capec, technique;

// ---------------------------------------------------------------------------
// Q2. Same chain as a path list for the graph view (nodes + relationships).
MATCH (v:CVE {id: $cve})
OPTIONAL MATCH p = (v)-[:INSTANCE_OF]->(:CWE)-[:CHILD_OF*0..2]->(:CWE)<-[:EXPLOITS]-(:CAPEC)-[:ENABLES]->(:Technique)
RETURN p
LIMIT 200;

// ---------------------------------------------------------------------------
// Q3. Shortest connection from a weakness to a technique (any direction over
// our relationship types). shortestPath stops at the first, shortest path.
MATCH (w:CWE {id: $cwe}), (t:Technique {id: $technique})
MATCH p = shortestPath((w)-[:CHILD_OF|EXPLOITS|ENABLES|SUBTECHNIQUE_OF*..8]-(t))
RETURN [n IN nodes(p) | coalesce(n.id, '')] AS path, length(p) AS hops;

// ---------------------------------------------------------------------------
// Q4. Aggregation: which weaknesses open the most attacker techniques?
// count(DISTINCT t) because one technique can be reached via several patterns.
MATCH (w:CWE)<-[:EXPLOITS]-(:CAPEC)-[:ENABLES]->(t:Technique)
WITH w, count(DISTINCT t) AS techniques
MATCH (w)<-[:INSTANCE_OF]-(v:CVE)
RETURN w.id AS cwe, coalesce(w.common_name, w.name) AS weakness, techniques, count(v) AS cves
ORDER BY techniques DESC, cves DESC
LIMIT 10;

// ---------------------------------------------------------------------------
// Q5. Aggregation: ATT&CK tactics reachable from KNOWN EXPLOITED CVEs.
// UNWIND turns each technique's tactics list into rows so we can group by tactic.
MATCH (v:CVE {is_kev: true})-[:INSTANCE_OF]->(:CWE)-[:CHILD_OF*0..2]->(:CWE)<-[:EXPLOITS]-(:CAPEC)-[:ENABLES]->(t:Technique)
UNWIND t.tactics AS tactic
RETURN tactic, count(DISTINCT v) AS kev_cves, count(DISTINCT t) AS techniques
ORDER BY kev_cves DESC;

// ---------------------------------------------------------------------------
// Q6. Black October: techniques per CVE in the spotlight (ids from MySQL event_cve).
UNWIND $cves AS id
MATCH (v:CVE {id: id})
OPTIONAL MATCH (v)-[:INSTANCE_OF]->(:CWE)-[:CHILD_OF*0..2]->(:CWE)<-[:EXPLOITS]-(:CAPEC)-[:ENABLES]->(t:Technique)
RETURN v.id AS cve, v.severity AS severity, v.is_kev AS kev, collect(DISTINCT t.id) AS techniques
ORDER BY size(techniques) DESC;

// ---------------------------------------------------------------------------
// Q7. Graph size (for the report).
CALL () { MATCH (n) RETURN labels(n)[0] AS kind, count(*) AS total
          UNION ALL
          MATCH ()-[r]->() RETURN type(r) AS kind, count(*) AS total }
RETURN kind, total ORDER BY kind;
