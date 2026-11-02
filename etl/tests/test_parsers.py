"""Parser tests for the CAPEC and ATT&CK loaders (no database needed).

Run:  python -m unittest discover -s etl/tests -t .
The fixtures copy the real file structures (CAPEC XML 3.x with namespace and
nested XHTML, ATT&CK STIX 2.1 bundle) with the edge cases the loaders handle.
"""
import json
import unittest
from pathlib import Path

from etl import load_attack, load_capec

FIX = Path(__file__).parent / "fixtures"


class CapecParserTest(unittest.TestCase):
    def setUp(self):
        self.rows, self.exploits, self.enables, self.counts = load_capec.parse(FIX / "capec_sample.xml")
        self.by_id = {r[0]: r for r in self.rows}

    def test_skips_deprecated(self):
        self.assertNotIn("CAPEC-9", self.by_id)
        self.assertEqual(self.counts["skipped_deprecated"], 1)

    def test_fields_and_levels(self):
        r = self.by_id["CAPEC-66"]
        self.assertEqual(r[1:5], ("SQL Injection", "Standard", "HIGH", "VERY HIGH"))
        self.assertIn("constructs SQL statements", r[5])  # nested XHTML flattened, whitespace collapsed

    def test_unknown_level_becomes_null(self):
        self.assertIsNone(self.by_id["CAPEC-471"][4])
        self.assertEqual(self.counts["unknown_severity"], 1)

    def test_exploits_pairs(self):
        self.assertEqual(self.exploits, [("CAPEC-471", "CWE-427"), ("CAPEC-66", "CWE-20"), ("CAPEC-66", "CWE-89")])

    def test_enables_only_attack_taxonomy(self):
        self.assertEqual(self.enables, [("CAPEC-471", "T1574"), ("CAPEC-471", "T1574.008")])
        self.assertEqual(self.counts["bad_attack_ids"], 1)


class AttackParserTest(unittest.TestCase):
    def setUp(self):
        self.rows, self.tactics, self.capec, self.counts = load_attack.parse(FIX / "attack_sample.json")
        self.by_id = {r[0]: r for r in self.rows}

    def test_skips_revoked_and_deprecated(self):
        self.assertNotIn("T1000", self.by_id)
        self.assertNotIn("T1001", self.by_id)
        self.assertEqual(self.counts["skipped_revoked_or_deprecated"], 2)

    def test_parents_before_subtechniques(self):
        order = [r[0] for r in self.rows]
        self.assertLess(order.index("T1059"), order.index("T1059.001"))
        self.assertTrue(all("." not in t for t in order[:2]))

    def test_parent_and_orphan(self):
        self.assertEqual(self.by_id["T1059.001"][3:5], (True, "T1059"))
        self.assertEqual(self.by_id["T9999.001"][4], None)
        self.assertEqual(self.counts["subtechniques_without_parent"], 1)

    def test_platforms_json_and_tactics(self):
        self.assertEqual(json.loads(self.by_id["T1190"][2]), ["Linux", "Windows", "Containers"])
        self.assertIn(("T1190", "initial-access"), self.tactics)
        self.assertNotIn(("T1059", "ignored"), self.tactics)

    def test_capec_refs(self):
        self.assertEqual(self.capec, [("CAPEC-66", "T1190")])


if __name__ == "__main__":
    unittest.main()
