import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "cache" / "final_mnt4_pairing" / "release_summary.json"


class FinalReleaseSummaryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.summary = json.loads(SUMMARY.read_text())

    def test_relation_roots_are_reported(self):
        relation_roots = self.summary["relation_roots"]
        self.assertRegex(relation_roots["lineCacheRelationRoot"], r"^0x[0-9a-f]{64}$")
        self.assertRegex(relation_roots["millerRelationRoot"], r"^0x[0-9a-f]{64}$")
        self.assertRegex(relation_roots["finalExponentiationRelationRoot"], r"^0x[0-9a-f]{64}$")

    def test_pipeline_summary_separates_envelope_from_mnt_native_layer(self):
        pipeline = self.summary["pipeline"]
        self.assertEqual(pipeline["evm_verifier_layer"], "compact_bn254_verifier_envelope")
        self.assertEqual(pipeline["offchain_source"], "rust_arkworks_mnt4_backend")
        self.assertEqual(pipeline["future_folding_layer"], "mnt4_mnt6_native_relation_layer")

    def test_comparison_table_contains_core_metrics(self):
        table = self.summary["comparison_table"]
        self.assertGreater(table["old_full_onchain_reference_gas"], 100_000_000)
        self.assertLess(table["new_final_verifier_gas"], 500_000)
        self.assertEqual(table["bn254_envelope_constraints"], 1538)
        self.assertEqual(table["mnt_native_relation_constraints"], 24178)
        self.assertGreater(table["bn254_emulated_pairing_reference_constraints"], table["mnt_native_relation_constraints"])


if __name__ == "__main__":
    unittest.main()

class FinalReleaseCompiledNativeRelationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.summary = json.loads(SUMMARY.read_text())

    def test_compiled_native_relation_metrics_are_reported(self):
        table = self.summary["comparison_table"]
        self.assertGreater(table["compiled_mnt_native_relation_constraints"], table["mnt_native_relation_constraints"])
        self.assertLess(table["compiled_mnt_native_relation_constraints"], table["bn254_emulated_pairing_reference_constraints"])
        self.assertEqual(table["compiled_mnt_native_relation_public_inputs"], 3)
        self.assertTrue(table["compiled_mnt_native_relation_satisfied"])

    def test_rust_backend_exports_native_relation_summary(self):
        native = self.summary["rust_backend"]["native_relation"]
        self.assertEqual(native["kind"], "compiledMntNativeRelation")
        self.assertTrue(native["is_satisfied"])
        self.assertGreater(native["constraints"], native["estimated_constraints"])
