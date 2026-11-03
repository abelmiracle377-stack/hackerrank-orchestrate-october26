import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from main import Evidence, deletion_intent, evidence_values, plan, sort_steps, walk

class SyntheticAuditCases(unittest.TestCase):
    """Three small hand-authored policy cases; these supplement sample CSV scoring."""
    def test_non_deletion_request_is_not_applicable(self):
        self.assertFalse(deletion_intent("Please keep my account and do not delete anything."))

    def test_enabled_connector_requires_disable(self):
        e=Evidence("synthetic_01","synthetic.json","integration_service","data_flow_01",
          "2026-01-01T00:00:00Z",{"resource_id":"data_flow_01","enabled":True},"ACTIVE_DATA_FLOW","")
        steps=sort_steps(plan([e]))
        self.assertEqual([s.operation for s in steps],
          ["REPORT_ACTIVE_DATA_FLOW","DISABLE_DATA_FLOW","VERIFY_DATA_FLOW_DISABLED"])
        self.assertEqual([s.state for s in steps],["ACTIVE","DISABLED","DISABLED"])

    def test_restore_allowed_backup_requires_block(self):
        e=Evidence("synthetic_02","synthetic.json","backup_service","backup_02",
          "2026-01-01T00:00:00Z",{"resource_id":"backup_02","restore_allowed":True},"BACKUP_ARCHIVE","")
        steps=sort_steps(plan([e]))
        self.assertEqual([s.operation for s in steps],
          ["REPORT_RESTORE_RISK","BLOCK_RESTORE","VERIFY_RESTORE_BLOCKED"])
        self.assertEqual([s.state for s in steps],["ACTIVE","BLOCKED","BLOCKED"])

    def test_evidence_walk_does_not_mix_sibling_subjects(self):
        bundle={"captured_at":"2026-01-01T00:00:00Z","records":[
          {"resource_id":"search_01","email":"alpha@example.test"},
          {"resource_id":"search_02","email":"beta@example.test"}]}
        rows=[r for r in walk(bundle) if r.get("resource_id")]
        self.assertEqual(len(rows),2)
        self.assertIn("alpha@example.test",evidence_values(rows[0]))
        self.assertNotIn("beta@example.test",evidence_values(rows[0]))

    def test_retained_security_record_is_verified_not_deleted(self):
        e=Evidence("synthetic_03","synthetic.json","security_service","audit_record_03",
          "2026-01-01T00:00:00Z",{"resource_id":"audit_record_03","retention_until":"2030-01-01"},"SECURITY_AUDIT_LOG","")
        steps=plan([e])
        self.assertEqual(len(steps),1)
        self.assertEqual(steps[0].operation,"VERIFY_RECORD_PRESENT")
        self.assertEqual(steps[0].phase,"VERIFICATION")

if __name__=="__main__": unittest.main()
