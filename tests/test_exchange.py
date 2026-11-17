import json
import tempfile
import unittest
from pathlib import Path

from exchange import Exchange


class ExchangeFlowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = Exchange(Path(self.temp.name) / "exchange.db")
        self.service.catalog.register("flow", "机构甲", "甲地", "restricted", [("count", "通行计数", "integer", False)], "2026-11-01")
        self.service.catalog.ingest("item-1", "flow", {"count": 8}, "2026-11-02")
        self.service.grants.define_purpose("运行协调", None, "2026-11-03", "机构甲")
        self.service.grants.issue("g-1", "flow", "机构乙", "运行协调", "2026-12-31", "2026-11-03")
        self.service.policies.set("甲地", "restricted", "运行协调", "allow", "2026-11-03", "机构甲")
        self.revision = self.service.products.assemble("report", "通行观察", ["item-1"], "2026-11-04", "机构甲")

    def tearDown(self):
        self.service.close()
        self.temp.cleanup()

    def test_delivery_keeps_revision_and_request_identity(self):
        desk = self.service.delivery
        receipt = desk.send("d-1", "report", self.revision, "机构乙", "运行协调", "2026-11-05")
        self.assertEqual(receipt["product_revision"], self.revision)
        self.assertEqual(receipt, desk.send("d-1", "report", self.revision, "机构乙", "运行协调", "2026-11-05"))
        with self.assertRaises(ValueError):
            desk.send("d-1", "report", self.revision, "其他机构", "运行协调", "2026-11-05")

    def test_grant_and_policy_gate_delivery(self):
        with self.assertRaises(PermissionError):
            self.service.delivery.send("d-2", "report", self.revision, "陌生机构", "运行协调", "2026-11-05")
        self.service.policies.set("甲地", "restricted", "运行协调", "deny", "2026-11-06", "机构甲")
        with self.assertRaises(PermissionError):
            self.service.delivery.send("d-3", "report", self.revision, "机构乙", "运行协调", "2026-11-07")
        self.assertTrue(self.service.history("report"))

    def test_unknown_fields_rejected(self):
        with self.assertRaises(ValueError):
            self.service.catalog.ingest("item-2", "flow", {"unknown": 9}, "2026-11-03")


class GrantChainTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.service = Exchange(Path(self.temp.name) / "exchange.db")
        self.service.catalog.register("flow", "机构甲", "甲地", "restricted", [("count", "通行计数", "integer", False)], "2026-11-01")
        self.service.catalog.ingest("item-1", "flow", {"count": 8}, "2026-11-02")
        grants = self.service.grants
        grants.define_purpose("供应链协调", None, "2026-11-02", "机构甲")
        grants.define_purpose("供应链协调·报关", "供应链协调", "2026-11-02", "机构甲")
        grants.define_purpose("供应链协调·仓储", "供应链协调", "2026-11-02", "机构甲")
        grants.define_purpose("营销推广", None, "2026-11-02", "机构甲")
        grants.issue("g-1", "flow", "机构乙", "供应链协调", "2026-12-31", "2026-11-03", delegable=True)
        grants.issue("g-2", "flow", "境外机构丙", "供应链协调·报关", "2026-11-30", "2026-11-03", grantor="机构乙", parent="g-1")
        for purpose in ("供应链协调·报关", "供应链协调·仓储", "营销推广"):
            self.service.policies.set("甲地", "restricted", purpose, "allow", "2026-11-03", "机构甲")
        self.revision = self.service.products.assemble("report", "通行观察", ["item-1"], "2026-11-04", "机构甲")

    def tearDown(self):
        self.service.close()
        self.temp.cleanup()

    def test_sub_grant_requires_delegable_parent(self):
        self.service.grants.issue("g-9", "flow", "机构丁", "供应链协调", "2026-12-31", "2026-11-03")
        with self.assertRaises(ValueError):
            self.service.grants.issue("g-10", "flow", "机构戊", "供应链协调", "2026-12-01", "2026-11-04", grantor="机构丁", parent="g-9")

    def test_sub_grant_must_narrow_purpose_validity_and_grantor(self):
        grants = self.service.grants
        with self.assertRaises(ValueError):
            grants.issue("g-11", "flow", "机构戊", "营销推广", "2026-11-01", "2026-11-04", grantor="机构乙", parent="g-1")
        with self.assertRaises(ValueError):
            grants.issue("g-12", "flow", "机构戊", "供应链协调·报关", "2027-01-31", "2026-11-04", grantor="机构乙", parent="g-1")
        with self.assertRaises(ValueError):
            grants.issue("g-13", "flow", "机构戊", "供应链协调·报关", "2026-11-01", "2026-11-04", grantor="机构丁", parent="g-1")
        with self.assertRaises(KeyError):
            grants.issue("g-14", "flow", "机构戊", "未登记用途", "2026-11-01", "2026-11-04")

    def test_delivery_follows_chain_and_records_basis(self):
        receipt = self.service.delivery.send("d-1", "report", self.revision, "境外机构丙", "供应链协调·报关", "2026-11-05")
        chain = json.loads(receipt["chain"])
        self.assertEqual([link["grant"] for link in chain["flow"]["grants"]], ["g-1", "g-2"])
        self.assertTrue(all(link["ok"] for link in chain["flow"]["grants"]))

    def test_delivery_blocked_when_purpose_outside_chain(self):
        with self.assertRaises(PermissionError) as ctx:
            self.service.delivery.send("d-2", "report", self.revision, "境外机构丙", "供应链协调·仓储", "2026-11-05")
        candidates = ctx.exception.args[0][0]["candidates"]
        self.assertEqual(candidates[0]["broken"], "g-2")
        self.assertEqual(candidates[0]["grants"][1]["reason"], "用途超出该环许可范围")
        self.assertTrue(candidates[0]["grants"][0]["ok"])

    def test_delivery_blocked_when_link_expired(self):
        with self.assertRaises(PermissionError) as ctx:
            self.service.delivery.send("d-3", "report", self.revision, "境外机构丙", "供应链协调·报关", "2026-12-01")
        link = ctx.exception.args[0][0]["candidates"][0]["grants"][1]
        self.assertEqual(link["grant"], "g-2")
        self.assertEqual(link["reason"], "许可已过有效期")

    def test_revoke_stops_downstream_and_marks_completed(self):
        desk = self.service.delivery
        receipt = desk.send("d-4", "report", self.revision, "境外机构丙", "供应链协调·报关", "2026-11-05")
        impact = self.service.grants.revoke("g-1", "2026-11-06", "机构甲")
        self.assertEqual(impact["descendants"], ["g-2"])
        self.assertEqual(impact["deliveries"], ["d-4"])
        with self.assertRaises(PermissionError) as ctx:
            desk.send("d-5", "report", self.revision, "境外机构丙", "供应链协调·报关", "2026-11-07")
        broken = ctx.exception.args[0][0]["candidates"][0]["grants"][0]
        self.assertEqual(broken["grant"], "g-1")
        self.assertEqual(broken["reason"], "许可已撤销")
        report = desk.explain("d-4", "2026-11-08")
        self.assertEqual(report["status"], "affected")
        self.assertEqual(report["impacts"][0]["grant"], "g-1")
        self.assertEqual([link["grant"] for link in report["chain"]["flow"]["grants"]], ["g-1", "g-2"])
        self.assertEqual(desk.send("d-4", "report", self.revision, "境外机构丙", "供应链协调·报关", "2026-11-05"), receipt)

    def test_explain_reports_intact_chain(self):
        self.service.delivery.send("d-6", "report", self.revision, "境外机构丙", "供应链协调·报关", "2026-11-05")
        report = self.service.delivery.explain("d-6", "2026-11-06")
        self.assertEqual(report["status"], "intact")
        self.assertEqual(report["impacts"], [])


if __name__ == "__main__":
    unittest.main()
