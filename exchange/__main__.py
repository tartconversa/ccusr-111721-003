import argparse
import json

from .service import Exchange


def main():
    parser = argparse.ArgumentParser(description="本地协作台账演练")
    parser.add_argument("--database", required=True)
    args = parser.parse_args()
    service = Exchange(args.database)
    try:
        service.catalog.register("flow", "机构甲", "甲地", "business", [("count", "通行计数", "integer", False)], "2026-11-17")
        service.catalog.ingest("item-1", "flow", {"count": 7}, "2026-11-17")
        service.grants.define_purpose("供应链协调", None, "2026-11-17", "机构甲")
        service.grants.define_purpose("供应链协调·报关", "供应链协调", "2026-11-17", "机构甲")
        service.grants.issue("g-1", "flow", "机构乙", "供应链协调", "2026-12-31", "2026-11-17", delegable=True)
        service.grants.issue("g-2", "flow", "境外机构丙", "供应链协调·报关", "2026-11-30", "2026-11-17", grantor="机构乙", parent="g-1")
        service.policies.set("甲地", "business", "供应链协调·报关", "allow", "2026-11-17", "机构甲")
        revision = service.products.assemble("report", "通行汇总", ["item-1"], "2026-11-17", "机构甲")
        receipt = service.delivery.send("d-1", "report", revision, "境外机构丙", "供应链协调·报关", "2026-11-18")
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
        impact = service.grants.revoke("g-1", "2026-11-19", "机构甲")
        print(json.dumps(impact, ensure_ascii=False, sort_keys=True))
        try:
            service.delivery.send("d-2", "report", revision, "境外机构丙", "供应链协调·报关", "2026-11-20")
        except PermissionError as reasons:
            print(json.dumps(reasons.args[0], ensure_ascii=False, sort_keys=True))
        print(json.dumps(service.delivery.explain("d-1", "2026-11-20"), ensure_ascii=False, sort_keys=True))
    finally:
        service.close()


if __name__ == "__main__":
    main()
