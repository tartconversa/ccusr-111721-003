import hashlib
import json

from .audit import write
from .grants import Grants
from .policy import Policies
from .products import Products


class Delivery:
    def __init__(self, connection):
        self.connection = connection
        self.grants = Grants(connection)
        self.policies = Policies(connection)
        self.products = Products(connection)

    def send(self, delivery_id, product_id, revision, recipient, purpose, at):
        existing = self.connection.execute("SELECT * FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
        if existing:
            if (existing["product_id"], existing["product_revision"], existing["recipient"], existing["purpose"]) != (product_id, revision, recipient, purpose):
                raise ValueError("交付编号已用于其他请求")
            return dict(existing)
        product = self.connection.execute("SELECT state FROM products WHERE id=? AND revision=?", (product_id, revision)).fetchone()
        if product is None or product["state"] != "draft":
            raise ValueError("数据产品修订不可交付")
        inputs = self.products.inputs(product_id, revision)
        if not inputs:
            raise ValueError("数据产品缺少输入")
        reasons, revisions, chains = [], {}, {}
        for asset in inputs:
            source_id = asset["source_id"]
            if asset["state"] != "active" or not asset["source_active"]:
                reasons.append({"source": source_id, "reason": "inactive"})
            outcome = self.grants.trace(source_id, recipient, purpose, at)
            if outcome["allowed"] is None:
                reasons.append({"source": source_id, "reason": "grant", "candidates": outcome["candidates"]})
            else:
                chains[source_id] = outcome["allowed"]
            decision, policy_revision = self.policies.decision(asset["jurisdiction"], asset["classification"], purpose)
            revisions[source_id] = policy_revision
            if decision != "allow":
                reasons.append({"source": source_id, "reason": "policy"})
        if reasons:
            with self.connection:
                write(self.connection, at, recipient, "delivery.reject", product_id, {"revision": revision, "reasons": reasons})
            raise PermissionError(reasons)
        digest = hashlib.sha256("|".join(asset["digest"] for asset in inputs).encode()).hexdigest()
        with self.connection:
            self.connection.execute(
                "INSERT INTO deliveries(id,product_id,product_revision,recipient,purpose,created_at,input_digest,policy_revisions,chain) VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    delivery_id, product_id, revision, recipient, purpose, at, digest,
                    json.dumps(revisions, sort_keys=True),
                    json.dumps(chains, ensure_ascii=False, sort_keys=True),
                ),
            )
            write(
                self.connection, at, recipient, "delivery.accept", delivery_id,
                {
                    "product": product_id,
                    "revision": revision,
                    "inputs": [a["id"] for a in inputs],
                    "chains": {source: [link["grant"] for link in chain["grants"]] for source, chain in chains.items()},
                },
            )
        return dict(self.connection.execute("SELECT * FROM deliveries WHERE id=?", (delivery_id,)).fetchone())

    def explain(self, delivery_id, at):
        row = self.connection.execute("SELECT * FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
        if row is None:
            raise KeyError(delivery_id)
        chain = json.loads(row["chain"])
        impacts = []
        for source_id, candidate in chain.items():
            for link in candidate["grants"]:
                current = self.connection.execute("SELECT status,valid_until FROM grants WHERE id=?", (link["grant"],)).fetchone()
                if current is None:
                    link["current"], problem = "missing", "许可记录缺失"
                elif current["status"] != "active":
                    link["current"], problem = current["status"], "许可已撤销"
                elif current["valid_until"] < at:
                    link["current"], problem = "expired", "许可已过有效期"
                else:
                    link["current"], problem = "active", None
                if problem:
                    impacts.append({"source": source_id, "grant": link["grant"], "problem": problem})
        return {
            "delivery": dict(row),
            "chain": chain,
            "status": "affected" if impacts else "intact",
            "impacts": impacts,
        }
