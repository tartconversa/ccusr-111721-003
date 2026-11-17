import json

from .audit import write

MAX_CHAIN_DEPTH = 32


class Grants:
    def __init__(self, connection):
        self.connection = connection

    def define_purpose(self, name, parent, at, actor):
        if parent is not None and self.connection.execute(
            "SELECT name FROM purposes WHERE name=?", (parent,)
        ).fetchone() is None:
            raise KeyError(parent)
        with self.connection:
            self.connection.execute("INSERT INTO purposes(name,parent) VALUES(?,?)", (name, parent))
            write(self.connection, at, actor, "purpose.define", name, {"parent": parent})

    def purpose_covers(self, ancestor, purpose):
        seen, current = set(), purpose
        while current is not None and current not in seen:
            if current == ancestor:
                return True
            seen.add(current)
            row = self.connection.execute("SELECT parent FROM purposes WHERE name=?", (current,)).fetchone()
            current = row["parent"] if row else None
        return False

    def issue(self, grant_id, source_id, recipient, purpose, valid_until, at, grantor=None, parent=None, delegable=False):
        source = self.connection.execute("SELECT owner FROM sources WHERE id=?", (source_id,)).fetchone()
        if source is None:
            raise KeyError(source_id)
        if self.connection.execute("SELECT name FROM purposes WHERE name=?", (purpose,)).fetchone() is None:
            raise KeyError(purpose)
        if parent is None:
            if grantor is not None and grantor != source["owner"]:
                raise ValueError("原始许可只能由来源方签发")
            grantor = source["owner"]
        else:
            upstream = self.connection.execute("SELECT * FROM grants WHERE id=?", (parent,)).fetchone()
            if upstream is None:
                raise KeyError(parent)
            if upstream["source_id"] != source_id:
                raise ValueError("转授许可必须针对同一数据来源")
            if grantor is not None and grantor != upstream["recipient"]:
                raise ValueError("转授方必须是上游许可的接收方")
            grantor = upstream["recipient"]
            if not upstream["delegable"]:
                raise ValueError("上游许可不允许再转授")
            if upstream["status"] != "active":
                raise ValueError("上游许可已撤销")
            if valid_until > upstream["valid_until"]:
                raise ValueError("有效期超出上游许可范围")
            if not self.purpose_covers(upstream["purpose"], purpose):
                raise ValueError("用途超出上游许可范围")
        with self.connection:
            self.connection.execute(
                "INSERT INTO grants(id,source_id,grantor,recipient,purpose,valid_until,parent_id,delegable) VALUES(?,?,?,?,?,?,?,?)",
                (grant_id, source_id, grantor, recipient, purpose, valid_until, parent, int(delegable)),
            )
            write(
                self.connection, at, grantor, "grant.issue", grant_id,
                {"source": source_id, "recipient": recipient, "parent": parent, "delegable": bool(delegable)},
            )

    def revoke(self, grant_id, at, actor):
        row = self.connection.execute("SELECT status FROM grants WHERE id=?", (grant_id,)).fetchone()
        if row is None:
            raise KeyError(grant_id)
        if row["status"] != "active":
            raise ValueError("许可已撤销")
        descendants = [r["id"] for r in self.connection.execute(
            "WITH RECURSIVE sub(id) AS ("
            "SELECT id FROM grants WHERE parent_id=? "
            "UNION SELECT g.id FROM grants g JOIN sub s ON g.parent_id=s.id"
            ") SELECT id FROM sub ORDER BY id",
            (grant_id,),
        )]
        broken = {grant_id, *descendants}
        deliveries = sorted(
            d["id"]
            for d in self.connection.execute("SELECT id,chain FROM deliveries")
            if broken & {link["grant"] for candidate in json.loads(d["chain"]).values() for link in candidate["grants"]}
        )
        with self.connection:
            self.connection.execute("UPDATE grants SET status='revoked' WHERE id=?", (grant_id,))
            write(self.connection, at, actor, "grant.revoke", grant_id, {"descendants": descendants, "deliveries": deliveries})
        return {"revoked": grant_id, "descendants": descendants, "deliveries": deliveries}

    def trace(self, source_id, recipient, purpose, at):
        source = self.connection.execute("SELECT owner FROM sources WHERE id=?", (source_id,)).fetchone()
        owner = source["owner"] if source else None
        candidates = [
            self._trace_chain(row, owner, purpose, at)
            for row in self.connection.execute(
                "SELECT * FROM grants WHERE source_id=? AND recipient=? ORDER BY id", (source_id, recipient)
            )
        ]
        allowed = next((c for c in candidates if c["ok"]), None)
        return {"allowed": allowed, "candidates": candidates}

    def _trace_chain(self, final, owner, purpose, at):
        rows, seen, row = [], set(), final
        while row is not None and row["id"] not in seen and len(rows) < MAX_CHAIN_DEPTH:
            rows.append(row)
            seen.add(row["id"])
            row = (
                self.connection.execute("SELECT * FROM grants WHERE id=?", (row["parent_id"],)).fetchone()
                if row["parent_id"]
                else None
            )
        rows.reverse()
        links = []
        for index, r in enumerate(rows):
            is_final = index == len(rows) - 1
            if r["parent_id"] is None:
                expected_grantor = owner
            elif index > 0:
                expected_grantor = rows[index - 1]["recipient"]
            else:
                expected_grantor = None
            checks = {
                "status": r["status"],
                "valid": r["valid_until"] >= at,
                "purpose_covers": self.purpose_covers(r["purpose"], purpose),
                "grantor_matches": expected_grantor is not None and r["grantor"] == expected_grantor,
                "delegation_allowed": True if is_final else bool(r["delegable"]),
            }
            reason = None
            if checks["status"] != "active":
                reason = "许可已撤销"
            elif not checks["valid"]:
                reason = "许可已过有效期"
            elif not checks["grantor_matches"]:
                reason = "授予方与授权链不符"
            elif not checks["purpose_covers"]:
                reason = "用途超出该环许可范围"
            elif not checks["delegation_allowed"]:
                reason = "该环许可不允许再转授"
            links.append({
                "grant": r["id"],
                "grantor": r["grantor"],
                "recipient": r["recipient"],
                "purpose": r["purpose"],
                "valid_until": r["valid_until"],
                "parent": r["parent_id"],
                "delegable": bool(r["delegable"]),
                "checks": checks,
                "ok": reason is None,
                "reason": reason,
            })
        broken = next((link["grant"] for link in links if not link["ok"]), None)
        return {"grants": links, "ok": broken is None, "broken": broken}
