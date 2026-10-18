import os
import re
import json

from yadacoin.http.base import BaseHandler

ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


class BaseKeyRiskHandler(BaseHandler):
    def get_template_path(self):
        return os.path.join(os.path.dirname(__file__), "templates")


class KeyRiskHomeHandler(BaseKeyRiskHandler):
    async def get(self):
        realms = []
        worker = getattr(self.application, "keyrisk_worker", None)
        if worker:
            realms = [realm.name for realm in worker.realms]
        self.render(
            "key_risk.html",
            yadacoin=self.yadacoin_vars,
            realms=realms,
            title="YadaCoin - Key Risk Analyzer",
        )


class KeyRiskSelfVerifyHandler(BaseKeyRiskHandler):
    async def post(self):
        worker = getattr(self.application, "keyrisk_worker", None)
        if not worker:
            self.set_status(503)
            return self.render_as_json({"error": "keyrisk worker not ready"})

        try:
            data = json.loads(self.request.body.decode("utf-8")) if self.request.body else {}
        except Exception:
            self.set_status(400)
            return self.render_as_json({"error": "Invalid JSON body"})
        address = (data.get("address") or "").strip().lower()
        realm = (data.get("realm") or "bsc").strip()

        if not ADDRESS_RE.match(address):
            self.set_status(400)
            return self.render_as_json({"error": "Invalid EVM address"})

        try:
            finding = await worker.self_verify(realm, address)
        except Exception as exc:
            self.set_status(400)
            return self.render_as_json({"error": str(exc)})

        return self.render_as_json({"status": True, "result": finding})


class KeyRiskAddressHandler(BaseKeyRiskHandler):
    async def get(self, address):
        realm = self.get_query_argument("realm", "bsc")
        address = (address or "").strip().lower()
        if not ADDRESS_RE.match(address):
            self.set_status(400)
            return self.render_as_json({"error": "Invalid EVM address"})

        finding = await self.config.mongo.async_site_db.key_risk_findings.find_one(
            {"realm": realm, "address": address}, {"_id": 0}
        )
        profile = await self.config.mongo.async_site_db.key_risk_profiles.find_one(
            {"realm": realm, "address": address}, {"_id": 0}
        )

        if not finding and not profile:
            self.set_status(404)
            return self.render_as_json({"error": "No risk data found"})

        return self.render_as_json(
            {
                "realm": realm,
                "address": address,
                "finding": finding,
                "profile": profile,
            }
        )


class KeyRiskFindingsHandler(BaseKeyRiskHandler):
    async def get(self):
        realm = self.get_query_argument("realm", None)
        try:
            min_score = int(self.get_query_argument("min_score", 0))
            limit = min(int(self.get_query_argument("limit", 50)), 500)
        except ValueError:
            self.set_status(400)
            return self.render_as_json({"error": "min_score and limit must be integers"})

        query = {"risk_score": {"$gte": min_score}}
        if realm:
            query["realm"] = realm

        findings = (
            await self.config.mongo.async_site_db.key_risk_findings.find(
                query, {"_id": 0}
            )
            .sort([("risk_score", -1), ("updated_at", -1)])
            .to_list(length=limit)
        )

        return self.render_as_json(
            {
                "count": len(findings),
                "realm": realm,
                "min_score": min_score,
                "results": findings,
            }
        )


class KeyRiskRealmStateHandler(BaseKeyRiskHandler):
    async def get(self):
        states = (
            await self.config.mongo.async_site_db.key_risk_realm_state.find(
                {}, {"_id": 0}
            )
            .sort([("realm", 1)])
            .to_list(length=100)
        )
        return self.render_as_json({"realms": states})


HANDLERS = [
    (r"/key-risk", KeyRiskHomeHandler),
    (r"/key-risk/api/v1/self-verify", KeyRiskSelfVerifyHandler),
    (r"/key-risk/api/v1/address/(0x[a-fA-F0-9]{40})", KeyRiskAddressHandler),
    (r"/key-risk/api/v1/findings", KeyRiskFindingsHandler),
    (r"/key-risk/api/v1/realms", KeyRiskRealmStateHandler),
]
