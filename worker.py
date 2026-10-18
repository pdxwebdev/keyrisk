import asyncio
import time
from datetime import datetime, timezone

import requests


class BaseRealmCrawler:
    def __init__(self, name, config, worker):
        self.name = name
        self.config = config or {}
        self.worker = worker

    async def run_cycle(self):
        raise NotImplementedError()


class BscRealmCrawler(BaseRealmCrawler):
    def __init__(self, name, config, worker):
        super().__init__(name, config, worker)
        self.api_base = self.config.get("api_base", "https://api.bscscan.com/api")
        self.api_key = self.config.get("api_key")
        self.start_block = int(self.config.get("start_block", 0))

    def _params(self, extra):
        params = dict(extra)
        if self.api_key:
            params["apikey"] = self.api_key
        return params

    def _get_json(self, params):
        response = requests.get(
            self.api_base,
            params=self._params(params),
            timeout=self.worker.http_timeout,
        )
        response.raise_for_status()
        return response.json()

    def _latest_block_number(self):
        payload = self._get_json({"module": "proxy", "action": "eth_blockNumber"})
        result = payload.get("result")
        if not result:
            raise RuntimeError(f"Invalid latest block response for realm={self.name}")
        return int(result, 16)

    def _block_transactions(self, block_number):
        tag = hex(block_number)
        payload = self._get_json(
            {
                "module": "proxy",
                "action": "eth_getBlockByNumber",
                "tag": tag,
                "boolean": "true",
            }
        )
        result = payload.get("result") or {}
        return result.get("transactions") or []

    def _address_summary(self, address):
        payload = self._get_json(
            {
                "module": "account",
                "action": "txlist",
                "address": address,
                "startblock": 0,
                "endblock": 99999999,
                "page": 1,
                "offset": self.worker.max_tx_scan,
                "sort": "asc",
            }
        )
        txs = payload.get("result") or []
        if not isinstance(txs, list):
            return None

        first_seen_ts = None
        if txs:
            try:
                first_seen_ts = int(txs[0].get("timeStamp", 0))
            except Exception:
                first_seen_ts = None

        return {
            "tx_count_estimate": len(txs),
            "first_seen_ts": first_seen_ts,
            "is_truncated": len(txs) >= self.worker.max_tx_scan,
            "source": "bscscan",
        }

    async def run_cycle(self):
        state = await self.worker.get_realm_state(self.name)
        last_block = state.get("last_scanned_block")
        if last_block is None:
            last_block = self.start_block

        latest_block = await asyncio.to_thread(self._latest_block_number)
        if latest_block <= last_block:
            return

        next_block = last_block + 1
        end_block = min(latest_block, next_block + self.worker.max_blocks_per_cycle - 1)

        address_set = set()
        for block_number in range(next_block, end_block + 1):
            txs = await asyncio.to_thread(self._block_transactions, block_number)
            for tx in txs:
                from_addr = (tx.get("from") or "").lower()
                to_addr = (tx.get("to") or "").lower()
                if from_addr.startswith("0x") and len(from_addr) == 42:
                    address_set.add(from_addr)
                if to_addr.startswith("0x") and len(to_addr) == 42:
                    address_set.add(to_addr)

        addresses = list(address_set)[: self.worker.max_addresses_per_cycle]
        sem = asyncio.Semaphore(self.worker.max_concurrency)

        async def analyze_address(address):
            async with sem:
                summary = await asyncio.to_thread(self._address_summary, address)
                if not summary:
                    return
                await self.worker.persist_profile(self.name, address, summary)
                await self.worker.persist_finding(self.name, address, summary)

        await asyncio.gather(*(analyze_address(a) for a in addresses), return_exceptions=True)

        await self.worker.update_realm_state(
            self.name,
            {
                "last_scanned_block": end_block,
                "latest_seen_block": latest_block,
                "updated_at": int(time.time()),
            },
        )


class KeyRiskWorker:
    def __init__(self, app):
        self.app = app
        self.config = app.config

        self.poll_interval_seconds = int(
            getattr(self.config, "key_risk_poll_interval_seconds", 45)
        )
        self.http_timeout = int(getattr(self.config, "key_risk_http_timeout", 10))
        self.max_tx_scan = int(getattr(self.config, "key_risk_max_tx_scan", 2000))
        self.max_blocks_per_cycle = int(
            getattr(self.config, "key_risk_max_blocks_per_cycle", 4)
        )
        self.max_addresses_per_cycle = int(
            getattr(self.config, "key_risk_max_addresses_per_cycle", 250)
        )
        self.max_concurrency = int(getattr(self.config, "key_risk_max_concurrency", 8))
        self.min_key_age_days = int(getattr(self.config, "key_risk_min_key_age_days", 30))
        self.high_tx_threshold = int(
            getattr(self.config, "key_risk_high_tx_threshold", 200)
        )

        self._running = False
        self._task = None
        self.realms = []

    def _now_ts(self):
        return int(time.time())

    def _to_iso(self, ts):
        if not ts:
            return None
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    def _build_realms(self):
        realm_configs = getattr(self.config, "key_risk_realms", None)
        if not realm_configs:
            realm_configs = [{"name": "bsc", "type": "bsc"}]

        crawlers = []
        for realm in realm_configs:
            realm_name = realm.get("name")
            realm_type = (realm.get("type") or "").lower()
            if not realm_name or not realm_type:
                continue
            if realm_type == "bsc":
                crawlers.append(BscRealmCrawler(realm_name, realm, self))
        return crawlers

    async def ensure_indexes(self):
        findings = self.config.mongo.async_site_db.key_risk_findings
        state = self.config.mongo.async_site_db.key_risk_realm_state
        profiles = self.config.mongo.async_site_db.key_risk_profiles

        await findings.create_index([("realm", 1), ("address", 1)], unique=True)
        await findings.create_index([("risk_score", -1), ("updated_at", -1)])
        await findings.create_index("updated_at")

        await state.create_index("realm", unique=True)
        await profiles.create_index([("realm", 1), ("address", 1)], unique=True)
        await profiles.create_index("updated_at")

    async def get_realm_state(self, realm):
        state = await self.config.mongo.async_site_db.key_risk_realm_state.find_one(
            {"realm": realm}, {"_id": 0}
        )
        return state or {}

    async def update_realm_state(self, realm, update_data):
        await self.config.mongo.async_site_db.key_risk_realm_state.update_one(
            {"realm": realm},
            {"$set": {"realm": realm, **update_data}},
            upsert=True,
        )

    def compute_risk(self, summary):
        first_seen_ts = summary.get("first_seen_ts")
        tx_count = int(summary.get("tx_count_estimate") or 0)

        age_days = None
        if first_seen_ts:
            age_days = (self._now_ts() - int(first_seen_ts)) / 86400

        risk_flags = []
        if age_days is not None and age_days >= self.min_key_age_days:
            risk_flags.append("old_key")
        if tx_count >= self.high_tx_threshold:
            risk_flags.append("high_transaction_volume")

        risk_score = min(100, len(risk_flags) * 50)
        return {
            "risk_score": risk_score,
            "risk_flags": risk_flags,
            "age_days": age_days,
        }

    async def persist_profile(self, realm, address, summary):
        now = self._now_ts()
        profile = {
            "realm": realm,
            "address": address.lower(),
            "first_seen_ts": summary.get("first_seen_ts"),
            "first_seen_at": self._to_iso(summary.get("first_seen_ts")),
            "tx_count_estimate": int(summary.get("tx_count_estimate") or 0),
            "is_truncated": bool(summary.get("is_truncated")),
            "source": summary.get("source") or "unknown",
            "updated_at": now,
        }
        await self.config.mongo.async_site_db.key_risk_profiles.update_one(
            {"realm": realm, "address": address.lower()},
            {"$set": profile},
            upsert=True,
        )

    async def persist_finding(self, realm, address, summary):
        now = self._now_ts()
        risk = self.compute_risk(summary)
        finding = {
            "realm": realm,
            "address": address.lower(),
            "risk_score": risk["risk_score"],
            "risk_flags": risk["risk_flags"],
            "age_days": risk["age_days"],
            "first_seen_ts": summary.get("first_seen_ts"),
            "tx_count_estimate": int(summary.get("tx_count_estimate") or 0),
            "updated_at": now,
            "updated_at_iso": self._to_iso(now),
        }
        await self.config.mongo.async_site_db.key_risk_findings.update_one(
            {"realm": realm, "address": address.lower()},
            {"$set": finding},
            upsert=True,
        )

    async def self_verify(self, realm, address):
        crawler = next((r for r in self.realms if r.name == realm), None)
        if not crawler:
            raise ValueError(f"Unknown realm: {realm}")
        summary = await asyncio.to_thread(crawler._address_summary, address.lower())
        if not summary:
            raise ValueError("Unable to fetch address summary")
        await self.persist_profile(realm, address, summary)
        await self.persist_finding(realm, address, summary)

        finding = await self.config.mongo.async_site_db.key_risk_findings.find_one(
            {"realm": realm, "address": address.lower()}, {"_id": 0}
        )
        return finding

    async def cycle(self):
        for realm in self.realms:
            try:
                await realm.run_cycle()
            except Exception as exc:
                self.config.app_log.warning(
                    "keyrisk cycle failed realm=%s error=%s", realm.name, exc
                )

    async def _run(self):
        self._running = True
        while self._running:
            await self.cycle()
            await asyncio.sleep(self.poll_interval_seconds)

    async def start(self):
        await self.ensure_indexes()
        self.realms = self._build_realms()
        if not self.realms:
            self.config.app_log.warning("keyrisk worker has no valid realms configured")
            return
        if self._task and not self._task.done():
            return
        self._task = asyncio.create_task(self._run())


async def bootstrap_keyrisk_worker(app):
    worker = KeyRiskWorker(app)
    app.keyrisk_worker = worker
    await worker.start()
