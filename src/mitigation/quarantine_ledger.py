"""
Persistent record of every mitigation action taken, so isolation decisions
are auditable after the fact rather than living only in ephemeral process
memory. Uses a flat JSON file instead of a database since the write volume
here is low (one entry per mitigation event, not per packet) and it keeps
the whole project dependency-light for a lab/demo environment.
"""

import json
import logging
import os
import time

logger = logging.getLogger(__name__)


class QuarantineLedger:
    def __init__(self, ledger_path: str = "logs/quarantine_ledger.json"):
        self.ledger_path = ledger_path
        os.makedirs(os.path.dirname(ledger_path), exist_ok=True)
        self._entries = self._load()

    def _load(self) -> dict:
        if not os.path.exists(self.ledger_path):
            return {}

        try:
            with open(self.ledger_path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("could not read existing ledger at %s (%s), starting fresh", self.ledger_path, exc)
            return {}

    def _persist(self):
        try:
            # write to a temp file first so a crash mid-write doesn't
            # corrupt the ledger we already had on disk
            tmp_path = f"{self.ledger_path}.tmp"
            with open(tmp_path, "w") as f:
                json.dump(self._entries, f, indent=2)
            os.replace(tmp_path, self.ledger_path)
        except OSError as exc:
            logger.error("failed to persist quarantine ledger: %s", exc)

    def add_entry(self, ip_address: str, client_id: str, anomaly_score: float, features: dict):
        self._entries[ip_address] = {
            "client_id": client_id,
            "anomaly_score": round(float(anomaly_score), 6),
            "quarantined_at": time.time(),
            "features": features,
            "active": True,
        }
        self._persist()
        logger.info("quarantine ledger updated for %s (client_id=%s, score=%.4f)",
                    ip_address, client_id, anomaly_score)

    def release_entry(self, ip_address: str):
        if ip_address in self._entries:
            self._entries[ip_address]["active"] = False
            self._entries[ip_address]["released_at"] = time.time()
            self._persist()
            logger.info("released quarantine entry for %s", ip_address)
        else:
            logger.warning("attempted to release %s but no ledger entry exists", ip_address)

    def is_quarantined(self, ip_address: str) -> bool:
        entry = self._entries.get(ip_address)
        return bool(entry and entry.get("active"))

    def active_count(self) -> int:
        return sum(1 for e in self._entries.values() if e.get("active"))

    def expire_stale_entries(self, max_age_seconds: int) -> list:
        """Returns the list of IPs released due to expiry, so the caller can also unblock them at the firewall."""
        now = time.time()
        expired_ips = []

        for ip_address, entry in self._entries.items():
            if entry.get("active") and (now - entry["quarantined_at"]) > max_age_seconds:
                entry["active"] = False
                entry["released_at"] = now
                expired_ips.append(ip_address)

        if expired_ips:
            self._persist()
            logger.info("expired %d stale quarantine entries", len(expired_ips))

        return expired_ips
