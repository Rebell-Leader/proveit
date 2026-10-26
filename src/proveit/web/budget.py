"""Spending guard for live mode: the public demo must stay up until judging ends without draining credits.

Admission reserves a worst-case cost before any work starts, so concurrent requests cannot all slip under the cap.
Each run is settled when its worker finishes (not when the browser disconnects): the actual cost on success, the
full reservation on failure, because a failed run may already have paid for some calls.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import threading

from proveit import CACHE_DIR

STATE = CACHE_DIR / "live_budget.json"
RESERVE = float(os.environ.get("PROVEIT_RUN_RESERVE", "0.10"))  # worst case: Ultra with long reasoning plus one retry
MAX_TRACKED_IPS = 5000


class Budget:
    def __init__(self) -> None:
        self.daily_dollars = float(os.environ.get("PROVEIT_DAILY_BUDGET", "1.00"))
        self.per_ip = int(os.environ.get("PROVEIT_RUNS_PER_IP", "5"))
        self.max_concurrent = int(os.environ.get("PROVEIT_MAX_CONCURRENT", "2"))
        self._lock = threading.Lock()
        self._running = 0
        self._reserved = 0.0

    def _load(self) -> dict:
        today = dt.date.today().isoformat()
        try:
            state = json.loads(STATE.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            state = {}
        if state.get("day") != today:
            state = {"day": today, "dollars": 0.0, "ips": {}}
        return state

    def _save(self, state: dict) -> None:
        if len(state["ips"]) > MAX_TRACKED_IPS:
            state["ips"] = dict(sorted(state["ips"].items(), key=lambda kv: -kv[1])[:MAX_TRACKED_IPS])
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(json.dumps(state))

    def admit(self, ip: str) -> str | None:
        """Reserve a run. None if admitted (the caller must later call settle), else the reason it was refused."""
        with self._lock:
            state = self._load()
            if self._running >= self.max_concurrent:
                return "Two live runs are already in progress. Try again in a minute; judge mode works meanwhile."
            if state["dollars"] + self._reserved + RESERVE > self.daily_dollars:
                return "Today's live-run budget is used up. Every curl report in judge mode still works."
            if state["ips"].get(ip, 0) >= self.per_ip:
                return f"You have used your {self.per_ip} live runs for today. Judge mode still works."
            state["ips"][ip] = state["ips"].get(ip, 0) + 1
            self._save(state)
            self._running += 1
            self._reserved += RESERVE
            return None

    def settle(self, actual: float | None) -> None:
        """Release a reservation and charge the actual cost (or the whole reservation if the run failed)."""
        with self._lock:
            state = self._load()
            state["dollars"] = round(state["dollars"] + (RESERVE if actual is None else actual), 5)
            self._save(state)
            self._running = max(0, self._running - 1)
            self._reserved = max(0.0, self._reserved - RESERVE)

    def status(self) -> dict:
        with self._lock:
            state = self._load()
            return {"spent_today": state["dollars"] + self._reserved, "daily_budget": self.daily_dollars}
