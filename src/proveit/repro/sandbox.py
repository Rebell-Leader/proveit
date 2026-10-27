"""Nebius Sandboxes (ConTree) over REST: isolated VMs that build curl and run a report's proof of concept.

REST rather than contree-sdk 0.3.6, because only the REST spawn request can start a VM without a guest network
interface, and report PoCs only ever run that way (AGENTS.md). Credentials: NEBIUS_API_KEY (the Token Factory key)
and NEBIUS_PROJECT_ID. They stay on this machine; nothing that runs in the guest sees them.
"""

from __future__ import annotations

import base64
import os
import time
from dataclasses import asdict, dataclass

import httpx

DEFAULT_BASE_URL = "https://api.tokenfactory.nebius.com/sandboxes/"
RUNNING = {"PENDING", "ASSIGNED", "EXECUTING"}


def configured() -> bool:
    return bool(os.environ.get("NEBIUS_API_KEY") and os.environ.get("NEBIUS_PROJECT_ID"))


@dataclass
class RunResult:
    operation: str
    image: str  # the image the run started from
    result_image: str | None  # saved filesystem, for runs that are not disposable
    status: str
    exit_code: int | None
    timed_out: bool
    signal: int | None
    stdout: str
    stderr: str
    truncated: bool
    seconds: float
    cost: float
    networking: bool

    @property
    def ok(self) -> bool:
        return self.status == "SUCCESS" and self.exit_code == 0 and not self.timed_out

    def to_dict(self) -> dict:
        return asdict(self)


def _decode(stream: dict | None) -> tuple[str, bool]:
    if not stream:
        return "", False
    value = stream.get("value") or ""
    if stream.get("encoding") == "base64":
        value = base64.b64decode(value).decode("utf-8", errors="replace")
    return value, bool(stream.get("truncated"))


class Sandboxes:
    def __init__(self, timeout: float = 30.0) -> None:
        if not configured():
            raise RuntimeError("Set NEBIUS_API_KEY and NEBIUS_PROJECT_ID in .env to use Nebius Sandboxes.")
        self.http = httpx.Client(
            base_url=os.environ.get("CONTREE_BASE_URL", DEFAULT_BASE_URL).rstrip("/") + "/",
            headers={"Authorization": f"Bearer {os.environ['NEBIUS_API_KEY']}", "Project": os.environ["NEBIUS_PROJECT_ID"]},
            timeout=timeout,
        )

    def _json(self, method: str, path: str, **kw) -> dict:
        resp = self.http.request(method, path, **kw)
        if resp.status_code >= 400:
            raise RuntimeError(f"Sandboxes {method} {path} -> {resp.status_code}: {resp.text[:300]}")
        return resp.json() if resp.content else {}

    def whoami(self) -> dict:
        return self._json("GET", "v1/whoami")

    def _wait(self, op_id: str, deadline: float) -> dict:
        delay = 1.0
        while True:
            op = self._json("GET", f"v1/operations/{op_id}")
            if op.get("status") not in RUNNING:
                return op
            if time.monotonic() > deadline:
                self.http.delete(f"v1/operations/{op_id}")
                raise TimeoutError(f"Sandboxes operation {op_id} did not finish in time; it was cancelled")
            time.sleep(delay)
            delay = min(delay * 1.5, 5.0)

    def run(self, image: str, command: str, *, networking: bool = False, disposable: bool = True, timeout: int = 120,
            truncate: int = 256 * 1024, env: dict[str, str] | None = None) -> RunResult:
        """Run a shell command in a fresh VM from `image`. Networking is off unless the caller turns it on, which
        only the curl build does (to fetch sources); a report's PoC never gets a network."""
        t0 = time.monotonic()
        body = {"image": image, "command": command, "shell": True, "networking": {"enabled": networking},
                "disposable": disposable, "timeout": timeout, "truncate_output_at": truncate}
        if env:
            body["env"] = env
        op_id = self._json("POST", "v1/instances", json=body)["uuid"]
        op = self._wait(op_id, t0 + timeout + 300)  # the VM's own limit applies first; this bounds queueing too
        meta = op.get("metadata") or {}
        res = meta.get("result") or {}
        state, resources = res.get("state") or {}, res.get("resources") or {}
        stdout, t_out = _decode(res.get("stdout"))
        stderr, t_err = _decode(res.get("stderr"))
        saved = (op.get("result") or {}).get("image") or op.get("result_image_uuid")
        return RunResult(operation=op_id, image=image, result_image=None if disposable else saved,
                         status=op.get("status", ""), exit_code=state.get("exit_code"),
                         timed_out=bool(state.get("timed_out")), signal=state.get("signal"),
                         stdout=stdout, stderr=stderr or (op.get("error") or ""), truncated=t_out or t_err,
                         seconds=round(time.monotonic() - t0, 1), cost=float(resources.get("cost") or 0.0),
                         networking=networking)

    def image_by_tag(self, tag: str) -> str | None:
        # The service answers a tag lookup with a redirect to the image's own path, "<uuid>/".
        resp = self.http.get("v1/inspect/", params={"tag": tag})
        if resp.status_code == 404:
            return None
        if resp.status_code not in (301, 302, 303, 307, 308):
            raise RuntimeError(f"Sandboxes image lookup {tag} -> {resp.status_code}: {resp.text[:300]}")
        return resp.headers["location"].strip("/").rsplit("/", 1)[-1]

    def tag(self, image: str, tag: str) -> None:
        self._json("PATCH", f"v1/images/{image}/tag", json={"tag": tag})
