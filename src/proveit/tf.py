"""Nebius Token Factory client. The API is OpenAI-compatible.

Notes from probing the live API (2026-10-26):
- `reasoning_effort` is accepted but has no effect on Nemotron; both models always reason.
- `chat_template_kwargs: {"enable_thinking": false}` turns reasoning off (Ultra: 147 -> 2 output tokens).
- Nano returns its reasoning in `message.reasoning`, Ultra in `message.reasoning_content`.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass
from functools import lru_cache
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

from proveit import CACHE_DIR, ROOT

load_dotenv(ROOT / ".env")

DEFAULT_BASE_URL = "https://api.tokenfactory.nebius.com/v1/"
LLM_CACHE = CACHE_DIR / "llm"

# USD per million tokens (input, output), from the Token Factory pricing page on 2026-10-25.
PRICES = {
    "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B": (0.06, 0.24),
    "nvidia/Nemotron-3_5-Lightning": (0.06, 0.24),
    "nvidia/nemotron-3-super-120b-a12b": (0.30, 0.90),
    "nvidia/Nemotron-3.5-Super-VL": (0.30, 0.90),
    "nvidia/Nemotron-3-Ultra-550b-a55b": (1.00, 3.00),
}


def model_fast() -> str:
    return os.environ.get("PROVEIT_MODEL_FAST", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B")


def model_deep() -> str:
    return os.environ.get("PROVEIT_MODEL_DEEP", "nvidia/Nemotron-3-Ultra-550b-a55b")


@lru_cache(maxsize=1)
def client() -> OpenAI:
    key = os.environ.get("NEBIUS_API_KEY")
    if not key:
        raise RuntimeError("NEBIUS_API_KEY is not set. Copy .env.example to .env and add your Token Factory key.")
    return OpenAI(base_url=os.environ.get("NEBIUS_BASE_URL", DEFAULT_BASE_URL), api_key=key, max_retries=5, timeout=900)


@dataclass
class Completion:
    model: str
    content: str
    data: Any | None
    prompt_tokens: int
    completion_tokens: int
    seconds: float
    reasoning: str = ""
    cached: bool = False
    finish_reason: str = ""
    attempts: int = 1

    @property
    def cost(self) -> float:
        p_in, p_out = PRICES.get(self.model, (0.0, 0.0))
        return (self.prompt_tokens * p_in + self.completion_tokens * p_out) / 1e6


class Spend:
    """Running total of tokens and dollars for API calls made in this process (cache hits cost nothing)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.calls = self.cached = 0
        self.dollars = 0.0
        self.by_model: dict[str, list[float]] = {}

    def add(self, c: Completion) -> None:
        with self._lock:
            if c.cached:
                self.cached += 1
                return
            self.calls += 1
            self.dollars += c.cost
            m = self.by_model.setdefault(c.model, [0, 0, 0.0])
            m[0] += c.prompt_tokens
            m[1] += c.completion_tokens
            m[2] += c.cost

    def __str__(self) -> str:
        parts = [f"{self.calls} calls ({self.cached} cached), ${self.dollars:.3f}"]
        parts += [f"  {k.split('/')[-1]}: {int(v[0])} in / {int(v[1])} out tokens, ${v[2]:.3f}" for k, v in self.by_model.items()]
        return "\n".join(parts)


SPEND = Spend()


def chat_json(
    messages: list[dict],
    schema: dict,
    *,
    model: str | None = None,
    thinking: bool = True,
    max_tokens: int = 4096,
    temperature: float = 0.0,
    use_cache: bool = True,
) -> Completion:
    """Chat completion constrained to a JSON schema. Returns the parsed object in `data`.

    Identical requests are answered from data/cache/llm/ so re-running an evaluation costs nothing.
    """
    model = model or model_fast()
    request = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "response_format": {"type": "json_schema", "json_schema": {"name": "result", "schema": schema, "strict": True}},
    }
    if not thinking:
        request["extra_body"] = {"chat_template_kwargs": {"enable_thinking": False}}
    key = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
    path = LLM_CACHE / f"{key[:2]}/{key}.json"
    if use_cache and path.exists():
        c = Completion(**json.loads(path.read_text()))
        c.cached = True
        SPEND.add(c)
        return c

    start = time.monotonic()
    prompt_tokens = completion_tokens = 0
    for attempt in range(1, 3):
        # A long reasoning run can hit max_tokens and leave no JSON; one retry usually succeeds. Both attempts are paid.
        resp = client().chat.completions.create(**request)
        msg = resp.choices[0].message
        extra = msg.model_extra or {}
        content = msg.content or ""
        if resp.usage:
            prompt_tokens += resp.usage.prompt_tokens
            completion_tokens += resp.usage.completion_tokens
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            data = None
        if data is not None:
            break
    c = Completion(
        model=model,
        content=content,
        data=data,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        seconds=time.monotonic() - start,
        reasoning=extra.get("reasoning") or extra.get("reasoning_content") or "",
        finish_reason=resp.choices[0].finish_reason or "",
        attempts=attempt,
    )
    if data is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(c)))
    SPEND.add(c)
    return c


def list_models() -> list[str]:
    return sorted(m.id for m in client().models.list().data)
