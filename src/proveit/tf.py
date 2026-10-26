"""Nebius Token Factory client. The API is OpenAI-compatible."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

from proveit import ROOT

load_dotenv(ROOT / ".env")

DEFAULT_BASE_URL = "https://api.tokenfactory.nebius.com/v1/"


def model_fast() -> str:
    return os.environ.get("PROVEIT_MODEL_FAST", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B")


def model_deep() -> str:
    return os.environ.get("PROVEIT_MODEL_DEEP", "nvidia/Nemotron-3-Ultra-550b-a55b")


def client() -> OpenAI:
    key = os.environ.get("NEBIUS_API_KEY")
    if not key:
        raise RuntimeError("NEBIUS_API_KEY is not set. Copy .env.example to .env and add your Token Factory key.")
    return OpenAI(base_url=os.environ.get("NEBIUS_BASE_URL", DEFAULT_BASE_URL), api_key=key)


@dataclass
class Completion:
    model: str
    content: str
    data: Any | None
    prompt_tokens: int
    completion_tokens: int
    seconds: float


def chat_json(
    messages: list[dict],
    schema: dict,
    *,
    model: str | None = None,
    reasoning_effort: str | None = None,
    max_tokens: int = 2048,
    temperature: float = 0.0,
) -> Completion:
    """Chat completion constrained to a JSON schema. Returns the parsed object in `data`."""
    kwargs: dict[str, Any] = {}
    if reasoning_effort:
        kwargs["reasoning_effort"] = reasoning_effort
    start = time.monotonic()
    resp = client().chat.completions.create(
        model=model or model_fast(),
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        response_format={"type": "json_schema", "json_schema": {"name": "result", "schema": schema, "strict": True}},
        **kwargs,
    )
    seconds = time.monotonic() - start
    content = resp.choices[0].message.content or ""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        data = None
    usage = resp.usage
    return Completion(
        model=resp.model,
        content=content,
        data=data,
        prompt_tokens=usage.prompt_tokens if usage else 0,
        completion_tokens=usage.completion_tokens if usage else 0,
        seconds=seconds,
    )


def list_models() -> list[str]:
    return sorted(m.id for m in client().models.list().data)
