"""A small Groq client for Doppel's text-LLM uses (P10 Case-File Writer; P17's analyst agent reuses it).

- Keys from ``.env`` (``GROQ_API_KEY``); never logged.
- Temperature 0, JSON mode by default; a **model chain** with fast failover (an overloaded or retired model
  skips to the next one), chosen by measurement on 2026-11-06 (``docs/eval/p10-casefile.md``):
  ``openai/gpt-oss-120b`` first (keeps domain names verbatim in Hindi; ``gpt-oss-20b`` transliterated one into
  Devanagari in the probe), then ``qwen/qwen3.8-27b``, then ``openai/gpt-oss-20b``. ``DOPPEL_TEXT_MODEL`` forces one.
- Every answer is cached in ``runs/casefile/llm_cache/`` by (model, messages, options), so a demo replays
  without the network. ``DOPPEL_OFFLINE=1`` = cache only, never call.
- The LLM only ever *words* things; callers validate what comes back (see ``writer.py``).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field

from doppel.contract import REPO_ROOT

DEFAULT_MODELS = ["openai/gpt-oss-120b", "qwen/qwen3.8-27b", "openai/gpt-oss-20b"]
CACHE = REPO_ROOT / "runs" / "casefile" / "llm_cache"
TIMEOUT_S = 30
KEY_NAMES = ("GROQ_API_KEY_1", "GROQ_API_KEY_2", "GROQ_API_KEY")
KEY_ERRORS = ("429", "RateLimit", "401", "403", "PermissionDenied", "Authentication", "API_KEY", "quota", "Invalid API Key")
MAX_WAIT_S = 30           # free-tier rate limits: wait at most this long once, when the server says so


class LLMUnavailable(RuntimeError):
    """No answer: offline with nothing cached, no key, or every model in the chain failed."""


@dataclass
class Answer:
    text: str
    model: str
    method: str                      # groq | cache
    ms: float
    tokens: int | None = None
    errors: list[str] = field(default_factory=list)

    def json(self) -> dict:
        return json.loads(self.text)


def _env() -> dict:
    vals = dict(os.environ)
    try:
        from dotenv import dotenv_values

        vals = {**{k: v for k, v in dotenv_values(REPO_ROOT / ".env").items() if v}, **vals}
    except ImportError:
        pass
    return vals


def offline() -> bool:
    from doppel import net

    return _env().get("DOPPEL_OFFLINE", "") not in ("", "0", "false") or net.down()


def models() -> list[str]:
    forced = _env().get("DOPPEL_TEXT_MODEL")
    return [forced] if forced else list(DEFAULT_MODELS)


def _key(model: str, messages: list[dict], opts: dict) -> str:
    blob = json.dumps({"m": model, "msg": messages, "o": opts}, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def cached(model: str, messages: list[dict], opts: dict) -> Answer | None:
    p = CACHE / f"{_key(model, messages, opts)}.json"
    if not p.exists():
        return None
    rec = json.loads(p.read_text(encoding="utf-8"))
    return Answer(rec["text"], rec["model"], "cache", 0.0, rec.get("tokens"))


def chat(messages: list[dict], *, json_mode: bool = True, temperature: float = 0.0, max_tokens: int = 2000,
         tools: list[dict] | None = None) -> Answer:
    """One completion through the model chain. Raises ``LLMUnavailable`` if nothing answers."""
    opts = {"json": json_mode, "t": temperature, "max": max_tokens, "tools": tools}
    for m in models():                                   # a recorded answer from any model in the chain wins
        hit = cached(m, messages, opts)
        if hit is not None:
            return hit
    env = _env()
    if offline():
        raise LLMUnavailable("offline (DOPPEL_OFFLINE=1) and no recorded answer")
    keys = list(dict.fromkeys(env[k] for k in KEY_NAMES if env.get(k)))
    if not keys:
        raise LLMUnavailable("no Groq key (GROQ_API_KEY_1 / _2 in .env)")
    try:
        from groq import Groq
    except ImportError as exc:                           # the `llm` extra isn't installed
        raise LLMUnavailable("groq package missing (pip install -e .[llm])") from exc
    clients = [Groq(api_key=k, timeout=TIMEOUT_S, max_retries=0) for k in keys]
    errors: list[str] = []
    for attempt in range(2):
        ans = _try_models(clients, messages, opts, json_mode, temperature, max_tokens, tools, errors)
        if ans is not None:
            return ans
        waits = [float(w) for w in re.findall(r"retry in ([0-9.]+)s", " ".join(errors))]
        if attempt == 0 and waits and all("429" in e or "RateLimit" in e for e in errors) and min(waits) <= MAX_WAIT_S:
            time.sleep(min(waits) + 0.5)                 # every model rate-limited: wait once, as the server asks
            continue
        break
    raise LLMUnavailable("; ".join(errors) or "no model answered")


def _call_keys(clients, m, kw, errors):
    """One model with key 1, then key 2: only a rate-limit or key error moves on to the next key."""
    for n, client in enumerate(clients, 1):
        t0 = time.perf_counter()
        try:
            return client.chat.completions.create(model=m, **kw), t0
        except Exception as exc:                          # noqa: BLE001 - next key, or next model
            hint = re.search(r"try again in (?:(\d+)m)?([\d.]+)s", str(exc))
            wait = f" (retry in {int(hint.group(1) or 0) * 60 + float(hint.group(2)):.1f}s)" if hint else ""
            errors.append(f"{m} key{n}: {type(exc).__name__}: {str(exc)[:120]}{wait}")
            from doppel import net

            if net.is_network_error(exc):                  # no internet: no other key or model will answer
                net.mark_down(f"narration: {type(exc).__name__}")
                raise LLMUnavailable("; ".join(errors)) from exc
            if not any(k in str(exc) or k in type(exc).__name__ for k in KEY_ERRORS):
                return None                                # a model problem: another key won't help
    return None


def _try_models(clients, messages, opts, json_mode, temperature, max_tokens, tools, errors) -> Answer | None:
    kw = {"messages": messages, "temperature": temperature, "max_completion_tokens": max_tokens}
    if json_mode:
        kw["response_format"] = {"type": "json_object"}
    if tools:
        kw["tools"] = tools
    for m in models():
        got = _call_keys(clients, m, kw, errors)
        if got is None:
            continue
        r, t0 = got
        msg = r.choices[0].message
        text = msg.content or ""
        if tools and getattr(msg, "tool_calls", None):
            text = json.dumps({"tool_calls": [{"id": c.id, "name": c.function.name, "arguments": c.function.arguments}
                                              for c in msg.tool_calls], "content": msg.content})
        ans = Answer(text, m, "groq", round((time.perf_counter() - t0) * 1000, 1),
                     getattr(r.usage, "total_tokens", None), errors)
        CACHE.mkdir(parents=True, exist_ok=True)
        (CACHE / f"{_key(m, messages, opts)}.json").write_text(
            json.dumps({"model": m, "text": text, "tokens": ans.tokens, "at": time.strftime("%Y-%m-%dT%H:%M:%S")},
                       ensure_ascii=False), encoding="utf-8")
        return ans
    return None
