"""
ai_assistant.py - answers free-text questions about the capture.

Important design rule (from the assignment): the PCAP file itself is NEVER
sent to the model. We send only the data that pcap_analyzer.py already
extracted (summary, HTTP transactions, streams, DNS, TLS SNI).

Every answer is then double-checked:
  1. verify_evidence() - every frame the AI cites must exist in the capture,
     and its timestamp must match the real frame time.
  2. local_answer()   - for the common question types (slowest request,
     status codes, requests per host, selected stream) we compute the answer
     directly in Python, so the user can compare it with the AI answer.
"""

from __future__ import annotations

import json
import re
import time
from collections import Counter

import anthropic
import httpx2  # HTTP library used by the google-genai SDK (for its timeout errors)
import openai
from google import genai
from google.genai import errors as genai_errors
from google.genai import types as genai_types

from pcap_analyzer import CaptureAnalysis, decode_body, fmt_time, transaction_row

# Supported AI providers: default model + the environment variable each SDK reads its key from.
# The model names can be changed in the dashboard sidebar.
PROVIDERS = {
    "Claude": {"default_model": "claude-opus-5-5", "env_var": "ANTHROPIC_API_KEY"},
    "OpenAI": {"default_model": "gpt-5", "env_var": "OPENAI_API_KEY"},
    "Google Gemini": {"default_model": "gemini-3.5-flash", "env_var": "GEMINI_API_KEY"},
}
TIMEOUT_S = 90                         # give up on a provider after this many seconds
MAX_TRANSACTIONS_IN_CONTEXT = 300      # keep the prompt a reasonable size
MAX_BODY_PREVIEW = 400                 # characters of request/response body per transaction

SYSTEM_PROMPT = """You are a network traffic analyst helping a student understand a Wireshark capture.
You receive JSON data that a Python parser ALREADY extracted from a PCAP file. You never see raw packets.

Rules:
- Answer ONLY from the provided JSON. If the data does not contain the answer, say so plainly and set confidence to "low".
- Frame numbers are Wireshark frame numbers (1-based). Cite them exactly as they appear in the data; never invent frames.
- "response_time_s" is the time between the request frame and the response frame (like Wireshark's http.time).
- When the question is about the slowest/fastest request, compare response_time_s across ALL transactions, not just the first ones.
- Every claim should be backed by evidence: the frame(s), their timestamps (copy the "time" value given in the data) and the field you used.
- If "truncated" is true, mention that only part of the transactions were provided.
- Write the answer in the same language as the question (Hebrew question -> Hebrew answer). Keep it short and concrete."""

ANSWER_SCHEMA = {
    "type": "object",
    "properties": {
        "answer": {"type": "string"},
        "evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "frame": {"type": "integer"},
                    "timestamp": {"type": "string"},
                    "field": {"type": "string"},
                    "explanation": {"type": "string"},
                },
                "required": ["frame", "timestamp", "field", "explanation"],
                "additionalProperties": False,
            },
        },
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "uncertainty_note": {"type": "string"},
    },
    "required": ["answer", "evidence", "confidence", "uncertainty_note"],
    "additionalProperties": False,
}


# --------------------------------------------------------------------------
# Context building
# --------------------------------------------------------------------------

def _preview(data: bytes) -> str:
    """Short printable preview of an HTTP body."""
    text = data.decode("utf-8", "replace")
    return text[:MAX_BODY_PREVIEW] + ("…" if len(text) > MAX_BODY_PREVIEW else "")


def build_context(analysis: CaptureAnalysis, selected_stream: int | None = None) -> dict:
    """Collect the extracted data into one JSON-serialisable dict for the model."""
    start = analysis.start_time or 0.0
    protocols = Counter(p["protocol"] for p in analysis.packets)
    endpoints = Counter()
    for p in analysis.packets:
        if p["src"]:
            endpoints[p["src"]] += 1
        if p["dst"]:
            endpoints[p["dst"]] += 1

    transactions = []
    for tx in analysis.transactions[:MAX_TRANSACTIONS_IN_CONTEXT]:
        row = transaction_row(tx, start)
        row["request_time"] = fmt_time(tx.request.last_time)
        row["response_time"] = fmt_time(tx.response.last_time) if tx.response else None
        if tx.request.body:
            row["request_body"] = _preview(tx.request.body)
        if tx.response and tx.response.body:
            row["response_body_preview"] = _preview(decode_body(tx.response))
        transactions.append(row)

    streams = []
    for s in analysis.streams.values():
        streams.append({
            "stream": s.stream_id,
            "client": f"{s.client[0]}:{s.client[1]}",
            "server": f"{s.server[0]}:{s.server[1]}",
            "packets": len(s.frames),
            "bytes": s.total_bytes,
            "first_frame": s.frames[0],
            "last_frame": s.frames[-1],
            "duration_s": round(s.end_time - s.start_time, 6),
            "http_transactions": [tx.tx_id for tx in analysis.transactions if tx.stream_id == s.stream_id],
        })

    context = {
        "file": analysis.file_name,
        "summary": {
            "packets": analysis.packet_count,
            "start_time": fmt_time(analysis.start_time),
            "end_time": fmt_time(analysis.end_time),
            "duration_s": round(analysis.duration, 6),
            "protocols": dict(protocols.most_common()),
            "top_endpoints": dict(endpoints.most_common(10)),
        },
        "http_transactions": transactions,
        "truncated": len(analysis.transactions) > MAX_TRANSACTIONS_IN_CONTEXT,
        "tcp_streams": streams[:200],
        "dns": [{"frame": d["frame"], "time": fmt_time(d["time"]), "name": d["name"],
                 "response": d["is_response"], "answers": d["answers"]} for d in analysis.dns_queries[:200]],
        "tls_client_hellos": [{"frame": h["frame"], "time": fmt_time(h["time"]), "sni": h["sni"],
                               "server": h["server"], "stream": h["stream"]} for h in analysis.tls_hellos[:200]],
    }
    if selected_stream is not None:
        context["selected_stream"] = selected_stream
    return context


# --------------------------------------------------------------------------
# Talking to Claude
# --------------------------------------------------------------------------

def ask_ai(question: str, analysis: CaptureAnalysis, selected_stream: int | None = None,
           provider: str = "Claude", api_key: str | None = None, model: str | None = None) -> dict:
    """
    Send the question + extracted context to the chosen provider and return a dict:
    {answer, evidence[], confidence, uncertainty_note} or {error: "..."}.
    All providers get the same system prompt, context and answer schema.
    """
    context = build_context(analysis, selected_stream)
    stream_hint = (f"\nThe user currently selected TCP stream {selected_stream} in the dashboard; "
                   f"'the selected stream' means that one.") if selected_stream is not None else ""
    user_message = (f"Extracted capture data (JSON):\n```json\n{json.dumps(context, ensure_ascii=False)}\n```\n"
                    f"{stream_hint}\nQuestion: {question}")
    model = model or PROVIDERS[provider]["default_model"]

    started = time.monotonic()
    if provider == "OpenAI":
        result = _ask_openai(user_message, api_key, model)
    elif provider == "Google Gemini":
        result = _ask_gemini(user_message, api_key, model)
    else:
        result = _ask_claude(user_message, api_key, model)
    if "error" not in result:
        result["prompt_chars"] = len(user_message)
    result["provider"] = f"{provider} ({model})"
    result["seconds"] = round(time.monotonic() - started, 1)
    return result


def list_models(provider: str, api_key: str | None) -> tuple[list[str], str | None]:
    """
    Ask the provider which models this API key can use.
    Returns (model names, error message or None). Model names change over time,
    so this is more reliable than a hard-coded default.
    """
    try:
        if provider == "OpenAI":
            client = openai.OpenAI(api_key=api_key) if api_key else openai.OpenAI()
            names = [m.id for m in client.models.list()
                     if m.id.startswith(("gpt-", "o")) and not any(x in m.id for x in
                                                                   ("audio", "realtime", "tts", "transcribe", "image", "search"))]
        elif provider == "Google Gemini":
            client = genai.Client(api_key=api_key) if api_key else genai.Client()
            names = [m.name.removeprefix("models/") for m in client.models.list()
                     if "generateContent" in (m.supported_actions or [])
                     and m.name.startswith("models/gemini") and "image" not in m.name and "tts" not in m.name]
        else:
            client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
            names = [m.id for m in client.models.list()]
    except (anthropic.AuthenticationError, openai.AuthenticationError):
        return [], "The API key was rejected."
    except openai.APIStatusError as e:
        return [], f"API error {e.status_code}: {e.message}"
    except anthropic.APIError as e:
        return [], f"API error: {e}"
    except genai_errors.APIError as e:
        return [], f"API error {e.code}: {e.message}"
    except (TypeError, ValueError, openai.OpenAIError):
        # raised by the SDKs when no key was given and none is in the environment
        return [], "No API key - paste one first."
    return sorted(set(names), reverse=True), None   # newest version numbers first


def _parse_json_answer(text: str) -> dict:
    """All providers return the answer as JSON text matching ANSWER_SCHEMA."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {"error": "The model returned an unreadable answer.", "raw": text}


def _ask_claude(user_message: str, api_key: str | None, model: str) -> dict:
    # With api_key=None the SDK reads ANTHROPIC_API_KEY from the environment.
    client = anthropic.Anthropic(api_key=api_key, timeout=TIMEOUT_S, max_retries=1) if api_key \
        else anthropic.Anthropic(timeout=TIMEOUT_S, max_retries=1)
    try:
        response = client.beta.messages.create(
            model=model,
            max_tokens=16000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_message}],
            # "low" effort = less thinking = a much faster answer; enough for questions over a small table
            output_config={"effort": "low",
                           "format": {"type": "json_schema", "schema": ANSWER_SCHEMA}},
            # If the model declines a request, let the API retry it on a fallback model.
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
    except anthropic.AuthenticationError:
        return {"error": "Invalid API key (set ANTHROPIC_API_KEY or paste it in the sidebar)."}
    except TypeError:
        # the SDK raises TypeError when no credentials were found at all
        return {"error": "No API key found - set ANTHROPIC_API_KEY or paste a key in the sidebar."}
    except anthropic.RateLimitError:
        return {"error": "Rate limit reached - wait a few seconds and try again."}
    except anthropic.APITimeoutError:
        return {"error": f"Claude did not answer within {TIMEOUT_S} seconds - try again."}
    except anthropic.APIStatusError as e:
        return {"error": f"API error {e.status_code}: {e.message}"}
    except anthropic.APIConnectionError:
        return {"error": "Could not reach the Anthropic API (check the internet connection)."}

    if response.stop_reason == "refusal":
        return {"error": "The model declined to answer this question."}
    text = next((b.text for b in response.content if b.type == "text"), "")
    return _parse_json_answer(text)


def _ask_openai(user_message: str, api_key: str | None, model: str) -> dict:
    try:
        # With api_key=None the SDK reads OPENAI_API_KEY; it raises OpenAIError if there is none.
        client = openai.OpenAI(api_key=api_key, timeout=TIMEOUT_S, max_retries=1) if api_key \
            else openai.OpenAI(timeout=TIMEOUT_S, max_retries=1)
        extra = {"reasoning_effort": "low"} if model.startswith(("gpt-5", "o")) else {}  # less thinking = faster
        response = client.chat.completions.create(
            model=model,
            **extra,
            messages=[{"role": "system", "content": SYSTEM_PROMPT},
                      {"role": "user", "content": user_message}],
            # Structured output: the reply must match ANSWER_SCHEMA exactly.
            response_format={"type": "json_schema",
                             "json_schema": {"name": "pcap_answer", "schema": ANSWER_SCHEMA, "strict": True}},
        )
    except openai.AuthenticationError:
        return {"error": "Invalid OpenAI API key."}
    except openai.RateLimitError:
        return {"error": "OpenAI rate limit / quota reached - check your billing or wait and retry."}
    except openai.NotFoundError:
        return {"error": f"OpenAI model '{model}' was not found - click 'Load available models' in the "
                         f"sidebar and pick another one."}
    except openai.APIStatusError as e:
        return {"error": f"OpenAI API error {e.status_code}: {e.message}"}
    except openai.APITimeoutError:
        return {"error": f"OpenAI did not answer within {TIMEOUT_S} seconds - try again."}
    except openai.APIConnectionError:
        return {"error": "Could not reach the OpenAI API (check the internet connection)."}
    except openai.OpenAIError:
        return {"error": "No OpenAI API key found - set OPENAI_API_KEY or paste a key in the sidebar."}

    message = response.choices[0].message
    if getattr(message, "refusal", None):
        return {"error": f"The model declined to answer: {message.refusal}"}
    return _parse_json_answer(message.content)


def _ask_gemini(user_message: str, api_key: str | None, model: str, retried: bool = False) -> dict:
    try:
        # With api_key=None the SDK reads GEMINI_API_KEY (or GOOGLE_API_KEY); ValueError if there is none.
        http_options = genai_types.HttpOptions(timeout=TIMEOUT_S * 1000)   # milliseconds
        client = genai.Client(api_key=api_key, http_options=http_options) if api_key \
            else genai.Client(http_options=http_options)
        response = client.models.generate_content(
            model=model,
            contents=user_message,
            config=genai_types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                # less thinking = a much faster answer (Gemini 3 thinks a lot by default)
                thinking_config=genai_types.ThinkingConfig(thinking_level="low"),
                # Structured output: JSON that matches ANSWER_SCHEMA.
                response_mime_type="application/json",
                response_json_schema=ANSWER_SCHEMA,
            ),
        )
    except ValueError:
        return {"error": "No Google API key found - set GEMINI_API_KEY or paste a key in the sidebar."}
    except genai_errors.ClientError as e:   # 4xx: bad key, unknown model, quota
        if e.code == 404:
            # Google's 404 for a retired model names its replacement ("...use models/<name> for...").
            # Retry once with that model instead of failing.
            suggested = re.search(r"use models/([\w.\-]+)", str(e.message))
            if suggested and not retried:
                result = _ask_gemini(user_message, api_key, suggested.group(1), retried=True)
                result["model_note"] = f"'{model}' is retired - answered with '{suggested.group(1)}' instead."
                return result
            return {"error": f"Gemini model '{model}' was not found - click 'Load available models' in the "
                             f"sidebar and pick another one. (server said: {e.message})"}
        if e.code == 429:
            return {"error": "Gemini rate limit / quota reached - wait and retry."}
        if "api key" in str(e.message).lower():
            return {"error": "Invalid Google API key."}
        return {"error": f"Gemini API error {e.code}: {e.message}"}
    except genai_errors.APIError as e:      # 5xx and other API failures
        if e.code in (503, 504):            # Google's servers are overloaded for this model
            return {"error": f"Gemini model '{model}' is overloaded right now (error {e.code}). "
                             f"Pick another model in the sidebar (gemini-3.5-flash is usually fast) or try again later."}
        return {"error": f"Gemini API error {e.code}: {e.message}"}
    except httpx2.TimeoutException:
        return {"error": f"Gemini did not answer within {TIMEOUT_S} seconds - try again."}
    except httpx2.HTTPError:
        return {"error": "Could not reach the Gemini API (check the internet connection)."}

    if not response.text:
        return {"error": "Gemini returned an empty answer (it may have blocked the request)."}
    return _parse_json_answer(response.text)


# --------------------------------------------------------------------------
# Verification of the AI answer
# --------------------------------------------------------------------------

def verify_evidence(evidence: list[dict], analysis: CaptureAnalysis) -> list[dict]:
    """
    Check each cited frame against the real capture.
    Adds 'status' = ok / time-mismatch / missing-frame and the real values.
    """
    checked = []
    for ev in evidence:
        item = dict(ev)
        frame = analysis.frame(int(ev.get("frame", 0)))
        if frame is None:
            item["status"] = "missing-frame"
            item["real_time"] = "-"
            item["real_info"] = "frame does not exist in this capture"
        else:
            real = fmt_time(frame["time"])
            item["real_time"] = real
            item["real_info"] = f'{frame["protocol"]}: {frame["info"]}'
            # accept the full time, only the clock part ("11:53:22.670"), or seconds since start
            cited = str(ev.get("timestamp", "")).strip()
            text_match = len(cited) >= 8 and real.endswith(cited)
            item["status"] = "ok" if text_match or _same_time(cited, frame["time"], analysis) else "time-mismatch"
        checked.append(item)
    return checked


def _same_time(cited: str, real_epoch: float, analysis: CaptureAnalysis) -> bool:
    """Accept a relative time (seconds since capture start) as well."""
    try:
        value = float(re.sub(r"[^\d.]", "", cited))
    except ValueError:
        return False
    return abs(value - (real_epoch - (analysis.start_time or 0))) < 0.002


# --------------------------------------------------------------------------
# Deterministic answers (ground truth for comparing with the AI)
# --------------------------------------------------------------------------

def local_answer(question: str, analysis: CaptureAnalysis, selected_stream: int | None = None) -> dict | None:
    """
    Compute the answer in plain Python for the question types the assignment
    lists. Returns None if the question is not one of those types.
    """
    q = question.lower()
    txs = analysis.transactions

    if any(w in q for w in ("slow", "איטי", "longest", "הכי ארוך")):
        answered = [t for t in txs if t.response]
        if not answered:
            return {"answer": "No HTTP transaction with a response was found.", "frames": []}
        t = max(answered, key=lambda x: x.response_time)
        return {"answer": f"Slowest: tx {t.tx_id} {t.request.method} {t.request.headers.get('host', '')}{t.request.uri} "
                          f"- {t.response_time * 1000:.1f} ms (status {t.response.status_code})",
                "frames": [t.request.last_frame, t.response.last_frame]}

    if any(w in q for w in ("status", "סטטוס", "קוד")):
        codes = Counter(t.response.status_code for t in txs if t.response)
        frames = [t.response.last_frame for t in txs if t.response]
        text = ", ".join(f"{code} ×{n}" for code, n in sorted(codes.items())) or "no responses"
        return {"answer": f"Status codes returned: {text}", "frames": frames}

    hosts = {t.request.headers.get("host", "").lower() for t in txs}
    host_in_q = next((h for h in sorted(hosts, key=len, reverse=True) if h and h in q), None)
    if host_in_q and any(w in q for w in ("how many", "כמה", "count", "number")):
        matching = [t for t in txs if t.request.headers.get("host", "").lower() == host_in_q]
        return {"answer": f"{len(matching)} HTTP requests were sent to {host_in_q}",
                "frames": [t.request.last_frame for t in matching]}

    if any(w in q for w in ("stream", "סטרים", "זרם")) and selected_stream in analysis.streams:
        s = analysis.streams[selected_stream]
        in_stream = [t for t in txs if t.stream_id == selected_stream]
        lines = [f"Stream {s.stream_id}: {s.client[0]}:{s.client[1]} ↔ {s.server[0]}:{s.server[1]}, "
                 f"{len(s.frames)} packets, {s.total_bytes} bytes, frames {s.frames[0]}-{s.frames[-1]}, "
                 f"{s.end_time - s.start_time:.3f}s"]
        for t in in_stream:
            status = t.response.status_code if t.response else "no response"
            lines.append(f"  tx {t.tx_id}: {t.request.method} {t.request.uri} → {status} "
                         f"(frames {t.request.last_frame}→{t.response.last_frame if t.response else '-'})")
        if not in_stream:
            lines.append("  no HTTP in this stream (probably TLS/encrypted or other TCP)")
        return {"answer": "\n".join(lines), "frames": [s.frames[0], s.frames[-1]]}

    if any(w in q for w in ("how many request", "כמה בקשות")):
        return {"answer": f"{len(txs)} HTTP requests in total",
                "frames": [t.request.last_frame for t in txs]}
    return None
