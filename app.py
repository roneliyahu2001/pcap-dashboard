"""
app.py - PCAP Dashboard V1 (Streamlit).

Run:  streamlit run app.py

Tabs:
  Overview        - packet count, times, endpoints, protocols, charts      (sections 23-26)
  HTTP            - automatic request/response matching + details          (sections 27-29)
  Follow Stream   - the whole TCP conversation as text
  HTTP vs HTTPS   - what is still visible in encrypted traffic             (creative)
  Ask AI          - free-text questions with verified evidence             (sections 30-34)
  Packets         - interactive packet filter
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from collections import Counter
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pandas as pd
import plotly.express as px
import streamlit as st

from ai_assistant import PROVIDERS, ask_ai, list_models, local_answer, verify_evidence
from pcap_analyzer import analyze_pcap, decode_body, fmt_time, transaction_row

SAMPLES_DIR = Path(__file__).parent / "samples"
EXAMPLE_QUESTIONS = [
    "Which HTTP request was the slowest?",
    "Which status codes were returned?",
    "How many requests were sent to httpbin.org?",
    "What happened in the selected stream?",
    "What parameters were sent in the form submission (POST)?",
]

st.set_page_config(page_title="PCAP Dashboard V1", page_icon="📡", layout="wide")


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

@st.cache_resource(show_spinner="Parsing capture…")
def load_capture(data_hash: str, data: bytes, name: str):
    """Write the bytes to a temp file and analyse it (cached per file content)."""
    suffix = Path(name).suffix or ".pcap"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(data)
        path = tmp.name
    try:
        return analyze_pcap(path, file_name=name)
    finally:
        os.unlink(path)


def pick_file():
    """Sidebar: upload a capture or choose one from ./samples."""
    st.sidebar.header("1. Capture file")
    uploaded = st.sidebar.file_uploader("Choose a PCAP / PCAPNG file", type=["pcap", "pcapng", "cap"])
    if uploaded is not None:
        return uploaded.getvalue(), uploaded.name
    samples = sorted(p.name for p in SAMPLES_DIR.glob("*") if p.suffix in (".pcap", ".pcapng", ".cap"))
    if samples:
        choice = st.sidebar.selectbox("…or use a file from ./samples", ["—"] + samples)
        if choice != "—":
            return (SAMPLES_DIR / choice).read_bytes(), choice
    return None, None


data, name = pick_file()
st.sidebar.header("2. AI settings")
provider = st.sidebar.segmented_control("AI provider", list(PROVIDERS), default="Claude",
                                        required=True, key="provider")
provider_info = PROVIDERS[provider]
# one key / model field per provider, so switching providers keeps what was typed
api_key_input = st.sidebar.text_input(f"{provider} API key", type="password", key=f"key_{provider}",
                                      help=f"Optional if {provider_info['env_var']} is set in the environment. "
                                           "The key is only kept in memory for this session.")
st.sidebar.caption("No confirm button is needed - the key is used as soon as it is pasted.")

# The model list is fetched from the provider with the user's key (names change over time).
models_state = f"models_{provider}"
if st.sidebar.button("Load available models", icon=":material/refresh:", width="stretch"):
    with st.sidebar:
        with st.spinner("Fetching models…"):
            names, error = list_models(provider, api_key_input or None)
    if error:
        st.sidebar.error(error)
    elif not names:
        st.sidebar.warning("This key has no usable models.")
    else:
        st.session_state[models_state] = names
if st.session_state.get(models_state):
    names = st.session_state[models_state]
    default = provider_info["default_model"]
    # Prefer the default model; otherwise the newest "flash"/"mini" (fast, cheap) model; otherwise the first.
    preferred = next((n for n in names if n == default), None) or \
        next((n for n in names if ("flash" in n or "mini" in n) and "preview" not in n and "lite" not in n), names[0])
    model_input = st.sidebar.selectbox("Model", names, key=f"model_select_{provider}",
                                       index=names.index(preferred))
else:
    model_input = st.sidebar.text_input("Model", value=provider_info["default_model"], key=f"model_{provider}",
                                         help="If you get 'model not found', click 'Load available models'.")
st.sidebar.caption("Only the extracted data (not the PCAP file) is sent to the model.")

st.title("📡 PCAP Dashboard V1")
if data is None:
    st.info("Upload a PCAP / PCAPNG file in the sidebar to begin.")
    st.stop()

try:
    analysis = load_capture(hashlib.sha256(data).hexdigest(), data, name)
except Exception as exc:  # scapy raises different errors for corrupt/unsupported files
    st.error(f"Could not read this file as PCAP/PCAPNG: {exc}")
    st.stop()

if analysis.packet_count == 0:
    st.warning("The file contains no packets.")
    st.stop()

start = analysis.start_time
packets_df = pd.DataFrame(analysis.packets)
packets_df["rel_time"] = packets_df["time"] - start
tx_rows = [transaction_row(tx, start) for tx in analysis.transactions]
tx_df = pd.DataFrame(tx_rows)

tabs = st.tabs(["Overview", "HTTP", "Follow Stream", "HTTP vs HTTPS", "Ask AI", "Packets"])

# --------------------------------------------------------------------------
# Overview
# --------------------------------------------------------------------------
with tabs[0]:
    st.subheader(f"File: {analysis.file_name}")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Packets", analysis.packet_count)
    c2.metric("Start", fmt_time(analysis.start_time).split(" ")[1])
    c3.metric("End", fmt_time(analysis.end_time).split(" ")[1])
    c4.metric("Duration", f"{analysis.duration:.3f} s")
    st.caption(f"Start: {fmt_time(analysis.start_time)}  ·  End: {fmt_time(analysis.end_time)}  ·  "
               f"TCP streams: {len(analysis.streams)}  ·  HTTP transactions: {len(analysis.transactions)}")

    left, right = st.columns(2)
    with left:
        st.markdown("**Main endpoints** (packets sent + received)")
        ep = Counter()
        bytes_ep = Counter()
        for p in analysis.packets:
            for addr in (p["src"], p["dst"]):
                if addr:
                    ep[addr] += 1
                    bytes_ep[addr] += p["length"]
        ep_df = pd.DataFrame([{"address": a, "packets": n, "bytes": bytes_ep[a]} for a, n in ep.most_common(15)])
        st.dataframe(ep_df, hide_index=True, width="stretch")
    with right:
        st.markdown("**Protocol distribution**")
        proto_df = packets_df.groupby("protocol").agg(packets=("frame", "count"), bytes=("length", "sum")).reset_index()
        fig = px.pie(proto_df, names="protocol", values="packets", hole=0.45)
        fig.update_layout(height=320, margin=dict(t=10, b=10, l=10, r=10))
        st.plotly_chart(fig, width="stretch")

    st.markdown("**Traffic volume over time** (bytes per time bucket, by protocol)")
    bucket = max(analysis.duration / 60, 0.01)       # about 60 buckets across the capture
    packets_df["bucket"] = (packets_df["rel_time"] // bucket) * bucket
    vol = packets_df.groupby(["bucket", "protocol"])["length"].sum().reset_index()
    fig = px.bar(vol, x="bucket", y="length", color="protocol",
                 labels={"bucket": "seconds since start", "length": "bytes"})
    fig.update_layout(height=320, margin=dict(t=10, b=10), bargap=0)
    st.plotly_chart(fig, width="stretch")

# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
with tabs[1]:
    if tx_df.empty:
        st.info("No HTTP (cleartext) traffic was found. HTTPS traffic is encrypted - see the 'HTTP vs HTTPS' tab.")
    else:
        # --- automatic problem detection --------------------------------
        errors = tx_df[(tx_df["status"].fillna(0) >= 400)]
        missing = tx_df[tx_df["status"].isna()]
        if not errors.empty:
            st.warning(f"⚠️ {len(errors)} HTTP error response(s): " +
                       ", ".join(f"tx {r.tx} → {int(r.status)} {r.reason} ({r.uri})" for r in errors.itertuples()))
        if not missing.empty:
            st.warning(f"⚠️ {len(missing)} request(s) with no response in the capture: " +
                       ", ".join(f"tx {r.tx} (frame {r.request_frame})" for r in missing.itertuples()))

        st.markdown("**HTTP transactions** (request ↔ response, matched automatically per TCP stream)")
        show_cols = ["tx", "method", "host", "uri", "src", "dst", "status", "response_time_s",
                     "request_frame", "response_frame", "response_segments", "stream"]
        st.dataframe(tx_df[show_cols], hide_index=True, width="stretch",
                     column_config={"response_time_s": st.column_config.NumberColumn("response time (s)", format="%.4f")})

        timed = tx_df.dropna(subset=["response_time_s"])
        if not timed.empty:
            timed = timed.assign(label=timed["tx"].astype(str) + " " + timed["method"] + " " + timed["uri"].str[:40],
                                 status_class=timed["status"].astype(int).astype(str).str[0] + "xx")
            fig = px.bar(timed, x="label", y="response_time_s", color="status_class",
                         labels={"label": "transaction", "response_time_s": "response time (s)"},
                         color_discrete_map={"2xx": "#2e9e5b", "3xx": "#3b82c4", "4xx": "#e0a100", "5xx": "#d64545"})
            fig.update_layout(height=300, margin=dict(t=10, b=10))
            st.plotly_chart(fig, width="stretch")

        st.divider()
        options = {f"tx {r['tx']}: {r['method']} {r['host']}{r['uri']} → {r['status']}": r["tx"] for r in tx_rows}
        chosen = st.selectbox("Select a transaction to see its details", list(options))
        tx = analysis.transactions[options[chosen] - 1]
        req, resp = tx.request, tx.response

        a, b = st.columns(2)
        with a:
            st.markdown(f"#### Request — frame {req.last_frame}")
            st.write({"Method": req.method, "URI": req.uri, "HTTP version": req.version,
                      "Host": req.headers.get("host", ""), "Source": f"{tx.client_ip}:{tx.client_port}",
                      "Destination": f"{tx.server_ip}:{tx.server_port}", "Time": fmt_time(req.last_time),
                      "User-Agent": req.headers.get("user-agent", "")})
            # parameters: query string (GET) and urlencoded body (POST)
            params = parse_qsl(urlsplit(req.uri).query)
            if params:
                st.markdown("**Query-string parameters** (inside the URI)")
                st.table(pd.DataFrame(params, columns=["name", "value"]))
            if req.body:
                ctype = req.headers.get("content-type", "")
                if "application/x-www-form-urlencoded" in ctype:
                    st.markdown("**Form parameters** (in the request body)")
                    st.table(pd.DataFrame(parse_qsl(req.body.decode("utf-8", "replace")), columns=["name", "value"]))
                else:
                    st.code(req.body.decode("utf-8", "replace")[:3000])
            with st.expander("Raw request headers"):
                st.code(req.raw_headers)
        with b:
            if resp is None:
                st.markdown("#### Response")
                st.error("No response found in the capture for this request.")
            else:
                st.markdown(f"#### Response — frame {resp.last_frame}")
                st.write({"Status": f"{resp.status_code} {resp.reason}", "Server IP": tx.server_ip,
                          "Server header": resp.headers.get("server", "(not present)"),
                          "Content-Type": resp.headers.get("content-type", "(not present)"),
                          "Content-Length": resp.headers.get("content-length", "(not present)"),
                          "Response time": f"{tx.response_time * 1000:.2f} ms "
                                           f"(frame {req.last_frame} → {resp.last_frame})",
                          "TCP segments": f"{len(resp.frames)} → frames {resp.frames}"})
                with st.expander("Raw response headers"):
                    st.code(resp.raw_headers)
                body = decode_body(resp)
                if body:
                    with st.expander(f"Response body ({len(body)} bytes)"):
                        st.code(body.decode("utf-8", "replace")[:5000])

# --------------------------------------------------------------------------
# Follow stream
# --------------------------------------------------------------------------
with tabs[2]:
    stream_labels = {f"Stream {s.stream_id}: {s.client[0]}:{s.client[1]} ↔ {s.server[0]}:{s.server[1]} "
                     f"({len(s.frames)} pkts)": s.stream_id for s in analysis.streams.values()}
    if not stream_labels:
        st.info("No TCP streams in this capture.")
        selected_stream = None
    else:
        http_streams = sorted({tx.stream_id for tx in analysis.transactions})
        labels = list(stream_labels)
        default = next((i for i, lbl in enumerate(labels) if stream_labels[lbl] in http_streams), 0)
        lbl = st.selectbox("TCP stream (this is also 'the selected stream' for the AI tab)", labels, index=default)
        selected_stream = stream_labels[lbl]
        s = analysis.streams[selected_stream]
        st.caption(f"Frames {s.frames[0]}–{s.frames[-1]} · {s.total_bytes} bytes · "
                   f"{s.end_time - s.start_time:.3f} s")
        # rebuild the conversation in arrival order, like Wireshark's Follow Stream
        chunks = sorted([("c2s", seg) for seg in s.segments["c2s"]] + [("s2c", seg) for seg in s.segments["s2c"]],
                        key=lambda x: x[1].frame)
        seen = {"c2s": set(), "s2c": set()}
        html_parts = []
        for direction, seg in chunks:
            if seg.seq in seen[direction]:
                continue                          # skip retransmissions
            seen[direction].add(seg.seq)
            text = seg.payload.decode("utf-8", "replace")
            printable = "".join(ch if ch.isprintable() or ch in "\r\n\t" else "." for ch in text)[:4000]
            printable = printable.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            color = "#c0392b" if direction == "c2s" else "#1f5fa8"
            html_parts.append(f'<div style="color:{color};white-space:pre-wrap;font-family:monospace;'
                              f'font-size:12px;border-left:3px solid {color};padding-left:8px;margin:4px 0">'
                              f'<b>[frame {seg.frame}]</b>\n{printable}</div>')
        st.markdown("<span style='color:#c0392b'>■ client → server</span> &nbsp; "
                    "<span style='color:#1f5fa8'>■ server → client</span>", unsafe_allow_html=True)
        st.markdown("".join(html_parts) or "_No payload in this stream (only handshake/ACKs)._",
                    unsafe_allow_html=True)

# --------------------------------------------------------------------------
# HTTP vs HTTPS
# --------------------------------------------------------------------------
with tabs[3]:
    st.markdown("What can an observer on the network still see? This compares cleartext HTTP with TLS (HTTPS).")
    tls_streams = {sid for sid, s in analysis.streams.items()
                   if 443 in (s.server[1], s.client[1]) or any(h["stream"] == sid for h in analysis.tls_hellos)}
    http_streams = {t.stream_id for t in analysis.transactions}   # a keep-alive stream counts once
    http_bytes = sum(analysis.streams[sid].total_bytes for sid in http_streams)
    tls_bytes = sum(analysis.streams[sid].total_bytes for sid in tls_streams)
    c1, c2, c3 = st.columns(3)
    c1.metric("HTTP transactions (readable)", len(analysis.transactions))
    c2.metric("TLS / HTTPS streams", len(tls_streams))
    c3.metric("QUIC packets (UDP 443)", int((packets_df["protocol"] == "QUIC").sum()))
    st.table(pd.DataFrame([
        {"Information": "IP addresses & ports", "HTTP": "✅ visible", "HTTPS": "✅ visible"},
        {"Information": "Packet sizes & timing", "HTTP": "✅ visible", "HTTPS": "✅ visible"},
        {"Information": "Server name", "HTTP": "✅ Host header", "HTTPS": "⚠️ visible in SNI (ClientHello) and DNS"},
        {"Information": "URL path & parameters", "HTTP": "✅ visible", "HTTPS": "❌ encrypted"},
        {"Information": "Headers, cookies, User-Agent", "HTTP": "✅ visible", "HTTPS": "❌ encrypted"},
        {"Information": "Page content / form data", "HTTP": "✅ visible", "HTTPS": "❌ encrypted"},
    ]))
    if analysis.tls_hellos:
        st.markdown("**Server names leaked by TLS SNI in this capture**")
        st.dataframe(pd.DataFrame([{"frame": h["frame"], "time": fmt_time(h["time"]), "SNI": h["sni"],
                                    "server": f'{h["server"]}:{h["server_port"]}',
                                    "stream bytes": analysis.streams[h["stream"]].total_bytes}
                                   for h in analysis.tls_hellos]), hide_index=True, width="stretch")
    dns_q = [d for d in analysis.dns_queries if not d["is_response"]]
    if dns_q:
        st.markdown("**DNS queries (cleartext - reveal which sites were visited)**")
        st.dataframe(pd.DataFrame([{"frame": d["frame"], "time": fmt_time(d["time"]), "name": d["name"]}
                                   for d in dns_q]), hide_index=True, width="stretch")
    if tls_bytes or http_bytes:
        fig = px.bar(pd.DataFrame([{"type": "HTTP streams", "bytes": http_bytes},
                                   {"type": "TLS streams", "bytes": tls_bytes}]), x="type", y="bytes")
        fig.update_layout(height=260, margin=dict(t=10, b=10))
        st.plotly_chart(fig, width="stretch")

# --------------------------------------------------------------------------
# Ask AI
# --------------------------------------------------------------------------
with tabs[4]:
    st.markdown("Ask a question in free text (English or Hebrew). The AI receives only the data extracted above. "
                "Every cited frame is checked against the capture, and where possible the answer is compared "
                "with a value computed directly in Python.")
    if selected_stream is not None:
        st.caption(f"Selected stream (from the Follow Stream tab): {selected_stream}")
    if "history" not in st.session_state:
        st.session_state.history = []

    cols = st.columns(len(EXAMPLE_QUESTIONS))
    for col, q in zip(cols, EXAMPLE_QUESTIONS):
        if col.button(q, width="stretch"):
            st.session_state.question = q
    question = st.text_area("Your question", key="question", height=80)

    if st.button("Ask", type="primary") and question.strip():
        with st.spinner(f"Asking {provider}…"):
            result = ask_ai(question, analysis, selected_stream, provider=provider,
                            api_key=api_key_input or None, model=model_input.strip() or None)
        local = local_answer(question, analysis, selected_stream)
        st.session_state.history.insert(0, {"question": question, "result": result, "local": local})

    for i, item in enumerate(st.session_state.history):
        result, local = item["result"], item["local"]
        with st.container(border=True):
            st.markdown(f"**Q:** {item['question']}")
            st.caption(f"Answered by: {result.get('provider', '-')} in {result.get('seconds', '-')} s")
            if result.get("model_note"):
                st.info(result["model_note"])
            if "error" in result:
                st.error(result["error"])
            else:
                conf = result.get("confidence", "low")
                badge = {"high": "🟢 high", "medium": "🟡 medium", "low": "🔴 low"}.get(conf, conf)
                st.markdown(f"**AI answer** (confidence: {badge})")
                st.write(result.get("answer", ""))
                if result.get("uncertainty_note"):
                    st.caption(f"Uncertainty: {result['uncertainty_note']}")
                checked = verify_evidence(result.get("evidence", []), analysis)
                if checked:
                    ev_df = pd.DataFrame(checked)
                    ev_df["status"] = ev_df["status"].map({"ok": "✅ verified", "time-mismatch": "⚠️ time differs",
                                                           "missing-frame": "❌ frame not found"})
                    st.markdown("**Evidence** (checked against the capture)")
                    st.dataframe(ev_df[["frame", "timestamp", "real_time", "field", "explanation", "real_info", "status"]],
                                 hide_index=True, width="stretch")
                    bad = [c for c in checked if c["status"] != "ok"]
                    if bad:
                        st.warning(f"{len(bad)} evidence item(s) could not be verified - treat this answer with care.")
                else:
                    st.warning("The AI gave no evidence for this answer.")
            if local:
                st.markdown("**Computed directly from the capture (no AI):**")
                st.code(local["answer"] + (f"\nframes: {local['frames'][:30]}" if local["frames"] else ""))
                if "error" not in result:
                    ai_frames = {int(e.get("frame", 0)) for e in result.get("evidence", [])}
                    overlap = ai_frames & set(local["frames"])
                    if local["frames"] and not overlap:
                        st.error("❗ The AI's evidence frames do not overlap the computed answer - possible mistake.")
                    elif overlap:
                        st.success("The AI cited at least one of the frames found by the direct computation.")

    if st.session_state.history:
        # export for the submission document (sections 33-34)
        lines = ["# AI Q&A log", f"Capture: {analysis.file_name}", ""]
        for item in reversed(st.session_state.history):
            r = item["result"]
            lines += [f"## Q: {item['question']}", f"Model: {r.get('provider', '-')}",
                      f"**AI:** {r.get('answer', r.get('error'))}",
                      f"Confidence: {r.get('confidence', '-')}",
                      "Evidence: " + ", ".join(f"frame {e['frame']} ({e['field']})" for e in r.get("evidence", [])),
                      f"**Computed:** {item['local']['answer'] if item['local'] else 'n/a'}", ""]
        st.download_button("⬇️ Download Q&A log (Markdown)", "\n".join(lines), file_name="ai_qa_log.md")

# --------------------------------------------------------------------------
# Packets
# --------------------------------------------------------------------------
with tabs[5]:
    f1, f2, f3 = st.columns(3)
    protos = f1.multiselect("Protocol", sorted(packets_df["protocol"].unique()))
    ip_filter = f2.text_input("IP address (src or dst)")
    port_filter = f3.text_input("Port (src or dst)")
    view = packets_df
    if protos:
        view = view[view["protocol"].isin(protos)]
    if ip_filter:
        view = view[(view["src"] == ip_filter.strip()) | (view["dst"] == ip_filter.strip())]
    if port_filter.strip().isdigit():
        port = int(port_filter)
        view = view[(view["sport"] == port) | (view["dport"] == port)]
    st.caption(f"{len(view)} of {len(packets_df)} packets")
    st.dataframe(view[["frame", "rel_time", "src", "sport", "dst", "dport", "protocol", "length", "info", "stream"]],
                 hide_index=True, width="stretch",
                 column_config={"rel_time": st.column_config.NumberColumn("time (s)", format="%.6f")})
