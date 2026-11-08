# PCAP Dashboard V1

A tool that takes a PCAP or PCAPNG file, extracts the information itself (no Wireshark needed), and answers questions about it with AI. Every answer comes with the evidence it is based on.

## Installation

Requires Python 3.10 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Running

```bash
streamlit run app.py
```

The browser opens at http://localhost:8501. In the sidebar, upload a PCAP or PCAPNG file, or pick one from the `samples/` folder.

### API key (only needed for AI questions)

The dashboard supports three AI providers. Choose one in the sidebar; a key for a single provider is enough:

| Provider | Where to get a key | Environment variable | Default model |
|---|---|---|---|
| Claude | console.anthropic.com | `ANTHROPIC_API_KEY` | `claude-opus-5-5` |
| OpenAI | platform.openai.com | `OPENAI_API_KEY` | `gpt-5` |
| Google Gemini | aistudio.google.com | `GEMINI_API_KEY` | `gemini-3.5-flash` |

Paste the key into the sidebar field, or set the environment variable before running, for example:

```bash
export GEMINI_API_KEY="..."
```

The key is kept only in the session's memory. Never put a key in the code or commit it.
Model names change over time: if you get a "model not found" or "overloaded" error, click **Load available models** in the sidebar and pick another model from the list.
Without a key the rest of the dashboard works normally, and the Ask AI tab still shows the answer computed directly from the capture.

## Project structure

| File | Purpose |
|---|---|
| `pcap_analyzer.py` | Reads the capture with Scapy, reassembles TCP streams (reorders out-of-order segments and ignores retransmissions), parses HTTP/1.x, matches requests to responses, and extracts TLS SNI and DNS |
| `ai_assistant.py` | Builds a JSON context from the extracted data, sends it to the chosen provider (Claude, OpenAI or Gemini) with the same structured answer schema (answer, evidence, confidence), and verifies the evidence against the capture |
| `app.py` | Streamlit user interface |
| `tests/make_test_pcap.py` | Generates a **synthetic** test capture whose answers are known in advance |
| `samples/` | Capture files (put your own recordings here) |

## Tabs (mapped to the assignment sections)

- **Overview** (23–26): packet count, start time, end time and duration, main endpoints, protocol distribution, and a traffic-volume-over-time chart.
- **HTTP** (27–29): a table of all transactions (method, host, URI, source and destination, status, response time, request frame and response frame). Selecting a transaction shows its headers, form or query parameters, and how many TCP segments made up the response.
- **Follow Stream**: the full conversation of a TCP stream, colored by direction (like Wireshark's Follow HTTP Stream).
- **HTTP vs HTTPS** (creative feature): what is still visible in encrypted traffic: server names from the TLS SNI, DNS queries and traffic volumes.
- **Ask AI** (30–34): free-text questions in English or Hebrew. Shows the answer, a confidence level and evidence (frames and timestamps). Every cited frame is verified against the capture, and the answer is compared with a value computed directly in Python. The full Q&A log can be downloaded and attached for sections 33–34.
- **Packets**: interactive filtering by protocol, IP address and port.

## How AI answers are checked

1. The AI receives **only** JSON with data that was already extracted. The PCAP file itself is never sent to the model.
2. Every frame the AI cites is checked: does it exist in the capture, and does the cited timestamp match its real time?
3. For the question types listed in the assignment (slowest request, status codes, number of requests to a host, the selected stream), the dashboard also computes the answer directly in Python. If the AI's frames do not overlap the computed ones, a warning is shown.

## Frame numbers and response times

Frame numbers match Wireshark's (starting at 1). When a response is split across several TCP segments, its frame is the segment that completed it, as in Wireshark. Response time is measured from the request frame to the response frame, like Wireshark's `http.time` field.

## Known limitations

- Only HTTP/1.x is parsed. HTTP/2 and HTTP/3 (QUIC) usually run over TLS, so they are not readable anyway.
- If a TCP segment is missing from the capture (packet loss), reassembly stops at the gap.
- The context sent to the AI is limited to 300 transactions; if there are more, the AI is told so.
