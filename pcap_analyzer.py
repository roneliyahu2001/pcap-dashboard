"""
pcap_analyzer.py - extracts structured data from a PCAP / PCAPNG file.

Everything the dashboard (and the AI) knows about the capture comes from
this module. We read raw packets with Scapy and do our own work on top:
  * a per-frame table (frame number, time, addresses, ports, protocol, length)
  * TCP stream reassembly per direction
  * HTTP/1.x request / response parsing and request<->response matching
  * TLS ClientHello SNI extraction (to show what HTTPS still reveals)
  * DNS query extraction

Frame numbers start at 1, exactly like in Wireshark, so every answer can be
checked against the original capture.
"""

from __future__ import annotations

import gzip
import zlib
from dataclasses import dataclass, field
from datetime import datetime

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, IPv6, PcapReader

try:  # ICMPv6 lives in a separate scapy module
    from scapy.layers.inet6 import _ICMPv6
except ImportError:  # pragma: no cover
    _ICMPv6 = None

HTTP_METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS",
                b"PATCH", b"CONNECT", b"TRACE")


# --------------------------------------------------------------------------
# Data classes
# --------------------------------------------------------------------------

@dataclass
class Segment:
    """One TCP segment that carried payload bytes."""
    seq: int
    payload: bytes
    frame: int
    time: float


@dataclass
class HttpMessage:
    """A single parsed HTTP request or response."""
    is_request: bool
    start_line: str
    headers: dict[str, str]          # header names lower-cased
    raw_headers: str                 # headers exactly as sent
    body: bytes
    first_frame: int                 # frame with the first byte of the message
    last_frame: int                  # frame that completed the message (= Wireshark's HTTP frame)
    last_time: float
    frames: list[int]                # all frames that carried bytes of this message
    method: str = ""
    uri: str = ""
    version: str = ""
    status_code: int | None = None
    reason: str = ""


@dataclass
class HttpTransaction:
    """A request together with the response that answered it."""
    tx_id: int
    stream_id: int
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    request: HttpMessage
    response: HttpMessage | None = None

    @property
    def response_time(self) -> float | None:
        """Seconds between the request frame and the response frame (like http.time)."""
        if self.response is None:
            return None
        return self.response.last_time - self.request.last_time


@dataclass
class TcpStream:
    """A TCP connection (both directions)."""
    stream_id: int                   # same numbering idea as Wireshark's tcp.stream
    client: tuple[str, int]          # side that sent the first packet (normally the SYN)
    server: tuple[str, int]
    frames: list[int] = field(default_factory=list)
    segments: dict[str, list[Segment]] = field(default_factory=lambda: {"c2s": [], "s2c": []})
    total_bytes: int = 0
    start_time: float = 0.0
    end_time: float = 0.0


@dataclass
class CaptureAnalysis:
    """Everything extracted from one capture file."""
    file_name: str
    packets: list[dict]
    streams: dict[int, TcpStream]
    transactions: list[HttpTransaction]
    tls_hellos: list[dict]
    dns_queries: list[dict]

    # ---- summary helpers -------------------------------------------------
    @property
    def packet_count(self) -> int:
        return len(self.packets)

    @property
    def start_time(self) -> float | None:
        return self.packets[0]["time"] if self.packets else None

    @property
    def end_time(self) -> float | None:
        return self.packets[-1]["time"] if self.packets else None

    @property
    def duration(self) -> float:
        if not self.packets:
            return 0.0
        return self.end_time - self.start_time

    def frame(self, number: int) -> dict | None:
        """Return the packet record for a Wireshark frame number (1-based)."""
        if 1 <= number <= len(self.packets):
            return self.packets[number - 1]
        return None


# --------------------------------------------------------------------------
# Packet level helpers
# --------------------------------------------------------------------------

def _looks_like_tls(payload: bytes) -> bool:
    """TLS records start with content type 20-23 and version 0x03 0x0X."""
    return len(payload) >= 3 and payload[0] in (20, 21, 22, 23) and payload[1] == 3


def _classify(pkt, payload: bytes, sport: int | None, dport: int | None) -> str:
    """Pick a human readable protocol name for the frame (a rough 'top layer')."""
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(DNS):
        return "mDNS" if 5353 in (sport, dport) else "DNS"
    if pkt.haslayer(TCP):
        if payload:
            if payload.startswith(HTTP_METHODS) or payload.startswith(b"HTTP/"):
                return "HTTP"
            if _looks_like_tls(payload):
                return "TLS"
        return "TCP"
    if pkt.haslayer(UDP):
        if 443 in (sport, dport):
            return "QUIC"
        if 67 in (sport, dport) or 68 in (sport, dport):
            return "DHCP"
        if 1900 in (sport, dport):
            return "SSDP"
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if _ICMPv6 is not None and pkt.haslayer(_ICMPv6):
        return "ICMPv6"
    if pkt.haslayer(IPv6):
        return "IPv6"
    if pkt.haslayer(IP):
        return "IPv4"
    return "Other"


def _parse_sni(payload: bytes) -> str | None:
    """
    Pull the server name (SNI) out of a TLS ClientHello.
    The SNI is sent in clear text even in HTTPS, which is exactly the point
    we want to show in the HTTP vs HTTPS comparison.
    """
    try:
        if len(payload) < 43 or payload[0] != 22 or payload[5] != 1:  # handshake / ClientHello
            return None
        pos = 5 + 4 + 2 + 32                     # record hdr, handshake hdr, version, random
        pos += 1 + payload[pos]                  # session id
        pos += 2 + int.from_bytes(payload[pos:pos + 2], "big")   # cipher suites
        pos += 1 + payload[pos]                  # compression methods
        ext_end = pos + 2 + int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        while pos + 4 <= ext_end and pos + 4 <= len(payload):
            ext_type = int.from_bytes(payload[pos:pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2:pos + 4], "big")
            if ext_type == 0:                    # server_name extension
                name_len = int.from_bytes(payload[pos + 7:pos + 9], "big")
                return payload[pos + 9:pos + 9 + name_len].decode("ascii", "replace")
            pos += 4 + ext_len
    except (IndexError, ValueError):
        pass
    return None


# --------------------------------------------------------------------------
# TCP reassembly
# --------------------------------------------------------------------------

def _reassemble(segments: list[Segment]) -> tuple[bytes, list[tuple[int, int, int, float]]]:
    """
    Rebuild the byte stream of one direction of a TCP connection.

    Returns the bytes plus a map of (start_offset, end_offset, frame, time)
    so we can later tell which frames carried which bytes of an HTTP message.
    Retransmissions / overlaps are dropped, out-of-order segments are sorted.
    """
    if not segments:
        return b"", []
    base = min(s.seq for s in segments)
    ordered = sorted(segments, key=lambda s: ((s.seq - base) % 2**32, s.frame))

    data = bytearray()
    offsets = []
    for seg in ordered:
        rel = (seg.seq - base) % 2**32
        end = rel + len(seg.payload)
        if end <= len(data):            # pure retransmission, already have these bytes
            continue
        if rel > len(data):             # gap (lost packet) - we cannot fill it, stop here
            break
        new_part = seg.payload[len(data) - rel:]
        offsets.append((len(data), len(data) + len(new_part), seg.frame, seg.time))
        data.extend(new_part)
    return bytes(data), offsets


def _frames_for_range(offsets, start: int, end: int) -> list[tuple[int, float]]:
    """All (frame, time) pairs whose bytes overlap [start, end)."""
    return [(f, t) for (s, e, f, t) in offsets if s < end and e > start]


# --------------------------------------------------------------------------
# HTTP parsing
# --------------------------------------------------------------------------

def _decode_chunked(data: bytes, pos: int) -> tuple[bytes, int]:
    """Decode a chunked body starting at pos. Returns (body, end_position)."""
    body = bytearray()
    while True:
        line_end = data.find(b"\r\n", pos)
        if line_end == -1:
            return bytes(body), len(data)
        size_text = data[pos:line_end].split(b";")[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            return bytes(body), len(data)
        pos = line_end + 2
        if size == 0:
            trailer_end = data.find(b"\r\n\r\n", pos - 2)
            return bytes(body), (trailer_end + 4) if trailer_end != -1 else len(data)
        body.extend(data[pos:pos + size])
        pos += size + 2


def decode_body(msg: HttpMessage) -> bytes:
    """Undo Content-Encoding (gzip / deflate) so the body is readable."""
    encoding = msg.headers.get("content-encoding", "").lower()
    try:
        if "gzip" in encoding:
            return gzip.decompress(msg.body)
        if "deflate" in encoding:
            return zlib.decompress(msg.body)
    except (OSError, zlib.error, EOFError):
        pass
    return msg.body


def _parse_http_messages(data: bytes, offsets, expect_request: bool,
                         request_methods: list[str] | None = None) -> list[HttpMessage]:
    """Split one reassembled direction into HTTP messages."""
    messages = []
    pos = 0
    response_index = 0
    while pos < len(data):
        if expect_request and not data[pos:].startswith(HTTP_METHODS):
            break
        if not expect_request and not data[pos:].startswith(b"HTTP/"):
            break
        header_end = data.find(b"\r\n\r\n", pos)
        if header_end == -1:
            break                                   # incomplete headers
        head = data[pos:header_end].decode("iso-8859-1")
        lines = head.split("\r\n")
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()
        body_start = header_end + 4

        msg = HttpMessage(is_request=expect_request, start_line=lines[0], headers=headers,
                          raw_headers=head, body=b"", first_frame=0, last_frame=0,
                          last_time=0.0, frames=[])
        parts = lines[0].split(" ", 2)
        if expect_request:
            msg.method = parts[0]
            msg.uri = parts[1] if len(parts) > 1 else ""
            msg.version = parts[2] if len(parts) > 2 else ""
        else:
            msg.version = parts[0]
            try:
                msg.status_code = int(parts[1])
            except (IndexError, ValueError):
                msg.status_code = None
            msg.reason = parts[2] if len(parts) > 2 else ""

        # ---- figure out where the body ends ----------------------------
        no_body = False
        if not expect_request:
            code = msg.status_code or 0
            req_method = (request_methods[response_index]
                          if request_methods and response_index < len(request_methods) else "")
            no_body = code < 200 or code in (204, 304) or req_method == "HEAD"
        if no_body:
            body_end = body_start
        elif "chunked" in headers.get("transfer-encoding", "").lower():
            msg.body, body_end = _decode_chunked(data, body_start)
        elif "content-length" in headers:
            try:
                length = int(headers["content-length"])
            except ValueError:
                length = 0
            body_end = min(body_start + length, len(data))
        elif expect_request:
            body_end = body_start                   # requests without length have no body
        else:
            body_end = len(data)                    # read until the connection closes
        if not msg.body:
            msg.body = data[body_start:body_end]

        covering = _frames_for_range(offsets, pos, max(body_end, header_end + 4))
        if covering:
            msg.frames = sorted(f for f, _ in covering)
            msg.first_frame = covering[0][0]
            # The message is complete only when its LAST ARRIVING segment shows up
            # (segments may arrive out of order) - Wireshark shows it in that frame.
            msg.last_frame, msg.last_time = max(covering)
        messages.append(msg)
        if not expect_request and (msg.status_code or 0) >= 200:
            response_index += 1
        pos = body_end
    return messages


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------

def analyze_pcap(path: str, file_name: str | None = None) -> CaptureAnalysis:
    """Read a PCAP/PCAPNG file and return a CaptureAnalysis."""
    packets: list[dict] = []
    streams: dict[int, TcpStream] = {}
    stream_by_key: dict[frozenset, int] = {}
    tls_hellos: list[dict] = []
    dns_queries: list[dict] = []

    with PcapReader(path) as reader:          # handles both pcap and pcapng
        for frame_no, pkt in enumerate(reader, start=1):
            t = float(pkt.time)
            ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
            src = dst = None
            sport = dport = None
            payload = b""
            if ip is not None:
                src, dst = ip.src, ip.dst
            elif pkt.haslayer(ARP):
                src, dst = pkt[ARP].psrc, pkt[ARP].pdst

            tcp = pkt.getlayer(TCP)
            udp = pkt.getlayer(UDP)
            if tcp is not None:
                sport, dport = int(tcp.sport), int(tcp.dport)
                payload = bytes(tcp.payload)
            elif udp is not None:
                sport, dport = int(udp.sport), int(udp.dport)

            proto = _classify(pkt, payload, sport, dport)
            record = {
                "frame": frame_no, "time": t, "src": src, "dst": dst,
                "sport": sport, "dport": dport, "protocol": proto,
                "length": len(pkt), "info": "", "stream": None,
            }

            # ---- TCP stream bookkeeping --------------------------------
            if tcp is not None and src is not None:
                key = frozenset({(src, sport), (dst, dport)})
                flags = int(tcp.flags)
                is_syn_only = flags & 0x02 and not flags & 0x10
                # a new SYN on a key whose stream already finished = port reuse -> new stream
                if key in stream_by_key and is_syn_only and streams[stream_by_key[key]].segments["s2c"]:
                    del stream_by_key[key]
                if key not in stream_by_key:
                    sid = len(streams)
                    stream_by_key[key] = sid
                    # if the first packet we see is a SYN/ACK, the sender is the server
                    if flags & 0x12 == 0x12:
                        streams[sid] = TcpStream(sid, client=(dst, dport), server=(src, sport), start_time=t)
                    else:
                        streams[sid] = TcpStream(sid, client=(src, sport), server=(dst, dport), start_time=t)
                stream = streams[stream_by_key[key]]
                stream.frames.append(frame_no)
                stream.total_bytes += len(pkt)
                stream.end_time = t
                record["stream"] = stream.stream_id
                if payload:
                    direction = "c2s" if (src, sport) == stream.client else "s2c"
                    stream.segments[direction].append(Segment(int(tcp.seq), payload, frame_no, t))
                    if payload[:1] == b"\x16":
                        sni = _parse_sni(payload)
                        if sni:
                            tls_hellos.append({"frame": frame_no, "time": t, "client": src,
                                               "server": dst, "server_port": dport, "sni": sni,
                                               "stream": stream.stream_id})
                            record["info"] = f"TLS ClientHello, SNI={sni}"

            # ---- DNS -----------------------------------------------------
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                try:
                    qname = dns.qd.qname.decode().rstrip(".") if dns.qd else ""
                except (AttributeError, UnicodeDecodeError):
                    qname = ""
                if qname:
                    is_response = bool(dns.qr)
                    answers = []
                    if is_response:
                        for i in range(dns.ancount or 0):
                            try:
                                rr = dns.an[i]
                                if rr.type in (1, 28):   # A / AAAA
                                    answers.append(str(rr.rdata))
                            except (IndexError, AttributeError):
                                break
                    dns_queries.append({"frame": frame_no, "time": t, "name": qname,
                                        "is_response": is_response, "answers": answers,
                                        "src": src, "dst": dst})
                    record["info"] = ("DNS response " if is_response else "DNS query ") + qname

            if tcp is not None and not record["info"]:
                record["info"] = f"{sport} → {dport} [{tcp.flags}] len={len(payload)}"
            packets.append(record)

    # ---- HTTP: reassemble every stream and parse both directions -------
    transactions: list[HttpTransaction] = []
    for stream in streams.values():
        c_data, c_off = _reassemble(stream.segments["c2s"])
        if not c_data.startswith(HTTP_METHODS):
            continue
        requests = _parse_http_messages(c_data, c_off, expect_request=True)
        s_data, s_off = _reassemble(stream.segments["s2c"])
        responses = _parse_http_messages(s_data, s_off, expect_request=False,
                                         request_methods=[r.method for r in requests])
        final_responses = [r for r in responses if (r.status_code or 0) >= 200]  # skip 100 Continue
        for i, req in enumerate(requests):
            tx = HttpTransaction(
                tx_id=len(transactions) + 1, stream_id=stream.stream_id,
                client_ip=stream.client[0], client_port=stream.client[1],
                server_ip=stream.server[0], server_port=stream.server[1],
                request=req, response=final_responses[i] if i < len(final_responses) else None)
            transactions.append(tx)
            packets[req.last_frame - 1]["info"] = f"{req.method} {req.uri} {req.version}"
            packets[req.last_frame - 1]["protocol"] = "HTTP"
            if tx.response:
                rf = tx.response.last_frame
                packets[rf - 1]["info"] = tx.response.start_line
                packets[rf - 1]["protocol"] = "HTTP"

    transactions.sort(key=lambda tx: tx.request.last_frame)
    for i, tx in enumerate(transactions, start=1):
        tx.tx_id = i

    return CaptureAnalysis(file_name=file_name or path, packets=packets, streams=streams,
                           transactions=transactions, tls_hellos=tls_hellos,
                           dns_queries=dns_queries)


# --------------------------------------------------------------------------
# Small helpers used by the UI and the AI module
# --------------------------------------------------------------------------

def fmt_time(epoch: float | None) -> str:
    """Epoch seconds -> readable local time with milliseconds."""
    if epoch is None:
        return "-"
    return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def transaction_row(tx: HttpTransaction, capture_start: float) -> dict:
    """Flat dict for one transaction - used for tables and as AI context."""
    req, resp = tx.request, tx.response
    return {
        "tx": tx.tx_id,
        "stream": tx.stream_id,
        "method": req.method,
        "host": req.headers.get("host", ""),
        "uri": req.uri,
        "http_version": req.version,
        "src": f"{tx.client_ip}:{tx.client_port}",
        "dst": f"{tx.server_ip}:{tx.server_port}",
        "status": resp.status_code if resp else None,
        "reason": resp.reason if resp else "",
        "content_type": resp.headers.get("content-type", "") if resp else "",
        "content_length": resp.headers.get("content-length", "") if resp else "",
        "server": resp.headers.get("server", "") if resp else "",
        "request_frame": req.last_frame,
        "response_frame": resp.last_frame if resp else None,
        "request_time_rel": round(req.last_time - capture_start, 6),
        "response_time_s": round(tx.response_time, 6) if resp else None,
        "response_segments": len(resp.frames) if resp else 0,
        "user_agent": req.headers.get("user-agent", ""),
    }
