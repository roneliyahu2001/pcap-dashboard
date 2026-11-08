"""
make_test_pcap.py - builds a small SYNTHETIC capture for testing the dashboard.

It is NOT a real recording (the assignment needs your own Wireshark capture).
It contains cases whose answers we know in advance, so we can check the
parser: a GET whose response is split into 3 TCP segments, a retransmitted
segment, an out-of-order segment, a POST form submission with a chunked
response, a 404, DNS, and a TLS ClientHello with SNI.

Usage:  python tests/make_test_pcap.py samples/synthetic_test.pcap
"""

import sys

from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, wrpcap

CLIENT, SERVER, DNS_SRV, TLS_SRV = "192.168.1.10", "54.204.39.132", "192.168.1.1", "142.250.75.14"
ETH = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
packets = []
clock = [1_760_000_000.0]


def add(pkt, dt=0.001):
    """Append a packet with a timestamp dt seconds after the previous one."""
    clock[0] += dt
    pkt.time = clock[0]
    packets.append(pkt)


def tcp_conn(cport, sport, server):
    """Handshake; returns mutable seq state [client_seq, server_seq]."""
    c, s = 1000, 5000
    add(ETH / IP(src=CLIENT, dst=server) / TCP(sport=cport, dport=sport, flags="S", seq=c))
    add(ETH / IP(src=server, dst=CLIENT) / TCP(sport=sport, dport=cport, flags="SA", seq=s, ack=c + 1), 0.02)
    add(ETH / IP(src=CLIENT, dst=server) / TCP(sport=cport, dport=sport, flags="A", seq=c + 1, ack=s + 1))
    return [c + 1, s + 1]


def c2s(st, cport, sport, server, data, dt=0.001):
    add(ETH / IP(src=CLIENT, dst=server) / TCP(sport=cport, dport=sport, flags="PA", seq=st[0], ack=st[1]) / data, dt)
    st[0] += len(data)


def s2c(st, cport, sport, server, data, dt=0.001, seq=None):
    """Server -> client data. Passing an explicit seq sends a retransmission."""
    add(ETH / IP(src=server, dst=CLIENT) / TCP(sport=sport, dport=cport, flags="PA",
                                                 seq=st[1] if seq is None else seq, ack=st[0]) / data, dt)
    if seq is None:
        st[1] += len(data)


# ---- DNS -------------------------------------------------------------------
add(ETH / IP(src=CLIENT, dst=DNS_SRV) / UDP(sport=50000, dport=53) / DNS(id=1, rd=1, qd=DNSQR(qname="httpbin.org")))
add(ETH / IP(src=DNS_SRV, dst=CLIENT) / UDP(sport=53, dport=50000) /
    DNS(id=1, qr=1, qd=DNSQR(qname="httpbin.org"), an=DNSRR(rrname="httpbin.org", rdata=SERVER)), 0.015)

# ---- Stream 0: GET /forms/post, response in 3 segments (one retransmitted) -
st = tcp_conn(51000, 80, SERVER)
c2s(st, 51000, 80, SERVER, b"GET /forms/post HTTP/1.1\r\nHost: httpbin.org\r\n"
    b"User-Agent: Mozilla/5.0 (Macintosh) TestBrowser/1.0\r\nAccept: text/html\r\n\r\n")
html = b"<html><body><form method='post' action='/post'>" + b"x" * 1400 + b"</form></body></html>"
resp = (b"HTTP/1.1 200 OK\r\nServer: gunicorn/19.9.0\r\nContent-Type: text/html; charset=utf-8\r\n"
        b"Content-Length: " + str(len(html)).encode() + b"\r\n\r\n" + html)
part1, part2, part3 = resp[:600], resp[600:1200], resp[1200:]
s2c(st, 51000, 80, SERVER, part1, 0.150)
part2_seq = st[1]
s2c(st, 51000, 80, SERVER, part2, 0.002)
s2c(st, 51000, 80, SERVER, part2, 0.001, seq=part2_seq)   # retransmission of part2
s2c(st, 51000, 80, SERVER, part3, 0.002)

# ---- Stream 1: favicon -> 404 ---------------------------------------------
st2 = tcp_conn(51001, 80, SERVER)
c2s(st2, 51001, 80, SERVER, b"GET /favicon.ico HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
s2c(st2, 51001, 80, SERVER, b"HTTP/1.1 404 NOT FOUND\r\nServer: gunicorn/19.9.0\r\n"
    b"Content-Type: text/html\r\nContent-Length: 9\r\n\r\nNot Found", 0.080)

# ---- TLS ClientHello with SNI (stream 2) ----------------------------------
st3 = tcp_conn(51002, 443, TLS_SRV)
sni = b"www.google.com"
ext = b"\x00\x00" + (len(sni) + 5).to_bytes(2, "big") + (len(sni) + 3).to_bytes(2, "big") + b"\x00" + len(sni).to_bytes(2, "big") + sni
body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + len(ext).to_bytes(2, "big") + ext
hs = b"\x01" + len(body).to_bytes(3, "big") + body
c2s(st3, 51002, 443, TLS_SRV, b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs)
s2c(st3, 51002, 443, TLS_SRV, b"\x17\x03\x03\x00\x20" + b"\xaa" * 32, 0.030)

# ---- Stream 0 again: POST form (keep-alive), chunked response, out of order
form = b"custname=Ron&custtel=0501234567&size=medium&topping=cheese&comments=test"
c2s(st, 51000, 80, SERVER, b"POST /post HTTP/1.1\r\nHost: httpbin.org\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " + str(len(form)).encode() + b"\r\n\r\n" + form, 2.0)
json_body = b'{"form": {"custname": "Ron", "size": "medium"}}'
chunked = (b"HTTP/1.1 200 OK\r\nServer: gunicorn/19.9.0\r\nContent-Type: application/json\r\n"
           b"Transfer-Encoding: chunked\r\n\r\n" + hex(len(json_body))[2:].encode() + b"\r\n" + json_body + b"\r\n0\r\n\r\n")
a, b = chunked[:90], chunked[90:]
seq_a = st[1]
add(ETH / IP(src=SERVER, dst=CLIENT) / TCP(sport=80, dport=51000, flags="PA", seq=seq_a + len(a), ack=st[0]) / b, 0.320)
add(ETH / IP(src=SERVER, dst=CLIENT) / TCP(sport=80, dport=51000, flags="PA", seq=seq_a, ack=st[0]) / a, 0.001)
st[1] += len(chunked)

wrpcap(sys.argv[1] if len(sys.argv) > 1 else "synthetic_test.pcap", packets)
print(f"wrote {len(packets)} packets")
