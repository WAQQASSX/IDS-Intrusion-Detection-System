"""Extract a fixed-length feature vector from a Scapy packet."""
from __future__ import annotations
import numpy as np

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.packet import Packet
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def extract_features(pkt) -> np.ndarray | None:
    """
    Extract 13 numerical features from a Scapy packet.

    Returns None if the packet cannot be parsed (e.g., non-IP traffic).
    """
    if not SCAPY_AVAILABLE:
        raise RuntimeError("Scapy is not installed.")

    if not pkt.haslayer("IP"):
        return None

    ip = pkt["IP"]

    pkt_len     = len(pkt)
    ip_proto    = ip.proto if hasattr(ip, "proto") else 0
    ttl         = ip.ttl if hasattr(ip, "ttl") else 0
    frag_offset = ip.frag if hasattr(ip, "frag") else 0
    header_len  = ip.ihl * 4 if hasattr(ip, "ihl") else 20

    # Transport layer
    src_port = dst_port = tcp_flags = udp_len = 0
    is_tcp = is_udp = is_icmp = 0
    payload_len = 0

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        src_port   = tcp.sport
        dst_port   = tcp.dport
        tcp_flags  = int(tcp.flags)
        is_tcp     = 1
        payload_len = len(tcp.payload)

    elif pkt.haslayer(UDP):
        udp = pkt[UDP]
        src_port    = udp.sport
        dst_port    = udp.dport
        udp_len     = udp.len
        is_udp      = 1
        payload_len = len(udp.payload)

    elif pkt.haslayer(ICMP):
        is_icmp     = 1
        payload_len = len(pkt[ICMP].payload)

    features = np.array([
        pkt_len, ip_proto, src_port, dst_port,
        tcp_flags, udp_len, ttl, is_tcp,
        is_udp, is_icmp, payload_len, frag_offset, header_len,
    ], dtype=np.float32)

    return features
