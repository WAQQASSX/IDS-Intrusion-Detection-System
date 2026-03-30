import threading
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether
from collections import deque

class PacketCapture:
    def __init__(self, callback=None, interface=None):
        self.callback = callback
        self.interface = interface
        self.running = False
        self._thread = None
        self.packet_queue = deque(maxlen=10000)

    def _process_packet(self, pkt):
        info = self._parse_packet(pkt)
        if info:
            self.packet_queue.append(info)
            if self.callback:
                self.callback(info)

    def _parse_packet(self, pkt):
        try:
            src = dst = "N/A"
            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
            elif pkt.haslayer(ARP):
                src = pkt[ARP].psrc
                dst = pkt[ARP].pdst
            elif pkt.haslayer(Ether):
                src = pkt[Ether].src
                dst = pkt[Ether].dst

            if pkt.haslayer(TCP):
                protocol = "TCP"
            elif pkt.haslayer(UDP):
                protocol = "UDP"
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"
            elif pkt.haslayer(ARP):
                protocol = "ARP"
            else:
                protocol = "Other"

            sport = dport = 0
            if pkt.haslayer(TCP):
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

            return {
                "src": src,
                "dst": dst,
                "protocol": protocol,
                "length": len(pkt),
                "sport": sport,
                "dport": dport,
                "timestamp": time.time(),
                "raw": pkt
            }
        except Exception:
            return None

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._capture, daemon=True)
        self._thread.start()

    def _capture(self):
        try:
            sniff(
                iface=self.interface if self.interface else None,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self.running
            )
        except Exception as e:
            print(f"Capture error: {e}")

    def stop(self):
        self.running = False
