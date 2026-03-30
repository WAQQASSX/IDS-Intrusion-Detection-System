"""Real-time packet sniffer using Scapy, runs in a background thread."""
from __future__ import annotations
import threading
from typing import Callable

try:
    from scapy.all import sniff, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from ids.utils import logger


def list_interfaces() -> list[str]:
    """Return all available network interfaces."""
    if not SCAPY_AVAILABLE:
        return ["eth0", "lo"]
    return get_if_list()


class PacketSniffer:
    """
    Background thread that captures packets on a chosen interface
    and calls `callback` with each Scapy packet object.
    """

    def __init__(self, interface: str, callback: Callable, bpf_filter: str = "ip"):
        self.interface  = interface
        self.callback   = callback
        self.bpf_filter = bpf_filter
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.packet_count = 0

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info("Sniffer started on %s", self.interface)

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=3)
        logger.info("Sniffer stopped. Packets captured: %d", self.packet_count)

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run(self):
        if not SCAPY_AVAILABLE:
            logger.error("Scapy not available.")
            return
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._handle_packet,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False,
            )
        except Exception as exc:
            logger.error("Sniffer error: %s", exc)

    def _handle_packet(self, pkt):
        self.packet_count += 1
        try:
            self.callback(pkt)
        except Exception as exc:
            logger.warning("Callback error: %s", exc)
