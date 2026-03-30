"""Shared utilities, constants, and logging setup."""
import logging
import os

# ── Logging ──────────────────────────────────────────────────────────────────
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger("IDS")

# ── Paths ─────────────────────────────────────────────────────────────────────
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(ROOT_DIR, "models")
DATA_DIR = os.path.join(ROOT_DIR, "data")

# ── Constants ─────────────────────────────────────────────────────────────────
FEATURE_NAMES = [
    "pkt_len", "ip_proto", "src_port", "dst_port",
    "tcp_flags", "udp_len", "ttl", "is_tcp",
    "is_udp", "is_icmp", "payload_len", "frag_offset", "header_len",
]

LABEL_MAP = {0: "Normal", 1: "Malicious"}
LABEL_COLORS = {0: "#27ae60", 1: "#e74c3c"}


def get_model_files() -> list:
    """Return list of .pkl files found in the models directory."""
    if not os.path.isdir(MODELS_DIR):
        return []
    return [f for f in os.listdir(MODELS_DIR) if f.endswith(".pkl")]
