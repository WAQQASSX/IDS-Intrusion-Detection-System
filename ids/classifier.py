"""Load a trained ML model and classify packet feature vectors."""
from __future__ import annotations
import os
import numpy as np
import joblib
from ids.utils import logger, MODELS_DIR, LABEL_MAP


class PacketClassifier:
    """Wraps a scikit-learn model for single-packet inference."""

    def __init__(self, model_path: str | None = None):
        self.model = None
        self.model_path = model_path
        if model_path:
            self.load(model_path)

    # ── Public API ─────────────────────────────────────────────────────────────

    def load(self, path: str) -> bool:
        """Load a model from disk. Returns True on success."""
        try:
            self.model = joblib.load(path)
            self.model_path = path
            logger.info("Model loaded: %s", os.path.basename(path))
            return True
        except Exception as exc:
            logger.error("Failed to load model: %s", exc)
            self.model = None
            return False

    def predict(self, features: np.ndarray) -> dict:
        """
        Classify a single feature vector.

        Returns a dict:
            label      - "Normal" | "Malicious"
            class_id   - 0 | 1
            confidence - float 0-1 (if model supports predict_proba)
        """
        if self.model is None:
            return self._demo_predict(features)

        vec = features.reshape(1, -1)
        class_id = int(self.model.predict(vec)[0])
        confidence = 0.0

        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(vec)[0]
            confidence = float(proba[class_id])

        return {
            "label": LABEL_MAP.get(class_id, "Unknown"),
            "class_id": class_id,
            "confidence": confidence,
        }

    # ── Demo fallback (rule-based heuristic) ─────────────────────────────────

    @staticmethod
    def _demo_predict(features: np.ndarray) -> dict:
        """
        Simple rule-based heuristic used when no model file is loaded.
        Flags traffic as malicious based on well-known suspicious patterns.
        """
        dst_port  = features[3]
        tcp_flags = features[4]
        ttl       = features[6]
        pkt_len   = features[0]

        # SYN flood: SYN flag only + very short TTL
        if tcp_flags == 2 and ttl < 10:
            return {"label": "Malicious", "class_id": 1, "confidence": 0.85}

        # Port scan: unusual high ports with tiny packet
        if dst_port > 60000 and pkt_len < 60:
            return {"label": "Malicious", "class_id": 1, "confidence": 0.72}

        # Large ICMP (ping flood / Smurf)
        if features[9] == 1 and pkt_len > 1200:
            return {"label": "Malicious", "class_id": 1, "confidence": 0.80}

        return {"label": "Normal", "class_id": 0, "confidence": 0.95}
