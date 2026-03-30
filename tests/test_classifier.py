"""Unit tests for the classifier."""
import unittest
import numpy as np
from ids.classifier import PacketClassifier


class TestDemoClassifier(unittest.TestCase):

    def setUp(self):
        self.clf = PacketClassifier()

    def test_normal_traffic(self):
        features = np.array([500, 6, 12345, 443, 16, 0, 128, 1, 0, 0, 450, 0, 20], dtype=np.float32)
        result = self.clf.predict(features)
        self.assertEqual(result["label"], "Normal")

    def test_syn_flood(self):
        features = np.array([60, 6, 54321, 80, 2, 0, 5, 1, 0, 0, 0, 0, 20], dtype=np.float32)
        result = self.clf.predict(features)
        self.assertEqual(result["label"], "Malicious")

    def test_icmp_flood(self):
        features = np.array([1300, 1, 0, 0, 0, 0, 64, 0, 0, 1, 1250, 0, 20], dtype=np.float32)
        result = self.clf.predict(features)
        self.assertEqual(result["label"], "Malicious")


if __name__ == "__main__":
    unittest.main()
