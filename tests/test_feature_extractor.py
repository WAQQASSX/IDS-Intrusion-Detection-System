"""Unit tests for the feature extractor."""
import unittest
import numpy as np

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from ids.feature_extractor import extract_features
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False


@unittest.skipUnless(SCAPY_OK, "Scapy not installed")
class TestFeatureExtractor(unittest.TestCase):

    def test_tcp_packet(self):
        pkt = IP(src="192.168.1.1", dst="10.0.0.1", ttl=64) / TCP(sport=12345, dport=80, flags="S")
        features = extract_features(pkt)
        self.assertIsNotNone(features)
        self.assertEqual(len(features), 13)
        self.assertEqual(features[7], 1.0)   # is_tcp
        self.assertEqual(features[3], 80.0)  # dst_port

    def test_udp_packet(self):
        pkt = IP() / UDP(sport=5000, dport=53)
        features = extract_features(pkt)
        self.assertIsNotNone(features)
        self.assertEqual(features[8], 1.0)

    def test_non_ip_returns_none(self):
        try:
            from scapy.layers.l2 import Ether
            pkt = Ether()
            self.assertIsNone(extract_features(pkt))
        except ImportError:
            pass


if __name__ == "__main__":
    unittest.main()
