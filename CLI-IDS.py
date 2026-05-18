#IDS - All-in-One File (CLI Version)
#Requires: scapy, joblib, numpy, pandas, xgboost
#Place model at:   model_knn.pkl
#Place scaler at:  RobustScalerDf.pkl


import os
import sys
import datetime
import threading
import logging
import warnings
import joblib
import numpy as np
import pandas as pd
warnings.filterwarnings("ignore")

# ─── LOGGING ──────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s]: %(message)s")
logger = logging.getLogger("IDS")

# ─── PATHS ────────────────────────────────────────────────────────────────────
# Setting up paths relative to this script so it doesn't break if run from another directory
ROOT_DIR    = os.path.dirname(os.path.abspath(__file__))
SCALER_PATH = os.path.join(ROOT_DIR, "RobustScalerDf.pkl")
MODEL_PATH  = os.path.join(ROOT_DIR, "model_knn.pkl")

# ─── CONSTANTS ────────────────────────────────────────────────────────────────
# These must match the exact feature order the KNN model was trained on.
FEATURE_NAMES = [
    "Protocol", "Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Bwd Pkts",
    "Fwd Pkt Len Max", "Fwd Pkt Len Min", "Fwd Pkt Len Mean",
    "Bwd Pkt Len Max", "Bwd Pkt Len Min", "Bwd Pkt Len Mean",
    "Flow Byts/s", "Flow Pkts/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Tot", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Tot", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd Pkts/s", "Bwd Pkts/s",
    "Pkt Len Min", "Pkt Len Mean", "Pkt Len Std", "Pkt Len Var",
    "Init Bwd Win Byts",
    "Active Mean", "Active Std", "Active Min",
    "Idle Mean", "Idle Std",
    "Packets_per_Second", "Bytes_per_Second", "Avg_Packet_Size"
]
LABEL_MAP = {0: "Normal", 1: "Malicious"}
THRESHOLD = 0.40  # Alert Catching threats is more important than a few false alarms.

# ─── FEATURE EXTRACTOR ────────────────────────────────────────────────────────
try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_OK = True
except ImportError:
    # If the user forgot to install scapy or isn't root/admin, we catch it here so the app doesn't crash instantly.
    SCAPY_OK = False

class Flow:
    #Represents a network conversation (session) between two hosts.
    #It tracks packet counts, sizes, and arrival times to calculate behavior metrics.
    
    def __init__(self, first_pkt, protocol):
        self.protocol       = protocol
        self.start_time     = float(first_pkt.time)
        self.last_time      = float(first_pkt.time)
        self.fwd_pkts       = 0
        self.bwd_pkts       = 0
        self.fwd_bytes      = 0
        self.bwd_bytes      = 0
        self.fwd_pkt_lens   = []
        self.bwd_pkt_lens   = []
        self.all_iats       = []  # Inter-Arrival Times (time between packets)
        self.fwd_last_time  = None
        self.bwd_last_time  = None
        self.fwd_iats       = []
        self.bwd_iats       = []
        self.init_bwd_win   = 0   # TCP window size (often unique in scanning/attacks)
        self.active_start   = float(first_pkt.time)
        self.idle_times     = []
        self.active_times   = []

    def update(self, pkt, direction):
        #Adds a new packet to this session and re-calculates timing gaps.
        curr = float(pkt.time)
        plen = len(pkt)
        iat  = curr - self.last_time
        self.all_iats.append(iat)
        
        # If no packets moved for over 1 second, we consider the connection to have been "idle".
        if iat > 1.0:
            self.idle_times.append(iat)
            self.active_times.append(self.last_time - self.active_start)
            self.active_start = curr
            
        # Separate statistics based on whether it's outbound (fwd) or inbound (bwd)
        if direction == "fwd":
            self.fwd_pkts  += 1
            self.fwd_bytes += plen
            self.fwd_pkt_lens.append(plen)
            if self.fwd_last_time is not None:
                self.fwd_iats.append(curr - self.fwd_last_time)
            self.fwd_last_time = curr
        else:
            self.bwd_pkts  += 1
            self.bwd_bytes += plen
            self.bwd_pkt_lens.append(plen)
            if self.bwd_last_time is not None:
                self.bwd_iats.append(curr - self.bwd_last_time)
            # Snag the initial window size from the very first response packet (common fingerprinting metric)
            if self.bwd_pkts == 1 and pkt.haslayer(TCP):
                self.init_bwd_win = pkt[TCP].window
            self.bwd_last_time = curr
        self.last_time = curr

    def get_features(self):
       #Flattens the gathered flow data into a single math array for the ML model.
        # Prevent division by zero if a session happens instantly
        dur = max(self.last_time - self.start_time, 1e-6)
        
        # Fallback values to keep numpy functions from crashing on empty lists
        fw  = np.array(self.fwd_pkt_lens) if self.fwd_pkt_lens else np.array([0])
        bw  = np.array(self.bwd_pkt_lens) if self.bwd_pkt_lens else np.array([0])
        al  = np.concatenate([fw, bw])
        fi  = np.array(self.fwd_iats) if self.fwd_iats else np.array([0])
        bi  = np.array(self.bwd_iats) if self.bwd_iats else np.array([0])
        ai  = np.array(self.all_iats)  if self.all_iats  else np.array([0])
        
        cur_act = self.last_time - self.active_start
        act = np.array(self.active_times + [cur_act])
        idl = np.array(self.idle_times) if self.idle_times else np.array([0])
        
        # This matches the exact order defined in FEATURE_NAMES
        return np.array([
            self.protocol, dur, self.fwd_pkts, self.bwd_pkts, self.bwd_bytes,
            np.max(fw), np.min(fw), np.mean(fw),
            np.max(bw), np.min(bw), np.mean(bw),
            (self.fwd_bytes + self.bwd_bytes) / dur,
            (self.fwd_pkts  + self.bwd_pkts)  / dur,
            np.mean(ai), np.std(ai), np.max(ai), np.min(ai),
            np.sum(fi), np.mean(fi), np.std(fi), np.max(fi), np.min(fi),
            np.sum(bi), np.mean(bi), np.std(bi), np.max(bi), np.min(bi),
            self.fwd_pkts / dur, self.bwd_pkts / dur,
            np.min(al), np.mean(al), np.std(al), np.var(al),
            self.init_bwd_win,
            np.mean(act), np.std(act), np.min(act),
            np.mean(idl), np.std(idl),
            self.fwd_pkts / dur,
            self.fwd_bytes / dur,
            self.fwd_bytes / (self.fwd_pkts + 1)
        ], dtype=np.float32)


class FlowTracker:
    """Keeps a live dictionary of active connections so we don't treat every packet as a brand new event."""
    def __init__(self):
        self.flows = {}

    def reset(self):
        self.flows = {}

    def get_features(self, pkt):
        if not pkt.haslayer(IP):
            return None
            
        ip    = pkt[IP]
        proto = int(ip.proto)
        sp = dp = 0
        
        # Grab ports if it's TCP or UDP; leave as 0 if it's ICMP/Raw IP
        if pkt.haslayer(TCP):
            sp, dp = pkt[TCP].sport, pkt[TCP].dport
        elif pkt.haslayer(UDP):
            sp, dp = pkt[UDP].sport, pkt[UDP].dport
            
        # We check both directions because a packet can be client->server OR server->client
        fk = (ip.src, ip.dst, sp, dp, proto)  # Forward direction key
        bk = (ip.dst, ip.src, dp, sp, proto)  # Backward direction key
        
        if fk in self.flows:
            self.flows[fk].update(pkt, "fwd")
            return self.flows[fk].get_features()
        elif bk in self.flows:
            self.flows[bk].update(pkt, "bwd")
            return self.flows[bk].get_features()
        else:
            # First time seeing this tuple? Spin up a new tracking slot.
            f = Flow(pkt, proto)
            f.update(pkt, "fwd")
            self.flows[fk] = f
            return f.get_features()

_tracker = FlowTracker()

# ─── CLASSIFIER ───────────────────────────────────────────────────────────────
class Classifier:
    """Handles parsing the raw statistical features through the scaler and model pipeline."""
    def __init__(self):
        self.model  = None
        self.scaler = None
        self._load()

    def _load(self):
        try:
            if os.path.exists(SCALER_PATH):
                self.scaler = joblib.load(SCALER_PATH)
                logger.info("Scaler loaded.")
            if os.path.exists(MODEL_PATH):
                self.model = joblib.load(MODEL_PATH)
                # Cap CPU threads to 1 to keep prediction cycles from bottlenecking packet sniffing threads
                if hasattr(self.model, "set_params"):
                    self.model.set_params(n_jobs=1)
                logger.info("Model loaded.")
            else:
                logger.error(f"Model not found: {MODEL_PATH}")
        except Exception as e:
            logger.error(f"Load error: {e}")

    def predict(self, features):
        if self.model is None:
            return {"label": "Normal", "confidence": 0.0, "attack_prob": 0.0}
        try:
            # Transform the flat list into a labeled DataFrame so the pipeline doesn't complain about losing feature names
            df = pd.DataFrame([features], columns=FEATURE_NAMES)
            if self.scaler is not None:
                X = pd.DataFrame(self.scaler.transform(df), columns=FEATURE_NAMES)
            else:
                X = df
                
            # If the model can output probabilities, we use our custom sensitive threshold instead of defaults.
            if hasattr(self.model, "predict_proba"):
                probs       = self.model.predict_proba(X)[0]
                attack_prob = float(probs[1])
                label       = "Malicious" if attack_prob >= THRESHOLD else "Normal"
                conf        = attack_prob if label == "Malicious" else float(probs[0])
                return {"label": label, "confidence": conf, "attack_prob": attack_prob}
                
            # Worst case fallback if the loaded model doesn't support probabilities
            pred = int(self.model.predict(X)[0])
            return {"label": LABEL_MAP.get(pred, "Unknown"), "confidence": 0.0, "attack_prob": 0.0}
        except Exception as e:
            logger.error(f"Predict error: {e}")
            return {"label": "Error", "confidence": 0.0, "attack_prob": 0.0}

# ─── SNIFFER ──────────────────────────────────────────────────────────────────
class Sniffer:
    """Spins off a background system thread to read packets coming off the network card hardware."""
    def __init__(self, iface, callback):
        self.iface    = iface
        self.callback = callback
        self._stop    = threading.Event()
        self._thread  = None

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self):
        from scapy.all import sniff, conf
        conf.sniff_promisc = True  # Promiscuous mode listens to ALL network traffic, not just traffic sent to our local IP.
        try:
            sniff(iface=self.iface, prn=self.callback,
                  stop_filter=lambda _: self._stop.is_set(),
                  store=False, promisc=True)  # store=False keeps scapy from eating up system RAM over time
        except Exception as e:
            logger.error(f"Sniffer error: {e}")

def list_interfaces():
    """Gathers standard names and system descriptions of your network adapters."""
    from scapy.all import conf
    return [{"name": i.name,
             "ip": i.ip if i.ip else "No IP",
             "description": i.description if i.description else i.name}
            for i in conf.ifaces.values()]

# ─── CLI ENGINE ───────────────────────────────────────────────────────────────
class CLIEngine:
    """Handles standard input/output formatting for the terminal interaction layer."""
    def __init__(self):
        self.classifier = Classifier()
        self.sniffer    = None
        self.counts     = {"Normal": 0, "Malicious": 0}

    def select_interface(self):
        """Interactive terminal prompt allowing users to pick which card to sniff on."""
        interfaces = list_interfaces()
        print("\n=== Available Interfaces ===")
        for idx, iface in enumerate(interfaces):
            print(f"[{idx}] {iface['description']} ({iface['ip']}) -> ID: {iface['name']}")
        
        while True:
            try:
                choice = input("\nSelect interface index to monitor: ").strip()
                idx = int(choice)
                if 0 <= idx < len(interfaces):
                    return interfaces[idx]['name']
            except (ValueError, IndexError):
                pass
            print("Invalid selection. Please try again.")

    def start(self):
        """Starts up the packet ingestion engine and blocks until the user exits via Ctrl+C."""
        iface = self.select_interface()
        _tracker.reset()
        
        print(f"\nStarting IDS on interface: {iface}")
        print(f"Alert Threshold: {THRESHOLD:.2f}")
        print("Press Ctrl+C to stop monitoring.\n")
        
        # Printing out column headers with fixed padding widths so everything lines up cleanly
        print(f"{'Time':<10} {'Src IP':<16} {'Dst IP':<16} {'Proto':<6} {'Len':<6} {'Label':<10} {'Prob':<6}")
        print("-" * 75)

        self.sniffer = Sniffer(iface, self._process)
        self.sniffer.start()

        try:
            while True:
                threading.Event().wait(1)  # Keeps the main thread alive without maxing out CPU utilization
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Gracefully shuts down the background loop and prints a final session report."""
        print("\nStopping engine...")
        if self.sniffer:
            self.sniffer.stop()
        print("\n=== Final Statistics ===")
        print(f"Normal Packets   : {self.counts['Normal']}")
        print(f"Malicious Packets: {self.counts['Malicious']}")
        print("Goodbye.")

    def _process(self, pkt):
        """Worker loop that transforms raw frames into data points and hands them off to the model."""
        info = {
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "src": "-", "dst": "-", "proto": "OTHER",
            "len": len(pkt), "label": "Normal", "conf": 0.0
        }
        if not SCAPY_OK: 
            self._output_packet(info)
            return
            
        if pkt.haslayer(IP):
            info["src"] = pkt[IP].src
            info["dst"] = pkt[IP].dst
            if pkt.haslayer(TCP):   info["proto"] = "TCP"
            elif pkt.haslayer(UDP): info["proto"] = "UDP"
            elif pkt.haslayer(ICMP):info["proto"] = "ICMP"
            
            feats = _tracker.get_features(pkt)
            if feats is not None:
                res = self.classifier.predict(feats)
                info["label"] = res["label"]
                info["conf"]  = res["attack_prob"]
                
        self._output_packet(info)

    def _output_packet(self, info):
        """Prints log rows and appends explicit warning strings to suspicious packets."""
        label = info["label"]
        self.counts[label] = self.counts.get(label, 0) + 1

        # Builds a clean row corresponding to our table headers
        out_line = (
            f"{info['time']:<10} {info['src']:<16} {info['dst']:<16} "
            f"{info['proto']:<6} {str(info['len']):<6} {info['label']:<10} {info['conf']:.1%}"
        )
        
        if label == "Malicious":
            print(f"{out_line} -> ALERT: Malicious Activity Detected")
        else:
            print(out_line)

# ─── ENTRY POINT ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not SCAPY_OK:
        print("Warning: Scapy dependency elements could not be fully loaded. Packet details will be limited.")
    
    engine = CLIEngine()
    engine.start()