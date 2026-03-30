# 🛡️ IDS – Intrusion Detection System

A **real-time, ML-powered Intrusion Detection System** with a PyQt5 graphical interface.  
It captures live network packets, extracts features, and classifies traffic as **Normal** or **Malicious** using trained machine learning models.

---

## 📁 Project Structure

```
IDS-Intrusion-Detection-System/
├── main.py                   # Entry point – launches the GUI
├── install_requirements.py   # One-click dependency installer
├── requirements.txt          # All Python dependencies
│
├── ids/                      # Core IDS package
│   ├── __init__.py
│   ├── sniffer.py            # Packet sniffing (Scapy)
│   ├── feature_extractor.py  # Feature extraction from packets
│   ├── classifier.py         # ML model loader & predictor
│   └── utils.py              # Helpers, logging, constants
│
├── gui/                      # GUI package
│   ├── __init__.py
│   ├── main_window.py        # Main window (PyQt5)
│   ├── packet_table.py       # Live packet table widget
│   └── stats_panel.py        # Stats & charts panel
│
├── models/                   # Trained model files (place .pkl here)
│   └── README.md             # Instructions for adding your model
│
├── generate_demo_model.py    # Script to generate demo Random Forest model
├── install_requirements.py   # Run once to install all dependencies
│
└── tests/                    # Unit tests
    ├── test_feature_extractor.py
    └── test_classifier.py
```

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/WAQQASSX/IDS-Intrusion-Detection-System.git
cd IDS-Intrusion-Detection-System
```

### 2. Install dependencies
```bash
python install_requirements.py
```
> ⚠️ **Linux/macOS**: Packet capture requires root. Run with `sudo python main.py`.  
> ⚠️ **Windows**: Install [Npcap](https://npcap.com/) before running.

### 3. (Optional) Generate the demo model
```bash
python generate_demo_model.py
```

### 4. Launch the IDS
```bash
python main.py
```

---

## 🎯 Features

| Feature | Description |
|---|---|
| Interface selector | Choose any available network interface |
| Real-time sniffing | Live packet capture using Scapy |
| ML classification | Normal / Malicious traffic labeling |
| Model switcher | Hot-swap between multiple trained models |
| Statistics panel | Live counters: packet rate, threat ratio |
| Alert log | Time-stamped malicious packet alerts |
| Export | Save captured packets & alerts to CSV |

---

## 🤖 Adding Your Own Trained Model

1. Train a scikit-learn model in your notebook
2. Save it with joblib:
   ```python
   import joblib
   joblib.dump(model, "models/my_model.pkl")
   ```
3. Launch the IDS → select your model from the **Model** dropdown

The model must accept a **feature vector of 13 values** (see `ids/feature_extractor.py`).

---

## 📊 Feature Vector (13 Features)

| # | Feature | Description |
|---|---|---|
| 1 | `pkt_len` | Total packet length |
| 2 | `ip_proto` | IP protocol number |
| 3 | `src_port` | Source port |
| 4 | `dst_port` | Destination port |
| 5 | `tcp_flags` | TCP flags as integer |
| 6 | `udp_len` | UDP payload length |
| 7 | `ttl` | IP Time-To-Live |
| 8 | `is_tcp` | 1 if TCP, else 0 |
| 9 | `is_udp` | 1 if UDP, else 0 |
| 10 | `is_icmp` | 1 if ICMP, else 0 |
| 11 | `payload_len` | Raw payload length |
| 12 | `frag_offset` | IP fragmentation offset |
| 13 | `header_len` | IP header length |

---

## 🔬 Model Selection & Justification

The recommended model is **Random Forest** for IDS classification:

- ✅ Handles mixed feature types without scaling
- ✅ Robust to noisy network data
- ✅ Provides feature importance for explainability
- ✅ Fast inference (< 1 ms per packet)
- ✅ Strong accuracy on CICIDS-2017 benchmark dataset

> Alternative: **Gradient Boosting (XGBoost)** for higher accuracy on imbalanced datasets.

---

## 📋 Requirements

- Python 3.9+
- Windows (with Npcap) or Linux/macOS (root required for raw sockets)
- PyQt5, Scapy, scikit-learn, joblib, numpy, pandas

---

## 📄 License

MIT License – free to use and modify.
