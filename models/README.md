# Models Directory

Place your trained scikit-learn `.pkl` model files here.

## Requirements

Your model must:
- Be saved with `joblib.dump(model, "models/my_model.pkl")`
- Accept a **numpy array of shape (1, 13)** as input
- Output class labels **0 = Normal, 1 = Malicious**
- Optionally implement `predict_proba()` for confidence scores

## Feature Vector (13 features in order)

```
[pkt_len, ip_proto, src_port, dst_port, tcp_flags,
 udp_len, ttl, is_tcp, is_udp, is_icmp, payload_len,
 frag_offset, header_len]
```

## Quick way to generate a demo model

From the project root:
```bash
python generate_demo_model.py
```
This will create `models/demo_model.pkl` – a Random Forest trained on synthetic attack patterns.
