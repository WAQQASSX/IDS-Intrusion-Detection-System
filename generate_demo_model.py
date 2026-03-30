"""
Run this script to generate a demo Random Forest model saved to models/.
Trained on synthetic data mimicking SYN floods, port scans, and ICMP floods.
Replace with your real trained model for production use.
"""
import os
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(MODELS_DIR, exist_ok=True)

rng = np.random.default_rng(42)
N = 5000

X = np.column_stack([
    rng.integers(40, 1500, N),
    rng.choice([6, 17, 1], N),
    rng.integers(1024, 65535, N),
    rng.integers(1, 65535, N),
    rng.integers(0, 64, N),
    rng.integers(0, 65535, N),
    rng.integers(1, 255, N),
    rng.integers(0, 2, N),
    rng.integers(0, 2, N),
    rng.integers(0, 2, N),
    rng.integers(0, 1400, N),
    rng.integers(0, 16, N),
    rng.choice([20, 24, 28, 32], N),
])

y = np.zeros(N, dtype=int)
y[(X[:, 4] == 2) & (X[:, 6] < 15)] = 1        # SYN flood
y[(X[:, 3] > 60000) & (X[:, 0] < 70)] = 1     # Port scan
y[(X[:, 9] == 1) & (X[:, 0] > 1200)] = 1      # ICMP flood

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("Training Random Forest classifier...")
clf = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

print("\n=== Evaluation ===")
print(classification_report(y_test, clf.predict(X_test), target_names=["Normal", "Malicious"]))

out = os.path.join(MODELS_DIR, "demo_model.pkl")
joblib.dump(clf, out)
print(f"\n✅ Model saved: {out}")
print("Launch the IDS: python main.py")
