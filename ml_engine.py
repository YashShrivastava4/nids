"""
ml_engine.py — Train Random Forest + Isolation Forest, save/load models.
"""

import os, json, pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from pcap_extractor import generate_synthetic_dataset, FEATURES

MODEL_DIR = "models"
RF_PATH   = os.path.join(MODEL_DIR, "rf.pkl")
ISO_PATH  = os.path.join(MODEL_DIR, "iso.pkl")
ENC_PATH  = os.path.join(MODEL_DIR, "enc.pkl")
SCL_PATH  = os.path.join(MODEL_DIR, "scaler.pkl")
META_PATH = os.path.join(MODEL_DIR, "meta.json")


def train_and_save(pcap_path: str = None):
    """
    Train on pcap data if available, else synthetic.
    Saves all model artifacts to models/.
    """
    print("[ML] Preparing dataset...")

    if pcap_path and os.path.exists(pcap_path):
        from pcap_extractor import extract_from_pcap
        df = extract_from_pcap(pcap_path)
        # pcap data has no labels — use IsoForest only, RF gets synthetic
        print(f"[ML] Loaded {len(df)} packets from {pcap_path}")
        df_synth = generate_synthetic_dataset(n=3000)
        df = pd.concat([df_synth], ignore_index=True)
    else:
        print("[ML] No pcap found — using synthetic CICIDS2017-aligned data")
        df = generate_synthetic_dataset(n=3000)

    X = df[FEATURES].values
    le = LabelEncoder()
    y = le.fit_transform(df["label"])
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y)

    print("[ML] Training Random Forest (100 trees)...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=12,
                                 random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    y_pred = rf.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred,
                                    target_names=le.classes_, output_dict=True)
    cm = confusion_matrix(y_test, y_pred).tolist()

    print("[ML] Training Isolation Forest (anomaly detector)...")
    benign_idx = list(le.classes_).index("BENIGN")
    X_benign = X_scaled[y == benign_idx]
    iso = IsolationForest(contamination=0.1, random_state=42, n_jobs=-1)
    iso.fit(X_benign)

    importances = dict(zip(FEATURES, rf.feature_importances_.tolist()))

    os.makedirs(MODEL_DIR, exist_ok=True)
    for path, obj in [(RF_PATH,rf),(ISO_PATH,iso),(ENC_PATH,le),(SCL_PATH,scaler)]:
        with open(path,"wb") as f: pickle.dump(obj,f)

    meta = {
        "accuracy": round(acc, 4),
        "classes": le.classes_.tolist(),
        "report": report,
        "confusion_matrix": cm,
        "feature_importances": importances,
        "n_train": len(X_train),
        "n_test": len(X_test),
        "data_source": pcap_path if pcap_path else "synthetic"
    }
    with open(META_PATH,"w") as f: json.dump(meta,f)
    print(f"[ML] Training complete. Accuracy: {acc:.4f}")
    return meta


def load_models():
    with open(RF_PATH,"rb")  as f: rf     = pickle.load(f)
    with open(ISO_PATH,"rb") as f: iso    = pickle.load(f)
    with open(ENC_PATH,"rb") as f: le     = pickle.load(f)
    with open(SCL_PATH,"rb") as f: scaler = pickle.load(f)
    with open(META_PATH)     as f: meta   = json.load(f)
    return rf, iso, le, scaler, meta


def predict(features: dict, rf, iso, le, scaler) -> dict:
    x = np.array([[features.get(f, 0) for f in FEATURES]])
    xs = scaler.transform(x)
    idx   = rf.predict(xs)[0]
    proba = rf.predict_proba(xs)[0]
    iso_score = iso.decision_function(xs)[0]
    return {
        "label":         le.classes_[idx],
        "confidence":    round(float(proba.max()), 3),
        "probas":        dict(zip(le.classes_, [round(float(p),3) for p in proba])),
        "anomaly_score": round(float(iso_score), 4),
        "is_anomaly":    bool(iso.predict(xs)[0] == -1),
    }


if __name__ == "__main__":
    # Run standalone to pre-train: python3 ml_engine.py
    pcap = "data/live_capture.pcap" if os.path.exists("data/live_capture.pcap") else None
    train_and_save(pcap)
