"""
app.py — NIDS main server
Auto-detects live capture capability.
Falls back to simulation if capture unavailable.
"""

import os, json, random, time, threading, collections
import numpy as np
from flask import Flask, jsonify, render_template, request

from pcap_extractor import (generate_synthetic_dataset, FEATURES,
                             start_live_capture, get_interface,
                             live_packet_queue, SCAPY_OK)
from ml_engine import train_and_save, load_models, predict, META_PATH, RF_PATH

app = Flask(__name__)

# ── Train models if needed ───────────────────────────────────────────────────
PCAP_PATH = "data/live_capture.pcap"
if not os.path.exists(RF_PATH):
    print("[NIDS] First run — training models...")
    train_and_save(PCAP_PATH if os.path.exists(PCAP_PATH) else None)

rf, iso, le, scaler, meta = load_models()
print(f"[NIDS] Ready. Accuracy={meta['accuracy']} | Source={meta['data_source']}")

# ── Try live capture only if explicitly enabled (not on cloud) ───────────────
LIVE_MODE = False
ENABLE_CAPTURE = os.environ.get("ENABLE_LIVE_CAPTURE", "false").lower() == "true"
if SCAPY_OK and ENABLE_CAPTURE:
    iface = get_interface()
    try:
        start_live_capture(iface)
        time.sleep(1.5)
        LIVE_MODE = True
        print(f"[NIDS] Live capture active on {iface}")
    except Exception as e:
        print(f"[NIDS] Live capture failed ({e}) — simulation mode")
else:
    print("[NIDS] Running in simulation mode (set ENABLE_LIVE_CAPTURE=true for live)")

# ── Simulation fallback ──────────────────────────────────────────────────────
_sim_pool = generate_synthetic_dataset(n=500, seed=99)
_sim_idx  = 0

feed       = collections.deque(maxlen=300)
feed_stats = {"total":0,"attacks":0,"anomalies":0,"benign":0}
lock       = threading.Lock()

PROTO_MAP = {6:"TCP",17:"UDP",1:"ICMP"}

def process_raw(raw: dict) -> dict:
    """Classify a raw packet dict from live capture or simulation."""
    features = {f: float(raw.get(f, 0)) for f in FEATURES}
    result   = predict(features, rf, iso, le, scaler)
    return {
        "time":         raw.get("time", time.strftime("%H:%M:%S")),
        "src":          raw.get("src", "—"),
        "dst":          raw.get("dst", "—"),
        "proto":        raw.get("proto_name") or PROTO_MAP.get(int(raw.get("proto",6)),"???"),
        "pkt_len":      int(raw.get("pkt_len",0)),
        "label":        result["label"],
        "confidence":   result["confidence"],
        "is_anomaly":   result["is_anomaly"],
        "anomaly_score":result["anomaly_score"],
        "is_live":      raw.get("is_live", False),
    }

def live_feed_loop():
    """Drain live_packet_queue and classify."""
    while True:
        if live_packet_queue:
            raw = live_packet_queue.popleft()
            entry = process_raw(raw)
            with lock:
                feed.append(entry)
                feed_stats["total"] += 1
                if entry["label"] == "BENIGN": feed_stats["benign"]  += 1
                else:                           feed_stats["attacks"] += 1
                if entry["is_anomaly"]:         feed_stats["anomalies"] += 1
        else:
            time.sleep(0.05)

def sim_feed_loop():
    """Simulation fallback — classifies synthetic flows."""
    global _sim_idx
    while True:
        if LIVE_MODE and len(live_packet_queue) > 0:
            time.sleep(0.2); continue
        row = _sim_pool.iloc[_sim_idx % len(_sim_pool)]
        _sim_idx += 1
        raw = {f: float(row[f]) for f in FEATURES}
        raw.update({"time": time.strftime("%H:%M:%S"),
                    "src":  f"192.168.{random.randint(1,5)}.{random.randint(2,254)}",
                    "dst":  random.choice(["10.0.0.1","8.8.8.8","1.1.1.1"]),
                    "proto_name": ["TCP","UDP","ICMP"][int(row["proto"]) % 3],
                    "is_live": False})
        entry = process_raw(raw)
        with lock:
            feed.append(entry)
            feed_stats["total"] += 1
            if entry["label"] == "BENIGN": feed_stats["benign"]  += 1
            else:                           feed_stats["attacks"] += 1
            if entry["is_anomaly"]:         feed_stats["anomalies"] += 1
        time.sleep(random.uniform(0.15, 0.35))

threading.Thread(target=live_feed_loop, daemon=True).start()
threading.Thread(target=sim_feed_loop,  daemon=True).start()

# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/meta")
def api_meta():
    return jsonify({**meta, "live_mode": LIVE_MODE})

@app.route("/api/feed")
def api_feed():
    with lock:
        return jsonify({"feed": list(feed)[-40:], "stats": dict(feed_stats)})

@app.route("/api/predict", methods=["POST"])
def api_predict():
    data     = request.json
    features = {f: float(data.get(f, 0)) for f in FEATURES}
    return jsonify(predict(features, rf, iso, le, scaler))

@app.route("/api/retrain", methods=["POST"])
def api_retrain():
    """Retrain on newly captured pcap."""
    global rf, iso, le, scaler, meta
    pcap = PCAP_PATH if os.path.exists(PCAP_PATH) else None
    meta = train_and_save(pcap)
    rf, iso, le, scaler, meta = load_models()
    return jsonify({"status": "ok", "accuracy": meta["accuracy"]})

if __name__ == "__main__":
    print("NIDS → http://localhost:5052")
    app.run(debug=False, port=5052, threaded=True)
