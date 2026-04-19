import os, time, threading, random, collections
import numpy as np
import pandas as pd

try:
    from scapy.all import rdpcap, sniff, IP, TCP, UDP, ICMP
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

FEATURES = [
    "pkt_len", "ttl", "proto", "src_port", "dst_port", "tcp_flags",
    "payload_len", "flow_duration", "fwd_pkt_count", "bwd_pkt_count",
    "fwd_pkt_len_mean", "bwd_pkt_len_mean", "flow_iat_mean",
    "syn_flag_cnt", "rst_flag_cnt", "fin_flag_cnt", "is_icmp"
]

live_packet_queue = collections.deque(maxlen=1000)
capture_running   = False
capture_thread    = None


def _packet_handler(pkt):
    if not pkt.haslayer(IP):
        return
    row = {
        "time":           time.strftime("%H:%M:%S"),
        "src":            pkt[IP].src,
        "dst":            pkt[IP].dst,
        "pkt_len":        len(pkt),
        "ttl":            pkt[IP].ttl,
        "proto":          pkt[IP].proto,
        "src_port":       pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0),
        "dst_port":       pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0),
        "tcp_flags":      int(pkt[TCP].flags) if pkt.haslayer(TCP) else 0,
        "payload_len":    len(pkt[IP].payload),
        "flow_duration":  0,
        "fwd_pkt_count":  1,
        "bwd_pkt_count":  0,
        "fwd_pkt_len_mean": len(pkt),
        "bwd_pkt_len_mean": 0,
        "flow_iat_mean":  0,
        "syn_flag_cnt":   1 if (pkt.haslayer(TCP) and pkt[TCP].flags & 0x02) else 0,
        "rst_flag_cnt":   1 if (pkt.haslayer(TCP) and pkt[TCP].flags & 0x04) else 0,
        "fin_flag_cnt":   1 if (pkt.haslayer(TCP) and pkt[TCP].flags & 0x01) else 0,
        "is_icmp":        int(pkt.haslayer(ICMP)),
        "proto_name":     "TCP" if pkt.haslayer(TCP) else ("UDP" if pkt.haslayer(UDP) else ("ICMP" if pkt.haslayer(ICMP) else "OTHER")),
        "is_live":        True,
    }
    live_packet_queue.append(row)


def start_live_capture(iface=None):
    global capture_running, capture_thread
    if capture_running:
        return

    def _run():
        global capture_running
        capture_running = True
        try:
            sniff(iface=iface, prn=_packet_handler, store=False, filter="ip", count=0)
        except Exception as e:
            print(f"[Capture] Error: {e}")
            print("[Capture] Falling back to simulation mode")
            capture_running = False

    capture_thread = threading.Thread(target=_run, daemon=True)
    capture_thread.start()
    print(f"[Capture] Live capture started on interface: {iface or 'auto'}")


def stop_live_capture():
    global capture_running
    capture_running = False


def get_interface():
    try:
        import subprocess
        result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], capture_output=True, text=True)
        for part in result.stdout.split():
            if part not in ('8.8.8.8','via','dev','src','uid','cache','','proto','kernel','scope','link'):
                if not part[0].isdigit():
                    return part
    except Exception:
        pass
    return None


def extract_from_pcap(pcap_path):
    if not SCAPY_OK:
        raise RuntimeError("Scapy not installed")
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"File not found: {pcap_path}")

    packets = rdpcap(pcap_path)
    rows = []
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        rows.append({
            "pkt_len":          len(pkt),
            "ttl":              pkt[IP].ttl,
            "proto":            pkt[IP].proto,
            "src_port":         pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0),
            "dst_port":         pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0),
            "tcp_flags":        int(pkt[TCP].flags) if pkt.haslayer(TCP) else 0,
            "payload_len":      len(pkt[IP].payload),
            "flow_duration":    0,
            "fwd_pkt_count":    1,
            "bwd_pkt_count":    0,
            "fwd_pkt_len_mean": len(pkt),
            "bwd_pkt_len_mean": 0,
            "flow_iat_mean":    0,
            "syn_flag_cnt":     1 if (pkt.haslayer(TCP) and pkt[TCP].flags & 0x02) else 0,
            "rst_flag_cnt":     1 if (pkt.haslayer(TCP) and pkt[TCP].flags & 0x04) else 0,
            "fin_flag_cnt":     1 if (pkt.haslayer(TCP) and pkt[TCP].flags & 0x01) else 0,
            "is_icmp":          int(pkt.haslayer(ICMP)),
        })
    return pd.DataFrame(rows)


def generate_synthetic_dataset(n=3000, seed=42):
    random.seed(seed)
    np.random.seed(seed)

    TYPES = {
        "BENIGN": 0.55, "DoS": 0.15, "PortScan": 0.12,
        "BruteForce": 0.08, "Infiltration": 0.05, "Botnet": 0.05
    }

    def flow(label):
        if label == "BENIGN":
            return dict(pkt_len=np.random.normal(500,150), ttl=random.choice([64,128]),
                proto=random.choice([6,17]), src_port=random.randint(1024,65535),
                dst_port=random.choice([80,443,53,22,8080]), tcp_flags=random.choice([2,16,18,24]),
                payload_len=np.random.normal(450,120), flow_duration=np.random.exponential(500),
                fwd_pkt_count=np.random.poisson(8), bwd_pkt_count=np.random.poisson(6),
                fwd_pkt_len_mean=np.random.normal(400,100), bwd_pkt_len_mean=np.random.normal(350,80),
                flow_iat_mean=np.random.exponential(80), syn_flag_cnt=random.randint(0,2),
                rst_flag_cnt=0, fin_flag_cnt=random.randint(0,1), is_icmp=0, label=label)
        elif label == "DoS":
            return dict(pkt_len=np.random.normal(60,10), ttl=random.randint(30,64),
                proto=random.choice([6,1]), src_port=random.randint(1024,65535),
                dst_port=random.choice([80,443]), tcp_flags=2,
                payload_len=np.random.normal(40,8), flow_duration=np.random.exponential(50),
                fwd_pkt_count=np.random.poisson(200), bwd_pkt_count=np.random.poisson(1),
                fwd_pkt_len_mean=np.random.normal(60,5), bwd_pkt_len_mean=np.random.normal(40,5),
                flow_iat_mean=np.random.exponential(5), syn_flag_cnt=random.randint(50,200),
                rst_flag_cnt=random.randint(0,5), fin_flag_cnt=0, is_icmp=random.randint(0,1), label=label)
        elif label == "PortScan":
            return dict(pkt_len=np.random.normal(54,5), ttl=64, proto=6,
                src_port=random.randint(1024,65535), dst_port=random.randint(1,1024), tcp_flags=2,
                payload_len=np.random.normal(20,3), flow_duration=np.random.exponential(10),
                fwd_pkt_count=np.random.poisson(1), bwd_pkt_count=0,
                fwd_pkt_len_mean=np.random.normal(54,3), bwd_pkt_len_mean=0,
                flow_iat_mean=np.random.exponential(2), syn_flag_cnt=1,
                rst_flag_cnt=random.randint(0,1), fin_flag_cnt=0, is_icmp=0, label=label)
        elif label == "BruteForce":
            return dict(pkt_len=np.random.normal(200,40), ttl=128, proto=6,
                src_port=random.randint(1024,65535), dst_port=random.choice([22,21,3389]), tcp_flags=24,
                payload_len=np.random.normal(180,30), flow_duration=np.random.exponential(200),
                fwd_pkt_count=np.random.poisson(30), bwd_pkt_count=np.random.poisson(30),
                fwd_pkt_len_mean=np.random.normal(200,20), bwd_pkt_len_mean=np.random.normal(200,20),
                flow_iat_mean=np.random.exponential(30), syn_flag_cnt=random.randint(1,3),
                rst_flag_cnt=random.randint(0,2), fin_flag_cnt=random.randint(0,1), is_icmp=0, label=label)
        else:
            return dict(pkt_len=np.random.normal(300,80), ttl=random.choice([64,128]),
                proto=random.choice([6,17]), src_port=random.randint(1024,65535),
                dst_port=random.choice([6667,1080,4444,8888]), tcp_flags=random.choice([16,24]),
                payload_len=np.random.normal(270,60), flow_duration=np.random.exponential(1000),
                fwd_pkt_count=np.random.poisson(15), bwd_pkt_count=np.random.poisson(15),
                fwd_pkt_len_mean=np.random.normal(300,50), bwd_pkt_len_mean=np.random.normal(300,50),
                flow_iat_mean=np.random.exponential(200), syn_flag_cnt=random.randint(0,2),
                rst_flag_cnt=0, fin_flag_cnt=random.randint(0,1), is_icmp=0, label=label)

    labels = random.choices(list(TYPES.keys()), weights=list(TYPES.values()), k=n)
    df = pd.DataFrame([flow(l) for l in labels])
    for col in df.select_dtypes(include=[np.number]).columns:
        df[col] = df[col].clip(lower=0)
    return df
