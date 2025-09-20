# 👻 Ghost Sniffer

**Ghost Sniffer** is a lightweight network sniffer + IDS tool built with [Scapy](https://scapy.net/).
It can monitor live network traffic, detect simple anomalies, and perform host profiling.

---

## ✨ Features

* 🔎 **Live Sniffing**: capture packets in real time from a network interface.
* 📂 **Offline Analysis**: read and analyze PCAP files.
* 🛡️ **IDS-style Detection**:

  * ARP spoofing
  * Port scans
  * SYN floods
  * DNS NXDOMAIN floods
  * High packet rate
* 📊 **Statistics**:

  * Per-protocol packet counts
  * Top talkers (most active IPs)
  * Periodic summaries (`--summary-interval`)
* 🧩 **Host Profiling**:

  * MAC addresses & vendors
  * DNS queries
  * TLS SNI
  * HTTP Host & User-Agent
* 💾 **Output Options**:

  * Save packets to **PCAP**
  * Save summaries to **CSV**
  * Save detailed info to **JSON**
* 🎨 **Output Modes**:

  * `--verbose` → detailed packet view with colored output (Scapy-like)
  * `--quiet` → only start message + final summary
  * `--stats-only` → only statistics
  * `--no-color` → disable colored output (for logs)
  * `--follow <IP>` → filter traffic for a specific IP

---

## 🚀 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/username/ghost-sniffer.git
cd ghost-sniffer
pip install -r requirements.txt
```

Dependencies:

* Python 3.8+
* [Scapy](https://scapy.net/)
* [Rich](https://github.com/Textualize/rich) (optional, for colored output)

---

## 🛠️ Usage

### Live capture

```bash
sudo python3 sniffer.py -i wlan0 -d 120 --pcap out.pcap --csv out.csv --verbose
```

### Offline analysis

```bash
python3 sniffer.py --read capture.pcap --verbose
```

### Quiet mode

```bash
sudo python3 sniffer.py -i eth0 -d 300 --quiet
```

### Save JSON

```bash
sudo python3 sniffer.py -i wlan0 -d 60 --json output.json
```

---

## ⚠️ Disclaimer

Use **Ghost Sniffer** only on networks or devices that **you own or have explicit permission to test**.
Unauthorized use may violate the law.

---

## 📜 License

MIT License © 2025
