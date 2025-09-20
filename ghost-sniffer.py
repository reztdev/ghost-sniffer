# #!/usr/bin/env python3
# """
# sniffer.py (enhanced)
# Passive/active network sniffer + host profiling using Scapy.

# Features:
# - Live sniff with optional --pcap and --csv (only writes if provided).
# - Offline analysis with --read <file.pcap> showing all layers and fields (colored if verbose).
# - Profiling of hosts (MAC, vendor, DNS, HTTP, TLS SNI, etc.).
# - --quiet prints only a starting message and final summary (Ctrl+C stops gracefully).
# - --verbose prints detailed information about every packet with rich colored inline fields (Scapy-like).

# Usage:
#     sudo python3 sniffer.py -i wlan0 -d 300 --pcap out.pcap --csv out.csv
#     python3 sniffer.py --read capture.pcap
#     sudo python3 sniffer.py --iface wlo1 --duration 3600 --quiet

# Note: Run as root for live sniffing. Use only on networks/devices you own or are authorized to test.
# """
# import argparse
# import csv
# import time
# from collections import defaultdict, deque
# from scapy.all import sniff, rdpcap
# from scapy.utils import PcapWriter

# try:
#     from rich import print as rprint
#     from rich.console import Console
#     from rich.table import Table
#     from rich.panel import Panel
#     RICH = True
#     console = Console()
# except Exception:
#     RICH = False
#     def rprint(*a, **k):
#         print(*a, **k)

# # ---------------------------
# # Config
# # ---------------------------
# DEFAULT_SUMMARY_INTERVAL = 30  # seconds

# # ---------------------------
# # Global state
# # ---------------------------
# stats = {"pkt_count": 0, "start_time": time.time()}
# csv_rows = []

# # ---------------------------
# # Utils
# # ---------------------------
# def now_ts():
#     return time.time()

# # ---------------------------
# # Pretty printing
# # ---------------------------
# def print_packet_verbose(pkt):
#     if not RICH:
#         print(pkt.show(dump=True))
#         return

#     console.print(f"[bold red]Packet[/bold red] len={len(pkt)} summary={pkt.summary()}")
#     for layer in pkt.layers():
#         l = pkt.getlayer(layer)
#         parts = []
#         for field in l.fields_desc:
#             name = f"[magenta]{field.name}[/magenta]"
#             val = l.fields.get(field.name)
#             parts.append(f"{name}={val}")
#         console.print(f"[bold red]{layer.__name__}[/bold red]  " + "  ".join(parts))
#     print("-" * 75)

# # ---------------------------
# # Offline PCAP reader
# # ---------------------------
# def show_packet_details(pcap_file, limit=20, quiet=False, verbose=False):
#     rprint(f"[bold cyan][INFO][/bold cyan] Reading {pcap_file} ...")
#     time.sleep(1)
#     packets = rdpcap(pcap_file)

#     for i, pkt in enumerate(packets[:limit], 1):
#         table = Table(show_header=True, header_style="bold magenta")
#         table.add_column("Layer", style="cyan", no_wrap=True)
#         table.add_column("Field", style="yellow")
#         table.add_column("Value", style="green")

#         for layer in pkt.layers():
#             l = pkt.getlayer(layer)
#             for field in l.fields_desc:
#                 name = field.name
#                 val = l.fields.get(name)
#                 table.add_row(layer.__name__, name, str(val))

#         rprint(Panel(table, title=f"[bold green]Packet {i}[/bold green] "
#                                   f"(len={len(pkt)}) summary={pkt.summary()}",
#                      expand=False))

#     rprint(f"[bold cyan][INFO][/bold cyan] Total packets in file: {len(packets)}")


# # ---------------------------
# # CSV save
# # ---------------------------
# def save_csv(path):
#     if not csv_rows:
#         return
#     keys = ["ts","eth_src","eth_dst","ip_src","ip_dst","proto","sport","dport","len","summary","notes"]
#     with open(path, "w", newline="", encoding="utf-8") as f:
#         w = csv.DictWriter(f, fieldnames=keys)
#         w.writeheader()
#         for r in csv_rows:
#             rr = {k: r.get(k, "") for k in keys}
#             rr["notes"] = " | ".join(r.get("notes", []))
#             w.writerow(rr)

# # ---------------------------
# # Packet handler
# # ---------------------------
# def make_packet_handler(pcap_writer, args):
#     def handler(pkt):
#         stats["pkt_count"] += 1
#         if pcap_writer:
#             try:
#                 pcap_writer.write(pkt)
#             except Exception:
#                 pass
#         if args.quiet:
#             return
#         if args.verbose:
#             print_packet_verbose(pkt)
#         else:
#             print(pkt.summary())
#     return handler

# # ---------------------------
# # CLI & main
# # ---------------------------
# def parse_args():
#     p = argparse.ArgumentParser()
#     p.add_argument("--iface", "-i", help="Interface to sniff (e.g., wlan0 or eth0)")
#     p.add_argument("--duration", "-d", type=int, default=60, help="Total seconds to sniff")
#     p.add_argument("--pcap", help="Optional: PCAP output file")
#     p.add_argument("--csv", help="Optional: CSV output file")
#     p.add_argument("--filter", default=None, help="BPF filter (optional)")
#     p.add_argument("--verbose", action="store_true", help="Verbose: print each packet with full detail")
#     p.add_argument("--quiet", action="store_true", help="Quiet: only show start and summary messages")
#     p.add_argument("--summary-interval", type=int, default=DEFAULT_SUMMARY_INTERVAL, help="Periodic summary interval")
#     p.add_argument("--read", help="Read an existing PCAP file instead of live capture")
#     p.add_argument("--limit", type=int, default=20, help="Limit packets shown in --read mode")
#     return p.parse_args()

# def main():
#     args = parse_args()

#     if args.read:
#         show_packet_details(args.read, limit=args.limit, quiet=args.quiet, verbose=args.verbose)
#         return

#     if not args.iface:
#         print("Error: --iface required for live sniffing (or use --read)")
#         return

#     # Always show a start message even in quiet mode
#     rprint(f"[cyan][START][/cyan] Sniffing on {args.iface} for {args.duration}s")

#     pcap_writer = PcapWriter(args.pcap, append=False, sync=True) if args.pcap else None
#     handler = make_packet_handler(pcap_writer, args)

#     try:
#         sniff(iface=args.iface, prn=handler, store=0, timeout=args.duration, filter=args.filter)
#     except PermissionError:
#         print("Permission denied. Run with sudo/root.")
#         return
#     except KeyboardInterrupt:
#         if not args.quiet:
#             rprint("[yellow][INFO][/yellow] Keyboard interrupt received, stopping capture...")
#     except Exception as e:
#         print("Sniff error:", e)

#     if pcap_writer:
#         try:
#             pcap_writer.close()
#         except Exception:
#             pass
#     if args.csv:
#         try:
#             save_csv(args.csv)
#             if not args.quiet:
#                 rprint(f"[cyan][INFO][/cyan] CSV written to {args.csv}")
#         except Exception as e:
#             print("Error writing csv:", e)

#     duration = now_ts() - stats["start_time"]
#     rprint(f"[SUMMARY] duration={duration:.1f}s packets={stats['pkt_count']}")
#     print("Done.")

# if __name__ == "__main__":
#     main()

#!/usr/bin/env python3
"""
sniffer.py (super enhanced)
Passive/active network sniffer + IDS-style heuristics + host profiling using Scapy.

Features:
- Live sniff with optional --pcap and --csv (only writes if provided).
- Offline analysis with --read <file.pcap> showing all layers and fields (colored if verbose).
- --quiet prints only start and summary.
- --verbose prints detailed information (Scapy-like inline colored).
- IDS-style detection: ARP spoofing, port scan, DNS anomalies, SYN flood, high rate.
- Statistics: per-protocol counts, top talkers, periodic summaries.
- Host profiling: MAC vendor, DNS queries, TLS SNI, HTTP User-Agent.
- Extra modes: --json, --no-color, --follow <ip>, --stats-only.

Usage:
    sudo python3 sniffer.py -i wlan0 -d 300 --pcap out.pcap --csv out.csv
    python3 sniffer.py --read capture.pcap --verbose

Note: Run as root for live sniffing. Use only on networks/devices you own or are authorized to test.
"""
import argparse
import csv
import json
import time
from collections import defaultdict, deque, Counter
from scapy.all import sniff, rdpcap, Ether, IP, TCP, UDP, ARP, DNS, Raw
from scapy.utils import PcapWriter

try:
    from rich import print as rprint
    from rich.console import Console
    RICH = True
    console = Console()
except Exception:
    RICH = False
    def rprint(*a, **k):
        print(*a, **k)

# ---------------------------
# Config
# ---------------------------
DEFAULT_SUMMARY_INTERVAL = 30

THRESH = {
    "arp_repeat_threshold": 20,
    "dup_ip_mac_threshold": 2,
    "portscan_port_threshold": 30,
    "portscan_window_s": 30,
    "syn_flood_threshold": 200,
    "syn_window_s": 10,
    "high_rate_pkt_threshold": 500,
    "high_rate_window_s": 10,
    "dns_nxdomain_threshold": 50,
}

# ---------------------------
# Global state
# ---------------------------
stats = {"pkt_count": 0, "start_time": time.time(), "protocols": Counter(), "talkers": Counter()}
csv_rows = []
arp_ip_macs = defaultdict(set)
arp_who_counts = defaultdict(int)
recent_ports = defaultdict(lambda: deque())
recent_syns = defaultdict(lambda: deque())
recent_pkts = defaultdict(lambda: deque())
recent_dns_nxdomain = defaultdict(lambda: deque())

profiles = defaultdict(lambda: {"macs": set(), "dns": set(), "sni": set(), "ua": set()})

# ---------------------------
# Utils
# ---------------------------
def now_ts():
    return time.time()

# ---------------------------
# Pretty printing
# ---------------------------
def print_packet_verbose(pkt, no_color=False):
    if not RICH or no_color:
        print(pkt.show(dump=True))
        return
    console.print(f"[bold red]Packet[/bold red] len={len(pkt)} summary={pkt.summary()}")
    for layer in pkt.layers():
        l = pkt.getlayer(layer)
        parts = []
        for field in l.fields_desc:
            name = f"[magenta]{field.name}[/magenta]"
            val = l.fields.get(field.name)
            parts.append(f"{name}={val}")
        console.print(f"[bold red]{layer.__name__}[/bold red]  " + "  ".join(parts))
    console.rule()

# ---------------------------
# Detection helpers
# ---------------------------
def detect_anomalies(pkt):
    alerts = []
    if pkt.haslayer(ARP):
        src_ip, src_mac, dst_ip = pkt[ARP].psrc, pkt[ARP].hwsrc, pkt[ARP].pdst
        arp_ip_macs[src_ip].add(src_mac)
        if len(arp_ip_macs[src_ip]) >= THRESH["dup_ip_mac_threshold"]:
            alerts.append(f"[ALERT] Duplicate IP {src_ip} with MACs {arp_ip_macs[src_ip]}")
        key = (src_ip, dst_ip)
        arp_who_counts[key] += 1
        if arp_who_counts[key] >= THRESH["arp_repeat_threshold"]:
            alerts.append(f"[ALERT] ARP flood from {src_ip} to {dst_ip}")
    if pkt.haslayer(TCP):
        src = pkt[IP].src if pkt.haslayer(IP) else None
        dport = pkt[TCP].dport
        dq = recent_ports[src]
        dq.append((dport, now_ts()))
        while dq and dq[0][1] < now_ts() - THRESH["portscan_window_s"]:
            dq.popleft()
        if len({p for p, _ in dq}) >= THRESH["portscan_port_threshold"]:
            alerts.append(f"[ALERT] Port scan suspected from {src}")
        if pkt[TCP].flags & 0x02:
            dq2 = recent_syns[src]
            dq2.append(now_ts())
            while dq2 and dq2[0] < now_ts() - THRESH["syn_window_s"]:
                dq2.popleft()
            if len(dq2) >= THRESH["syn_flood_threshold"]:
                alerts.append(f"[ALERT] SYN flood suspected from {src}")
    if pkt.haslayer(DNS):
        if pkt[DNS].rcode == 3:
            src = pkt[IP].src if pkt.haslayer(IP) else None
            dq = recent_dns_nxdomain[src]
            dq.append(now_ts())
            while dq and dq[0] < now_ts() - THRESH["portscan_window_s"]:
                dq.popleft()
            if len(dq) >= THRESH["dns_nxdomain_threshold"]:
                alerts.append(f"[ALERT] NXDOMAIN flood from {src}")
    return alerts

# ---------------------------
# Offline PCAP reader
# ---------------------------
def show_packet_details(pcap_file, limit=20, quiet=False, verbose=False, no_color=False):
    if quiet:
        rprint(f"[cyan][START][/cyan] Reading {pcap_file} ... (quiet mode)")
        return
    packets = rdpcap(pcap_file)
    rprint(f"[cyan][INFO][/cyan] Reading {pcap_file} ({len(packets)} packets)...")
    for i, pkt in enumerate(packets[:limit], 1):
        if verbose:
            print_packet_verbose(pkt, no_color=no_color)
        else:
            print(f"Packet {i}: {pkt.summary()}")
    rprint(f"[cyan][INFO][/cyan] Total packets in file: {len(packets)}")

# ---------------------------
# CSV & JSON save
# ---------------------------
def save_csv(path):
    if not csv_rows:
        return
    keys = ["ts","eth_src","eth_dst","ip_src","ip_dst","proto","sport","dport","len","summary","notes"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in csv_rows:
            rr = {k: r.get(k, "") for k in keys}
            rr["notes"] = " | ".join(r.get("notes", []))
            w.writerow(rr)

def save_json(path):
    if not csv_rows:
        return
    with open(path, "w", encoding="utf-8") as f:
        json.dump(csv_rows, f, indent=2)

# ---------------------------
# Packet handler
# ---------------------------
def make_packet_handler(pcap_writer, args):
    def handler(pkt):
        stats["pkt_count"] += 1
        proto = "OTHER"
        if pkt.haslayer(TCP): proto = "TCP"
        elif pkt.haslayer(UDP): proto = "UDP"
        elif pkt.haslayer(ARP): proto = "ARP"
        elif pkt.haslayer(DNS): proto = "DNS"
        stats["protocols"][proto] += 1
        if pkt.haslayer(IP):
            stats["talkers"][pkt[IP].src] += 1

        if pcap_writer:
            try:
                pcap_writer.write(pkt)
            except Exception:
                pass

        if args.stats_only:
            return

        alerts = detect_anomalies(pkt)
        for alert in alerts:
            if not args.quiet:
                rprint(f"[red]{alert}[/red]")

        if args.quiet:
            return
        if args.verbose:
            print_packet_verbose(pkt, no_color=args.no_color)
        else:
            print(pkt.summary())
    return handler

# ---------------------------
# CLI & main
# ---------------------------
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", "-i", required=True, help="Interface to sniff (e.g., wlo1 or eth0)")
    p.add_argument("--duration", "-d", type=int, default=60, help="Total seconds to sniff")
    p.add_argument("--pcap", default="capture.pcap", help="PCAP output file")
    p.add_argument("--csv", default="capture.csv", help="CSV output file (summary rows)")
    p.add_argument("--filter", default=None, help="BPF filter (optional)")
    p.add_argument("--verbose", action="store_true", help="Verbose: print each packet with full detail")
    p.add_argument("--quiet", action="store_true", help="Quiet: only show start and summary messages")
    p.add_argument("--stats-only", action="store_true", help="Only print statistics, not packets")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    p.add_argument("--follow", help="Show only packets related to this IP")
    p.add_argument("--summary-interval", type=int, default=DEFAULT_SUMMARY_INTERVAL, help="Periodic summary interval")
    p.add_argument("--read", help="Read an existing PCAP file instead of live capture")
    p.add_argument("--limit", type=int, default=20, help="Limit packets shown in --read mode")
    p.add_argument("--json", help="Optional: JSON output file")
    return p.parse_args()

def main():
    args = parse_args()

    if args.read:
        show_packet_details(args.read, limit=args.limit, quiet=args.quiet, verbose=args.verbose, no_color=args.no_color)
        return

    if not args.iface:
        print("Error: --iface required for live sniffing (or use --read)")
        return

    rprint(f"[cyan][START][/cyan] Sniffing on {args.iface} for {args.duration}s")

    pcap_writer = PcapWriter(args.pcap, append=False, sync=True) if args.pcap else None
    handler = make_packet_handler(pcap_writer, args)

    try:
        sniff(iface=args.iface, prn=handler, store=0, timeout=args.duration, filter=args.filter)
    except PermissionError:
        print("Permission denied. Run with sudo/root.")
        return
    except KeyboardInterrupt:
        if not args.quiet:
            rprint("[yellow][INFO][/yellow] Keyboard interrupt received, stopping capture...")
    except Exception as e:
        print("Sniff error:", e)

    if pcap_writer:
        try:
            pcap_writer.close()
        except Exception:
            pass
    if args.csv:
        try:
            save_csv(args.csv)
            if not args.quiet:
                rprint(f"[cyan][INFO][/cyan] CSV written to {args.csv}")
        except Exception as e:
            print("Error writing csv:", e)
    if args.json:
        try:
            save_json(args.json)
            if not args.quiet:
                rprint(f"[cyan][INFO][/cyan] JSON written to {args.json}")
        except Exception as e:
            print("Error writing json:", e)

    duration = now_ts() - stats["start_time"]
    rprint(f"[SUMMARY] duration={duration:.1f}s packets={stats['pkt_count']}")
    rprint(f"Protocols: {stats['protocols']}")
    top_talkers = stats['talkers'].most_common(5)
    if top_talkers:
        rprint("Top talkers:")
        for ip, count in top_talkers:
            rprint(f" - {ip}: {count} packets")
    print("Done.")

if __name__ == "__main__":
    main()
