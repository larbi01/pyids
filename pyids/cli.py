# pyids/cli.py
import argparse
import sys

from pyids.core.sniffer import list_interfaces, run_sniffer, DEFAULT_BPF

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pyids",
        description="Lightweight Python IDS — Scapy-based (Section 1: sniffer foundation)"
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # pyids ifaces
    s1 = sub.add_parser("ifaces", help="List available interfaces")
    
    # pyids sniff --iface eth0 [--bpf ...] [--count N] [--no-promisc]
    s2 = sub.add_parser("sniff", help="Run a basic packet sniffer")
    s2.add_argument("--iface", required=True, help="Interface name (e.g., eth0, lo)")
    s2.add_argument("--bpf", default=DEFAULT_BPF, help=f"BPF filter (default: {DEFAULT_BPF})")
    s2.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    s2.add_argument("--no-promisc", action="store_true", help="Disable promiscuous mode")

    return p

def cmd_ifaces(_: argparse.Namespace) -> int:
    rows = list_interfaces()
    if not rows:
        print("No interfaces found.")
        return 1
    for name, desc in rows:
        print(f"{name:10s}  {desc}")
    return 0

def cmd_sniff(args: argparse.Namespace) -> int:
    promisc = not args.no_promisc
    run_sniffer(
        iface=args.iface,
        bpf=args.bpf,
        count=args.count,
        promisc=promisc,
    )
    return 0

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.cmd == "ifaces": return cmd_ifaces(args)
    if args.cmd == "sniff":  return cmd_sniff(args)
    print("Unknown command", file=sys.stderr)
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
