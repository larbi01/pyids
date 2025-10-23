# pyids/core/sniffer.py
from __future__ import annotations
from datetime import datetime
from typing import Optional, Callable, Iterable
import sys
import time
from pyids.detectors.base import Detector, Alert

from scapy.all import sniff, conf, IFACES, Packet  # type: ignore

# Default BPF keeps it lightweight but useful
DEFAULT_BPF = "arp or icmp or (tcp and (port 22 or port 80 or port 443)) or (udp and port 53)"

def list_interfaces() -> list[tuple[str, str]]:
    """
    Return [(name, description), ...] for available interfaces.
    """
    out = []
    for n, iface in IFACES.items():
        # iface.name is the OS name, iface.description may be None
        out.append((iface.name, iface.description or ""))
    # dedupe & sort by name
    seen, unique = set(), []
    for name, desc in out:
        if name not in seen:
            seen.add(name)
            unique.append((name, desc))
    unique.sort(key=lambda t: t[0])
    return unique

def _default_callback(pkt: Packet) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    # Build a tiny summary line
    try:
        summary = pkt.summary()
    except Exception:
        summary = "<unprintable packet>"
    print(f"[{ts}] {summary}")


def make_detection_callback(detectors: Iterable[Detector], verbose_packets: bool = True):
    """
    Returns a Scapy 'prn' callback that feeds packets to detectors and prints alerts live.
    """
    def _cb(pkt):
        now = time.time()
        if verbose_packets:
            try:
                print(f"[pkt] {pkt.summary()}")
            except Exception:
                print("[pkt] <unprintable>")
        for det in detectors:
            try:
                alerts = det.process(pkt, now)
            except Exception as e:
                print(f"[detector err] {det.__class__.__name__}: {e}")
                continue
            for a in alerts:
                # compact single-line alert; later we’ll also log to SQLite/JSON
                print(f"[ALERT] {a.kind.upper()} sev={a.severity} src={a.src} dst={a.dst} msg='{a.message}' meta={a.meta}")
    return _cb



def run_sniffer(
    iface: str,
    bpf: Optional[str] = None,
    count: int = 0,
    promisc: bool = True,
    prn: Optional[Callable[[Packet], None]] = None,
) -> None:
    """
    Run a Scapy sniffer on a given iface.
    :param iface: OS interface name (e.g., 'eth0' or 'lo')
    :param bpf: Berkeley Packet Filter (e.g., 'tcp or arp'); if None, DEFAULT_BPF
    :param count: number of packets to capture (0 = infinite until Ctrl-C)
    :param promisc: promiscuous mode (True by default)
    :param prn: per-packet callback
    """
    if prn is None:
        prn = _default_callback

    filt = bpf if bpf is not None else DEFAULT_BPF

    print(f"[i] Sniffing on iface='{iface}'  filter='{filt}'  promisc={promisc}  count={count or '∞'}")
    print("[i] Press Ctrl-C to stop.")
    try:
        sniff(
            iface=iface,
            filter=filt,
            prn=prn,
            store=False,
            count=count,        # 0 means unlimited
            promisc=promisc,
        )
    except PermissionError:
        print("[!] Permission denied. Re-run with sudo (sniffing requires root).", file=sys.stderr)
    except OSError as e:
        print(f"[!] OS error: {e}. Check interface name / permissions.", file=sys.stderr)
