# pyids/detectors/synscan.py -- debug instrumented version
from __future__ import annotations
from collections import defaultdict, deque
from typing import Dict, Deque, Tuple, List
import time

from scapy.layers.inet import IP, TCP  # type: ignore

from pyids.detectors.base import Detector, Alert

def _ipv4_pair(pkt) -> Tuple[str | None, str | None]:
    if pkt.haslayer(IP):
        ip = pkt[IP]
        return ip.src, ip.dst
    return None, None

def _is_syn_only(pkt) -> bool:
    if not pkt.haslayer(TCP):
        return False
    flags = int(pkt[TCP].flags)
    syn = bool(flags & 0x02)
    ack = bool(flags & 0x10)
    return syn and not ack  # classic SYN (no ACK bit)

class SynFloodDetector(Detector):
    def __init__(self, window_sec: float = 5.0, syn_threshold: int = 100, cooldown_sec: float = 10.0, verbose: bool = False):
        self.window = window_sec
        self.thresh = syn_threshold
        self.cooldown = cooldown_sec
        self.buckets: Dict[str, Deque[float]] = defaultdict(deque)  # src_ip -> timestamps
        self.last_alert: Dict[str, float] = {}  # src_ip -> last alert time
        self.verbose = verbose

    def process(self, pkt, now: float) -> List[Alert]:
        src, dst = _ipv4_pair(pkt)
        if not src or not _is_syn_only(pkt):
            return []
        dq = self.buckets[src]
        dq.append(now)
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        count = len(dq)
        if self.verbose:
            print(f"[DBG][SYN] src={src} count={count} window={self.window}s thresh={self.thresh}")
        alerts: List[Alert] = []
        if count >= self.thresh:
            last = self.last_alert.get(src, 0.0)
            if now - last >= self.cooldown:
                self.last_alert[src] = now
                alerts.append(Alert(
                    kind="syn_flood",
                    severity="high",
                    message=f"SYN flood suspected from {src}: {count} SYNs in {self.window:.0f}s",
                    ts=now,
                    src=src,
                    dst=dst,
                    meta={"window_sec": self.window, "count": count, "threshold": self.thresh}
                ))
        return alerts

class PortScanDetector(Detector):
    def __init__(self, window_sec: float = 10.0, port_threshold: int = 20, cooldown_sec: float = 15.0, verbose: bool = False):
        self.window = window_sec
        self.thresh = port_threshold
        self.cooldown = cooldown_sec
        # map (src,dst) -> {port: last_seen_ts}
        from collections import defaultdict as _dd
        self.by_pair = _dd(dict)  # type: ignore
        self.last_alert: Dict[Tuple[str, str], float] = {}
        self.verbose = verbose

    def process(self, pkt, now: float) -> List[Alert]:
        if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
            return []
        ip = pkt[IP]; tcp = pkt[TCP]
        src, dst = ip.src, ip.dst
        if src is None or dst is None:
            return []
        pair = (src, dst)
        d = self.by_pair[pair]
        d[int(tcp.dport)] = now
        cutoff = now - self.window
        stale = [p for p, ts in list(d.items()) if ts < cutoff]
        for p in stale:
            del d[p]
        n_unique = len(d)
        if self.verbose:
            print(f"[DBG][SCAN] {src}->{dst} unique_ports={n_unique} window={self.window}s thresh={self.thresh}")
        alerts: List[Alert] = []
        if n_unique >= self.thresh:
            last = self.last_alert.get(pair, 0.0)
            if now - last >= self.cooldown:
                self.last_alert[pair] = now
                sample_ports = sorted(d.keys())[:10]
                alerts.append(Alert(
                    kind="port_scan",
                    severity="medium",
                    message=f"Port scan suspected: {src} -> {dst}, {n_unique} unique ports in {self.window:.0f}s",
                    ts=now,
                    src=src,
                    dst=dst,
                    meta={"window_sec": self.window, "unique_ports": n_unique, "threshold": self.thresh, "sample": sample_ports}
                ))
        return alerts

