import time
from collections import defaultdict, deque
from typing import Dict, Tuple

from scapy.all import ICMP, TCP

from .config import IDSConfig
from .logger import EventLogger
from .utils import cleanup_old_entries


class IDSDetectors:
    def __init__(self, cfg: IDSConfig, logger: EventLogger):
        self.cfg = cfg
        self.log = logger

        # Anti-spam
        self._last_icmp: Dict[Tuple[str, str], float] = {}

        # Recent activity
        self._recent_ports_by_src = defaultdict(lambda: deque(maxlen=cfg.deque_maxlen))
        self._recent_syn_by_src = defaultdict(lambda: deque(maxlen=cfg.deque_maxlen))

        # Optional: scan alert cooldown to reduce repeated HIGH spam
        self._last_scan_alert: Dict[str, float] = {}
        self._scan_alert_cooldown_sec = 5

    # ---------- ICMP ----------
    def handle_icmp(self, packet, src_ip: str, dst_ip: str) -> None:
        # ---- DEBUG (TEMP) ----
        try:
            icmp_layer = packet[ICMP]
            print(f"[DBG ICMP] {src_ip} -> {dst_ip} type={int(icmp_layer.type)} code={int(icmp_layer.code)}")
        except Exception:
            pass
        # ----------------------

        key = (src_ip, dst_ip)
        t = time.time()
        last = self._last_icmp.get(key, 0)

        if t - last < self.cfg.icmp_cooldown_sec:
            return

        self._last_icmp[key] = t

        icmp_type = int(packet[ICMP].type)
        icmp_code = int(packet[ICMP].code)

        self.log.log(
            severity="LOW",
            event_type="ICMP",
            message=f"ICMP type={icmp_type} code={icmp_code} from {src_ip} to {dst_ip}",
            src_ip=src_ip,
            dst_ip=dst_ip,
            extra={"icmp_type": icmp_type, "icmp_code": icmp_code},
        )

    # ---------- PORT SCAN ----------
    def _can_scan_alert(self, src_ip: str) -> bool:
        t = time.time()
        last = self._last_scan_alert.get(src_ip, 0)
        if t - last >= self._scan_alert_cooldown_sec:
            self._last_scan_alert[src_ip] = t
            return True
        return False

    def detect_portscan(self, src_ip: str) -> None:
        dq = self._recent_ports_by_src[src_ip]
        cleanup_old_entries(dq, self.cfg.scan_window_sec)

        unique_ports = {dport for (ts, dport) in dq}
        if len(unique_ports) >= self.cfg.portscan_unique_ports and self._can_scan_alert(src_ip):
            self.log.log(
                severity="HIGH",
                event_type="PORT_SCAN",
                message=f"{src_ip} touched {len(unique_ports)} unique ports in {self.cfg.scan_window_sec}s",
                src_ip=src_ip,
                extra={
                    "unique_ports_count": len(unique_ports),
                    "window_sec": self.cfg.scan_window_sec,
                },
            )
            dq.clear()

    # ---------- SYN SCAN ----------
    def detect_syn_scan(self, src_ip: str) -> None:
        dq = self._recent_syn_by_src[src_ip]
        cleanup_old_entries(dq, self.cfg.scan_window_sec)

        if len(dq) >= self.cfg.synscan_syn_count and self._can_scan_alert(src_ip):
            self.log.log(
                severity="HIGH",
                event_type="SYN_SCAN",
                message=f"{src_ip} sent {len(dq)} SYN packets in {self.cfg.scan_window_sec}s",
                src_ip=src_ip,
                extra={"syn_count": len(dq), "window_sec": self.cfg.scan_window_sec},
            )
            dq.clear()

    # ---------- TCP ----------
    def handle_tcp(self, packet, src_ip: str, dst_ip: str) -> None:
        tcp = packet[TCP]
        sport = int(tcp.sport)
        dport = int(tcp.dport)

        # ---- DEBUG (TEMP) ----
        # This prints to the TERMINAL where you launched `ui.py`
        try:
            print(f"[DBG TCP] {src_ip}:{sport} -> {dst_ip}:{dport} flags={tcp.flags}")
        except Exception:
            pass
        # ----------------------

        # Track ports for port scan detection
        self._recent_ports_by_src[src_ip].append((time.time(), dport))
        self.detect_portscan(src_ip)

        # SYN-only detection (SYN set, ACK not set)
        flags = int(tcp.flags)
        is_syn = (flags & 0x02) != 0
        is_ack = (flags & 0x10) != 0

        if is_syn and not is_ack:
            self._recent_syn_by_src[src_ip].append(time.time())
            self.detect_syn_scan(src_ip)

        # Suspicious ports
        if dport in self.cfg.suspicious_ports:
            self.log.log(
                severity="MEDIUM",
                event_type="SUSPICIOUS_PORT",
                message=f"dport={dport} from {src_ip}:{sport} -> {dst_ip}:{dport}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                extra={"sport": sport, "dport": dport},
            )

        # Optional info print
        if dport == 80:
            print(f"[*] HTTP traffic {src_ip}:{sport} -> {dst_ip}:{dport}")