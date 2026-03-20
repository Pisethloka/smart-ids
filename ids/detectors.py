import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple

from scapy.all import ICMP, IP, TCP, UDP, Raw

from .config import IDSConfig
from .logger import EventLogger
from .utils import cleanup_old_entries


class IDSDetectors:
    def __init__(self, cfg: IDSConfig, logger: EventLogger):
        self.cfg = cfg
        self.log = logger

        self._last_icmp: Dict[Tuple[str, str], float] = {}
        self._recent_ports_by_src: Dict[str, Deque[Tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=cfg.deque_maxlen)
        )
        self._recent_syn_by_src: Dict[str, Deque[Tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=cfg.deque_maxlen)
        )

        self._last_scan_alert: Dict[Tuple[str, str], float] = {}
        self._last_port_alert: Dict[Tuple[str, int], float] = {}
        self._last_flag_alert: Dict[Tuple[str, str, int], float] = {}

        self._port_cleanup_at: Dict[str, float] = {}
        self._syn_cleanup_at: Dict[str, float] = {}

        self._scan_alert_cooldown_sec = 5
        self._suspicious_port_cooldown_sec = 2
        self._flag_alert_cooldown_sec = 5

    def _now(self) -> float:
        return time.time()

    def _can_alert_with_cooldown(
        self,
        store: Dict,
        key,
        cooldown_sec: float,
    ) -> bool:
        now = self._now()
        last = store.get(key, 0.0)
        if now - last < cooldown_sec:
            return False
        store[key] = now
        return True

    def _can_scan_alert(self, src_ip: str, alert_type: str) -> bool:
        return self._can_alert_with_cooldown(
            self._last_scan_alert,
            (src_ip, alert_type),
            self._scan_alert_cooldown_sec,
        )

    def handle_icmp(self, packet, src_ip: str, dst_ip: str) -> None:
        if not packet.haslayer(ICMP):
            return

        icmp = packet[ICMP]
        now = self._now()
        key = (src_ip, dst_ip)

        last = self._last_icmp.get(key, 0.0)
        if now - last < self.cfg.icmp_cooldown_sec:
            return

        self._last_icmp[key] = now

        icmp_type = int(icmp.type)
        icmp_code = int(icmp.code)

        self.log.log(
            severity="LOW",
            event_type="ICMP",
            message=f"ICMP type={icmp_type} code={icmp_code} from {src_ip} to {dst_ip}",
            src_ip=src_ip,
            dst_ip=dst_ip,
            extra={"icmp_type": icmp_type, "icmp_code": icmp_code},
        )

    def detect_portscan(self, src_ip: str) -> None:
        packets = self._recent_ports_by_src[src_ip]
        now = self._now()

        if now - self._port_cleanup_at.get(src_ip, 0.0) >= 1.0:
            cleanup_old_entries(packets, self.cfg.scan_window_sec)
            self._port_cleanup_at[src_ip] = now

        unique_ports = sorted({dport for _, dport in packets})
        unique_count = len(unique_ports)

        if unique_count < self.cfg.portscan_unique_ports:
            return

        if not self._can_scan_alert(src_ip, "PORT_SCAN"):
            return

        preview = ",".join(map(str, unique_ports[:10]))
        more = "..." if unique_count > 10 else ""

        self.log.log(
            severity="HIGH",
            event_type="PORT_SCAN",
            message=(
                f"{src_ip} touched {unique_count} unique ports "
                f"in {self.cfg.scan_window_sec}s [{preview}{more}]"
            ),
            src_ip=src_ip,
            extra={
                "unique_ports_count": unique_count,
                "window_sec": self.cfg.scan_window_sec,
                "ports_preview": unique_ports[:10],
            },
        )

        packets.clear()

    def detect_syn_activity(self, src_ip: str) -> None:
        packets = self._recent_syn_by_src[src_ip]
        now = self._now()

        if now - self._syn_cleanup_at.get(src_ip, 0.0) >= 1.0:
            cleanup_old_entries(packets, self.cfg.scan_window_sec)
            self._syn_cleanup_at[src_ip] = now

        syn_count = len(packets)
        unique_ports = sorted({dport for _, dport in packets})
        unique_count = len(unique_ports)

        if syn_count < self.cfg.synscan_syn_count:
            return

        if unique_count >= self.cfg.portscan_unique_ports:
            if not self._can_scan_alert(src_ip, "SYN_SCAN"):
                return

            preview = ",".join(map(str, unique_ports[:10]))
            more = "..." if unique_count > 10 else ""

            self.log.log(
                severity="HIGH",
                event_type="SYN_SCAN",
                message=(
                    f"{src_ip} sent {syn_count} SYN packets across "
                    f"{unique_count} ports in {self.cfg.scan_window_sec}s "
                    f"[{preview}{more}]"
                ),
                src_ip=src_ip,
                extra={
                    "syn_count": syn_count,
                    "unique_ports_count": unique_count,
                    "window_sec": self.cfg.scan_window_sec,
                    "ports_preview": unique_ports[:10],
                },
            )
            packets.clear()
            return

        if not self._can_scan_alert(src_ip, "SYN_BURST"):
            return

        target_port = unique_ports[0] if unique_ports else None
        self.log.log(
            severity="HIGH",
            event_type="SYN_BURST",
            message=(
                f"{src_ip} sent {syn_count} SYN packets to port {target_port} "
                f"in {self.cfg.scan_window_sec}s"
            ),
            src_ip=src_ip,
            extra={
                "syn_count": syn_count,
                "target_port": target_port,
                "window_sec": self.cfg.scan_window_sec,
            },
        )
        packets.clear()

    def detect_abnormal_tcp_flags(self, packet) -> None:
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return

        flags = packet[TCP].flags
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dport = int(packet[TCP].dport)

        if int(flags) == 0:
            if self._can_alert_with_cooldown(
                self._last_flag_alert,
                (src_ip, "NULL_SCAN", dport),
                self._flag_alert_cooldown_sec,
            ):
                self.log.log(
                    severity="HIGH",
                    event_type="NULL_SCAN",
                    message=f"NULL scan detected from {src_ip} -> {dst_ip}:{dport}",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    extra={"dport": dport},
                )
            return

        flag_str = str(flags)
        if all(flag in flag_str for flag in ("F", "P", "U")):
            if self._can_alert_with_cooldown(
                self._last_flag_alert,
                (src_ip, "XMAS_SCAN", dport),
                self._flag_alert_cooldown_sec,
            ):
                self.log.log(
                    severity="HIGH",
                    event_type="XMAS_SCAN",
                    message=f"XMAS scan detected from {src_ip} -> {dst_ip}:{dport}",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    extra={"dport": dport},
                )

    def handle_tcp(self, packet, src_ip: str, dst_ip: str) -> None:
        if not packet.haslayer(TCP):
            return

        tcp = packet[TCP]
        sport = int(tcp.sport)
        dport = int(tcp.dport)
        now = self._now()

        self.detect_abnormal_tcp_flags(packet)

        self._recent_ports_by_src[src_ip].append((now, dport))
        self.detect_portscan(src_ip)

        flags = int(tcp.flags)
        is_syn = bool(flags & 0x02)
        is_ack = bool(flags & 0x10)

        if is_syn and not is_ack:
            self._recent_syn_by_src[src_ip].append((now, dport))
            self.detect_syn_activity(src_ip)

        if dport in self.cfg.suspicious_ports:
            if self._can_alert_with_cooldown(
                self._last_port_alert,
                (src_ip, dport),
                self._suspicious_port_cooldown_sec,
            ):
                self.log.log(
                    severity="MEDIUM",
                    event_type="SUSPICIOUS_PORT",
                    message=f"dport={dport} from {src_ip}:{sport} -> {dst_ip}:{dport}",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    extra={"sport": sport, "dport": dport},
                )

    def handle_udp(self, packet, src_ip: str, dst_ip: str) -> None:
        if not packet.haslayer(UDP) or not packet.haslayer(Raw):
            return

        udp = packet[UDP]
        sport = int(udp.sport)
        dport = int(udp.dport)
        payload_len = len(packet[Raw].load)

        if payload_len < 32:
            return

        self.log.log(
            severity="MEDIUM",
            event_type="UDP_FUZZING",
            message=f"Large UDP payload ({payload_len} bytes) from {src_ip}:{sport} -> {dst_ip}:{dport}",
            src_ip=src_ip,
            dst_ip=dst_ip,
            extra={"sport": sport, "dport": dport, "payload_len": payload_len},
        )
