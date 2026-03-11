from collections import defaultdict, deque
from shared.config import DETECTION


class IDSDetectors:
    def __init__(self):
        self.port_scan_unique_ports = DETECTION.get("port_scan_unique_ports", 8)
        self.port_scan_window_sec = DETECTION.get("port_scan_window_sec", 8)

        self.icmp_burst_threshold = DETECTION.get("icmp_burst_threshold", 10)
        self.icmp_burst_window_sec = DETECTION.get("icmp_burst_window_sec", 5)

        self.tcp_burst_threshold = DETECTION.get("tcp_burst_threshold", 20)
        self.tcp_burst_window_sec = DETECTION.get("tcp_burst_window_sec", 5)

        self.alert_cooldown_sec = DETECTION.get("alert_cooldown_sec", 5)

        self.port_scan_tracker = defaultdict(deque)
        self.icmp_tracker = defaultdict(deque)
        self.tcp_tracker = defaultdict(deque)

        self.last_alert_time = {}

    def _cleanup(self, dq, now, window_sec):
        while dq and (now - dq[0][0]) > window_sec:
            dq.popleft()

    def _can_alert(self, key, now):
        last_time = self.last_alert_time.get(key, 0)
        if (now - last_time) >= self.alert_cooldown_sec:
            self.last_alert_time[key] = now
            return True
        return False

    def process_packet(self, packet_info):
        alerts = []

        now = packet_info["time"]
        src_ip = packet_info["src_ip"]
        dst_ip = packet_info["dst_ip"]
        proto = packet_info["proto"]
        dst_port = packet_info.get("dst_port")

        # Port scan detection:
        # same source touches many destination ports in a short time
        if proto == "TCP" and dst_port is not None:
            port_dq = self.port_scan_tracker[src_ip]
            port_dq.append((now, dst_port))
            self._cleanup(port_dq, now, self.port_scan_window_sec)

            unique_ports = {port for _, port in port_dq}
            if len(unique_ports) >= self.port_scan_unique_ports:
                key = f"PORTSCAN:{src_ip}"
                if self._can_alert(key, now):
                    alerts.append({
                        "severity": "MEDIUM",
                        "type": "Port Scan",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "message": f"Possible port scan from {src_ip} across {len(unique_ports)} ports"
                    })

        # ICMP burst detection:
        # fast repeated ping traffic
        if proto == "ICMP":
            icmp_dq = self.icmp_tracker[src_ip]
            icmp_dq.append((now, 1))
            self._cleanup(icmp_dq, now, self.icmp_burst_window_sec)

            if len(icmp_dq) >= self.icmp_burst_threshold:
                key = f"ICMPBURST:{src_ip}"
                if self._can_alert(key, now):
                    alerts.append({
                        "severity": "HIGH",
                        "type": "Ping Burst",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "message": f"Heavy ICMP traffic from {src_ip} ({len(icmp_dq)} packets in window)"
                    })

        # TCP burst detection:
        # repeated TCP attempts in a short window, even if connection fails
        if proto == "TCP":
            tcp_dq = self.tcp_tracker[src_ip]
            tcp_dq.append((now, 1))
            self._cleanup(tcp_dq, now, self.tcp_burst_window_sec)

            if len(tcp_dq) >= self.tcp_burst_threshold:
                key = f"TCPBURST:{src_ip}"
                if self._can_alert(key, now):
                    alerts.append({
                        "severity": "HIGH",
                        "type": "TCP Burst",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "message": f"High TCP activity from {src_ip} ({len(tcp_dq)} packets in window)"
                    })

        return alerts