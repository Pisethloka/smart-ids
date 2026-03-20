from scapy.all import ICMP, IP, TCP, UDP, AsyncSniffer

from .detectors import IDSDetectors


class IDSSniffer:
    def __init__(self, iface: str, bpf_filter: str, detectors: IDSDetectors):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.detectors = detectors
        self._sniffer = None

    def packet_callback(self, packet) -> None:
        try:
            if not packet.haslayer(IP):
                return

            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst

            self.detectors.log.emit_ui_event(
                {
                    "time": "",
                    "severity": "INFO",
                    "type": "PACKET",
                    "message": "",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                }
            )

            if packet.haslayer(ICMP):
                self.detectors.handle_icmp(packet, src_ip, dst_ip)
                return

            if packet.haslayer(TCP):
                self.detectors.handle_tcp(packet, src_ip, dst_ip)
                return

            if packet.haslayer(UDP):
                self.detectors.handle_udp(packet, src_ip, dst_ip)

        except Exception as e:
            self.detectors.log.emit_ui_event(
                {
                    "time": "",
                    "severity": "HIGH",
                    "type": "ERROR",
                    "message": f"packet_callback error: {e}",
                }
            )

    def start(self) -> None:
        kwargs = {
            "iface": self.iface,
            "prn": self.packet_callback,
            "store": False,
        }

        if self.bpf_filter and self.bpf_filter.strip():
            kwargs["filter"] = self.bpf_filter

        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None
