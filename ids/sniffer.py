from scapy.all import ICMP, IP, TCP, AsyncSniffer, sniff

from .detectors import IDSDetectors


class IDSSniffer:
    def __init__(self, iface: str, bpf_filter: str, detectors: IDSDetectors):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.detectors = detectors
        self._sniffer = None

    def packet_callback(self, packet) -> None:
        if not packet.haslayer(IP):
            return

        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst

        if packet.haslayer(ICMP):
            self.detectors.handle_icmp(packet, src_ip, dst_ip)
            return

        if packet.haslayer(TCP):
            self.detectors.handle_tcp(packet, src_ip, dst_ip)
            return

    def start(self) -> None:
        # Async sniffer so we can stop cleanly
        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter=self.bpf_filter,
            prn=self.packet_callback,
            store=False,
        )
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None
