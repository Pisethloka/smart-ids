from scapy.all import ICMP, IP, TCP, AsyncSniffer, sniff

from .detectors import IDSDetectors


class IDSSniffer:
    def __init__(self, iface: str, bpf_filter: str, detectors: IDSDetectors):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.detectors = detectors
        self._sniffer = None

    def packet_callback(self, packet) -> None:
        print("[DBG] got packet:", packet.summary())

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
        kwargs = dict(
            iface=self.iface,
            prn=self.packet_callback,
            store=False,
        )
        # Only apply BPF filter if non-empty
        if self.bpf_filter and self.bpf_filter.strip():
            kwargs["filter"] = self.bpf_filter

        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer:
            self._sniffer.stop()
            self._sniffer = None
