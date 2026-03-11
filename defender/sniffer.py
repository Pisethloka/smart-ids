import threading
import time
from scapy.all import sniff, IP, TCP, ICMP


class IDSSniffer:
    def __init__(self, interface, packet_callback, status_callback=None):
        self.interface = interface
        self.packet_callback = packet_callback
        self.status_callback = status_callback
        self._stop_event = threading.Event()
        self._thread = None

    def _handle_packet(self, packet):
        if self._stop_event.is_set():
            return

        if IP not in packet:
            return

        proto = "OTHER"
        dst_port = None

        if TCP in packet:
            proto = "TCP"
            dst_port = int(packet[TCP].dport)
        elif ICMP in packet:
            proto = "ICMP"

        packet_info = {
            "time": time.time(),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "proto": proto,
            "dst_port": dst_port
        }

        self.packet_callback(packet_info)

    def _run(self):
        try:
            if self.status_callback:
                self.status_callback(f"Monitoring on {self.interface}")

            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set()
            )
        except Exception as error:
            if self.status_callback:
                self.status_callback(f"Sniffer error: {error}")

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self.status_callback:
            self.status_callback("Monitoring stopped")