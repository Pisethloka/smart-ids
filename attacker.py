import ipaddress
import logging
import socket
import time

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import ICMP, IP, TCP, RandShort, send

# ── Color constants ────────────────────────────────────────────
R = "\033[1;91m"  # bright bold red  (matches ASCII art)
DR = "\033[31m"  # dark red
W = "\033[97m"  # white
RS = "\033[0m"  # reset
# ──────────────────────────────────────────────────────────────

ASCII_ART = """
\033[1;91m
  ██████  ███▄ ▄███▓ ▄▄▄       ██▀███  ▄▄▄█████▓    ██▓▓█████▄   ██████
▒██    ▒ ▓██▒▀█▀ ██▒▒████▄    ▓██ ▒ ██▒▓  ██▒ ▓▒   ▓██▒▒██▀ ██▌▒██    ▒
░ ▓██▄   ▓██    ▓██░▒██  ▀█▄  ▓██ ░▄█ ▒▒ ▓██░ ▒░   ▒██▒░██   █▌░ ▓██▄
  ▒   ██▒▒██    ▒██ ░██▄▄▄▄██ ▒██▀▀█▄  ░ ▓██▓ ░    ░██░░▓█▄   ▌  ▒   ██▒
▒██████▒▒▒██▒   ░██▒ ▓█   ▓██▒░██▓ ▒██▒  ▒██▒ ░    ░██░░▒████▓ ▒██████▒▒
▒ ▒▓▒ ▒ ░░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▒▓ ░▒▓░  ▒ ░░      ░▓   ▒▒▓  ▒ ▒ ▒▓▒ ▒ ░
░ ░▒  ░ ░░  ░      ░  ▒   ▒▒ ░  ░▒ ░ ▒░    ░        ▒ ░ ░ ▒  ▒ ░ ░▒  ░ ░
░  ░  ░  ░      ░     ░   ▒     ░░   ░   ░          ▒ ░ ░ ░  ░ ░  ░  ░
      ░         ░         ░  ░   ░                  ░     ░          ░
                                                        ░
\033[0m"""

SUBTITLE = (
    "\033[1;91m"
    "        ╔══════════════════════════════════════════════════╗\n"
    "        ║          A T T A C K   S I M U L A T O R         ║\n"
    "        ║          ===============================         ║\n"
    "        ║                S M A R T - I D S                 ║\n"
    "        ╚══════════════════════════════════════════════════╝"
    "\033[0m"
)


def print_banner() -> None:
    print(ASCII_ART)
    print(SUBTITLE)
    print()


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def get_target_ip() -> str:
    while True:
        ip = input(W + "Target IP: " + RS).strip()
        if is_valid_ip(ip):
            return ip
        print(R + "Invalid IP. Example: 192.168.1.10" + RS)


def banner(title: str) -> None:
    print(R + "\n" + "=" * 52 + RS)
    print(R + f"[*] {title}" + RS)
    print(R + "=" * 52 + RS)


def safe_tcp_connect(target_ip: str, port: int, timeout: float = 0.2) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((target_ip, port))
    except Exception:
        pass


def icmp_burst(target_ip: str, count: int = 10, interval: float = 0.15) -> None:
    banner("ICMP BURST")
    print(W + f"Target  : {target_ip}" + RS)
    print(W + f"Packets : {count}" + RS)
    send(IP(dst=target_ip) / ICMP(), count=count, inter=interval, verbose=False)
    print(R + "[+] ICMP burst sent." + RS)


def suspicious_ports(target_ip: str, repeats: int = 4) -> None:
    banner("SUSPICIOUS PORT PROBES")
    ports = [23, 4444, 23, 4444] * repeats
    print(W + f"Target   : {target_ip}" + RS)
    print(W + f"Attempts : {len(ports)}" + RS)

    for port in ports:
        safe_tcp_connect(target_ip, port, timeout=0.25)
        time.sleep(0.06)

    print(R + "[+] Suspicious port sequence complete." + RS)


def connect_port_scan(target_ip: str, start_port: int = 1, end_port: int = 30) -> None:
    banner("TCP CONNECT PORT SCAN")
    print(W + f"Target     : {target_ip}" + RS)
    print(W + f"Port range : {start_port}-{end_port}" + RS)

    for port in range(start_port, end_port + 1):
        safe_tcp_connect(target_ip, port, timeout=0.05)

    print(R + "[+] Connect scan complete." + RS)


def syn_scan(
    target_ip: str, start_port: int = 1, end_port: int = 30, delay: float = 0.02
) -> None:
    banner("TCP SYN SCAN")
    print(W + f"Target     : {target_ip}" + RS)
    print(W + f"Port range : {start_port}-{end_port}" + RS)

    packets = [
        IP(dst=target_ip) / TCP(sport=RandShort(), dport=port, flags="S")
        for port in range(start_port, end_port + 1)
    ]
    send(packets, inter=delay, verbose=False)
    print(R + "[+] SYN scan complete." + RS)


def syn_burst(
    target_ip: str, port: int = 80, count: int = 25, interval: float = 0.03
) -> None:
    banner("SYN BURST")
    print(W + f"Target  : {target_ip}:{port}" + RS)
    print(W + f"Packets : {count}" + RS)

    send(
        IP(dst=target_ip) / TCP(sport=RandShort(), dport=port, flags="S"),
        count=count,
        inter=interval,
        verbose=False,
    )
    print(R + "[+] SYN burst sent." + RS)


def full_test_sequence(target_ip: str) -> None:
    banner("FULL TEST SEQUENCE")
    icmp_burst(target_ip, count=8, interval=0.15)
    time.sleep(0.8)

    suspicious_ports(target_ip, repeats=3)
    time.sleep(0.8)

    connect_port_scan(target_ip, 1, 20)
    time.sleep(0.8)

    syn_scan(target_ip, 1, 20, delay=0.02)
    time.sleep(0.8)

    syn_burst(target_ip, port=80, count=20, interval=0.03)
    print(R + "[+] Full test sequence complete." + RS)


def local_demo_help() -> None:
    banner("LOCAL DEMO MODE")
    print(W + "Same-device real packet testing on Windows is unreliable.")
    print("Use one of these instead:" + RS)
    print(R + "  1." + W + " In the UI, click: SELF-TEST" + RS)
    print(R + "  2." + W + " Use your phone on the same Wi-Fi" + RS)
    print(R + "  3." + W + " Use another laptop/VM on the same network" + RS)
    print(R + "\nFor external-device testing:" + RS)
    print(W + "  - Run this attacker.py on another machine")
    print("  - Target your IDS PC's LAN IP")
    print("  - Or use nmap from Termux / another laptop" + RS)


def custom_attack(target_ip: str) -> None:
    print(R + "\nCustom attack options:" + RS)
    try:
        start_port = int(input(W + "Start port : " + RS).strip())
        end_port = int(input(W + "End port   : " + RS).strip())
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            print(R + "Invalid port range." + RS)
            return

        print(R + "\n  1." + W + " Custom connect scan" + RS)
        print(R + "  2." + W + " Custom SYN scan" + RS)
        print(R + "  3." + W + " Custom SYN burst" + RS)
        choice = input(R + "> " + RS).strip()

        if choice == "1":
            connect_port_scan(target_ip, start_port, end_port)
        elif choice == "2":
            syn_scan(target_ip, start_port, end_port)
        elif choice == "3":
            count = int(input(W + "Packet count: " + RS).strip())
            syn_burst(target_ip, port=start_port, count=count)
        else:
            print(R + "Invalid choice." + RS)
    except ValueError:
        print(R + "Invalid number entered." + RS)


def main() -> None:
    print_banner()
    print(R + "=" * 80 + RS)
    print(R + "  Tips:" + RS)
    print(W + "  - Best testing: another device -> your IDS PC")
    print("  - Windows same-device packet attacks can be unreliable")
    print("  - For same-device demo, use the UI SELF-TEST button" + RS)
    print(R + "=" * 80 + RS)

    target_ip = ""
    while True:
        print(R + "\n  Choose mode:" + RS)
        print(R + "  1." + W + " Set / change target IP" + RS)
        print(R + "  2." + W + " ICMP burst" + RS)
        print(R + "  3." + W + " Suspicious port probes" + RS)
        print(R + "  4." + W + " TCP connect port scan" + RS)
        print(R + "  5." + W + " TCP SYN scan" + RS)
        print(R + "  6." + W + " SYN burst" + RS)
        print(R + "  7." + W + " Full test sequence" + RS)
        print(R + "  8." + W + " Custom attack" + RS)
        print(R + "  9." + W + " Local demo help" + RS)
        print(R + "  0." + W + " Exit" + RS)

        if target_ip:
            print(R + f"\n  Current target: " + W + target_ip + RS)
        else:
            print(DR + "\n  Current target: not set" + RS)

        choice = input(R + "\n> " + RS).strip()

        if choice == "1":
            target_ip = get_target_ip()

        elif choice in {"2", "3", "4", "5", "6", "7", "8"}:
            if not target_ip:
                print(R + "Set target IP first." + RS)
                continue

            if choice == "2":
                icmp_burst(target_ip)
            elif choice == "3":
                suspicious_ports(target_ip)
            elif choice == "4":
                connect_port_scan(target_ip)
            elif choice == "5":
                syn_scan(target_ip)
            elif choice == "6":
                syn_burst(target_ip)
            elif choice == "7":
                full_test_sequence(target_ip)
            elif choice == "8":
                custom_attack(target_ip)

        elif choice == "9":
            local_demo_help()

        elif choice == "0":
            print(R + "\nExiting attacker. Goodbye." + RS)
            break

        else:
            print(R + "Invalid choice." + RS)


if __name__ == "__main__":
    main()
