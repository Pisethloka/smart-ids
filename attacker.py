import logging
import socket
import threading
import time

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ICMP, IP, TCP, send, sr1

# --- CONFIGURATION ---
# Change this to your machine's actual IP address (e.g., "192.168.10.9")
# Scapy on Windows sometimes ignores 127.0.0.1 (localhost)
TARGET_IP = "192.168.10.9"


def print_header(title):
    print(f"\n{'=' * 40}")
    print(f"[*] {title}")
    print(f"{'=' * 40}")


def test_icmp():
    print_header("Sending ICMP Pings")
    for i in range(3):
        print(f" -> Sending Ping {i + 1} to {TARGET_IP}...")
        packet = IP(dst=TARGET_IP) / ICMP()
        send(packet, verbose=False)
        time.sleep(0.5)
    print("[+] ICMP Test Complete.")


def test_suspicious_port(port=23):
    print_header(f"Touching Suspicious Port ({port})")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        print(f" -> Connecting to {TARGET_IP}:{port}...")
        s.connect((TARGET_IP, port))
        s.close()
    except Exception:
        pass  # We don't care if it connects, we just want the IDS to see the attempt
    print(f"[+] Suspicious Port {port} Test Complete.")


def test_port_scan():
    print_header("Simulating Port Scan (Ports 1-50)")
    # Your config needs 12 unique ports in 10 seconds to trigger HIGH
    for port in range(1, 51):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((TARGET_IP, port))
            s.close()
        except Exception:
            pass
    print("[+] Port Scan Simulation Complete.")


def test_syn_scan():
    print_header("Simulating SYN Flood / Scan")
    # Your config needs 20 SYN packets in 10 seconds to trigger HIGH
    print(f" -> Firing 25 SYN packets at {TARGET_IP}:80...")

    # Craft a pure SYN packet (Flags="S")
    packet = IP(dst=TARGET_IP) / TCP(dport=80, flags="S")

    # Send them rapidly
    send(packet, count=25, verbose=False)
    print("[+] SYN Scan Simulation Complete.")


def main_menu():
    while True:
        print("\n" + "=" * 40)
        print("   SMART IDS - ATTACK SIMULATOR v1.0")
        print("=" * 40)
        print(f"Target IP: {TARGET_IP}\n")
        print("1. Send ICMP Pings (LOW Severity)")
        print("2. Touch Suspicious Port 23 (MEDIUM Severity)")
        print("3. Simulate Fast Port Scan (HIGH Severity)")
        print("4. Simulate SYN Flood (HIGH Severity)")
        print("5. Run ALL Tests Sequence")
        print("0. Exit")

        choice = input("\nSelect an attack vector [0-5]: ")

        if choice == "1":
            test_icmp()
        elif choice == "2":
            test_suspicious_port(23)
            test_suspicious_port(4444)
        elif choice == "3":
            test_port_scan()
        elif choice == "4":
            test_syn_scan()
        elif choice == "5":
            test_icmp()
            time.sleep(2)
            test_suspicious_port(23)
            time.sleep(2)
            test_port_scan()
            time.sleep(2)
            test_syn_scan()
        elif choice == "0":
            print("Exiting simulator...")
            break
        else:
            print("Invalid selection.")


if __name__ == "__main__":
    main_menu()
