import sys
from typing import List, Tuple

from scapy.arch.windows import get_windows_if_list

from .utils import is_private_ipv4


def list_usable_interfaces() -> List[Tuple[dict, str]]:
    """
    Keep interfaces that:
    - have private IPv4
    - are Wi-Fi or Ethernet (common physical)
    """
    interfaces = get_windows_if_list()
    if not interfaces:
        return []

    usable = []
    for iface in interfaces:
        desc = (iface.get("description") or "").lower()
        ips = iface.get("ips") or []
        guid = iface.get("guid")

        if not guid or not ips:
            continue

        ipv4s = [ip for ip in ips if "." in ip and is_private_ipv4(ip)]
        if not ipv4s:
            continue

        if "wi-fi" not in desc and "wifi" not in desc and "ethernet" not in desc:
            continue

        usable.append((iface, ipv4s[0]))

    return usable


def pick_interface(mode: str = "auto", index: int = 0) -> str:
    usable = list_usable_interfaces()

    if not usable:
        print("No usable interfaces found (Wi-Fi/Ethernet with private IPv4).")
        print("Check Wi-Fi connection and Npcap install.")
        sys.exit(1)

    if mode == "auto":
        iface, ip = usable[0]
        print(f"Auto-selected interface: {iface.get('description')} ({ip})")
        return rf"\Device\NPF_{iface['guid']}"

    if mode == "index":
        print("\n--- Usable Network Interfaces ---")
        for i, (iface, ip) in enumerate(usable):
            print(f"{i}: {iface.get('description')} ({ip})")

        if index < 0 or index >= len(usable):
            print("Invalid interface_index in config/CLI.")
            sys.exit(1)

        iface = usable[index][0]
        return rf"\Device\NPF_{iface['guid']}"

    print("interface_mode must be 'auto' or 'index'.")
    sys.exit(1)
