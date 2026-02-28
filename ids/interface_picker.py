import platform
import sys

def pick_interface_cross_platform(mode="auto", index=0):
    os_name = platform.system().lower()

    # Windows
    if os_name == "windows":
        from ids.interface_win import pick_interface
        return pick_interface(mode=mode, index=index)

    # Linux / macOS
    from scapy.all import get_if_list

    ifaces = [i for i in get_if_list() if i != "lo"]

    if not ifaces:
        print("No usable interfaces found.")
        sys.exit(1)

    if mode == "auto":
        print(f"Auto-selected interface: {ifaces[0]}")
        return ifaces[0]

    if mode == "index":
        print("--- Interfaces ---")
        for i, name in enumerate(ifaces):
            print(f"{i}: {name}")

        if index < 0 or index >= len(ifaces):
            print("Invalid interface_index.")
            sys.exit(1)

        return ifaces[index]

    print("interface_mode must be 'auto' or 'index'.")
    sys.exit(1)
