import platform
import subprocess


def _default_iface_linux() -> str | None:
    """
    Return the interface name used by the default route on Linux.
    Example: 'wlo1', 'eth0'
    """
    try:
        out = subprocess.check_output(["ip", "route"], text=True)
        for line in out.splitlines():
            if line.startswith("default "):
                parts = line.split()
                if "dev" in parts:
                    return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return None


def pick_interface_cross_platform(mode="auto", index=None):
    os_name = platform.system().lower()

    # ---------- Linux ----------
    if os_name == "linux":
        if mode == "auto":
            iface = _default_iface_linux()
            if not iface:
                raise RuntimeError("Could not detect default Linux interface (ip route).")
            return iface

        if mode == "index":
            # If you already have your own Linux index-list logic, keep it.
            # Simple version: read available ifaces from `ip -br link`
            out = subprocess.check_output(["ip", "-br", "link"], text=True)
            ifaces = [line.split()[0] for line in out.splitlines() if line.strip()]
            if index is None or index < 0 or index >= len(ifaces):
                raise ValueError(f"Invalid iface index {index}. Available: {ifaces}")
            return ifaces[index]

        raise ValueError("mode must be 'auto' or 'index'")

    # ---------- Windows ----------
    if os_name == "windows":
        # KEEP your existing Windows picker here.
        # Example placeholder:
        from ids.interface_win import pick_interface  # your existing code
        return pick_interface(mode=mode, index=index)

    # ---------- macOS (optional later) ----------
    raise RuntimeError(f"Unsupported OS: {os_name}")