import platform
import subprocess
from typing import List


def _run_command(command: List[str]) -> str:
    return subprocess.check_output(command, text=True, stderr=subprocess.DEVNULL)


def _default_iface_linux() -> str | None:
    try:
        output = _run_command(["ip", "route"])
    except Exception:
        return None

    for line in output.splitlines():
        if not line.startswith("default "):
            continue
        parts = line.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    return None


def _list_linux_interfaces() -> List[str]:
    output = _run_command(["ip", "-br", "link"])
    return [line.split()[0] for line in output.splitlines() if line.strip()]


def pick_interface_cross_platform(mode: str = "auto", index: int | None = None) -> str:
    os_name = platform.system().lower()

    if os_name == "linux":
        if mode == "auto":
            iface = _default_iface_linux()
            if iface:
                return iface
            raise RuntimeError("Could not detect the default Linux interface.")

        if mode == "index":
            interfaces = _list_linux_interfaces()
            if index is None or index < 0 or index >= len(interfaces):
                raise ValueError(
                    f"Invalid interface index {index}. Available interfaces: {interfaces}"
                )
            return interfaces[index]

        raise ValueError("mode must be 'auto' or 'index'")

    if os_name == "windows":
        from ids.interface_win import pick_interface

        return pick_interface(mode=mode, index=index)

    raise RuntimeError(f"Unsupported OS: {os_name}")
