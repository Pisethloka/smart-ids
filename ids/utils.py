import datetime
import time
from collections import deque


def now_ts() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def cleanup_old_entries(dq: deque, window_sec: int) -> None:
    now = time.time()
    while dq:
        item = dq[0]
        ts = item[0] if isinstance(item, tuple) else item
        if now - ts > window_sec:
            dq.popleft()
        else:
            break


def is_private_ipv4(ip: str) -> bool:
    """Basic private IPv4 check for Windows interface filtering."""
    if not isinstance(ip, str) or "." not in ip:
        return False

    if ip.startswith("10.") or ip.startswith("192.168."):
        return True

    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2 and parts[1].isdigit():
            second = int(parts[1])
            return 16 <= second <= 31

    return False
