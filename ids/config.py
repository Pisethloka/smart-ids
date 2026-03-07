import json
import os
from dataclasses import dataclass
from typing import Set


@dataclass
class IDSConfig:
    suspicious_ports: Set[int]
    icmp_cooldown_sec: int
    scan_window_sec: int
    portscan_unique_ports: int
    synscan_syn_count: int
    bpf_filter: str
    log_file_txt: str
    log_file_jsonl: str
    interface_mode: str
    interface_index: int
    deque_maxlen: int


def load_config(path: str) -> IDSConfig:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)

    if not os.path.isabs(path):
        path = os.path.join(project_root, path)

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return IDSConfig(
        suspicious_ports=set(map(int, data.get("suspicious_ports", [23, 4444]))),
        icmp_cooldown_sec=int(data.get("icmp_cooldown_sec", 3)),
        scan_window_sec=int(data.get("scan_window_sec", 10)),
        portscan_unique_ports=int(data.get("portscan_unique_ports", 12)),
        synscan_syn_count=int(data.get("synscan_syn_count", 20)),
        bpf_filter=str(data.get("bpf_filter", "icmp or tcp")),
        log_file_txt=str(data.get("log_file_txt", "ids_log.txt")),
        log_file_jsonl=str(data.get("log_file_jsonl", "ids_log.jsonl")),
        interface_mode=str(data.get("interface_mode", "auto")),
        interface_index=int(data.get("interface_index", 0)),
        deque_maxlen=int(data.get("deque_maxlen", 2000)),
    )
