import json
from typing import Any, Callable, Dict, Optional

from .utils import now_ts


class EventLogger:
    def __init__(
        self,
        txt_path: str,
        jsonl_path: str,
        ui_callback: Optional[Callable[[dict], None]] = None,
    ):
        self.txt_path = txt_path
        self.jsonl_path = jsonl_path
        self.ui_callback = ui_callback

    def log(
        self,
        severity: str,
        event_type: str,
        message: str,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        line = f"[{now_ts()}] {severity}: {event_type} - {message}"
        print(line)

        # TXT
        try:
            with open(self.txt_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as e:
            print(f"[{now_ts()}] WARN: Could not write TXT log: {e}")

        # JSONL
        record = {
            "time": now_ts(),
            "severity": severity,
            "type": event_type,
            "message": message,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
        }
        if extra:
            record["extra"] = extra

        try:
            with open(self.jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as e:
            print(f"[{now_ts()}] WARN: Could not write JSON log: {e}")

        # Send to UI (if provided)
        if self.ui_callback:
            try:
                self.ui_callback(record)
            except Exception:
                pass
