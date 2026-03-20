import json
import os
import threading
import time


class EventLogger:
    def __init__(self, log_file_txt, log_file_jsonl, ui_callback=None):
        self.log_file_txt = log_file_txt
        self.log_file_jsonl = log_file_jsonl
        self.ui_callback = ui_callback
        self._lock = threading.Lock()

    def emit_ui_event(self, event: dict) -> None:
        if self.ui_callback:
            try:
                self.ui_callback(event)
            except Exception:
                pass

    def log(
        self,
        severity: str,
        event_type: str,
        message: str,
        src_ip: str = "",
        dst_ip: str = "",
        extra: dict | None = None,
    ) -> None:
        ts = time.strftime("%H:%M:%S")
        event = {
            "time": ts,
            "severity": severity,
            "type": event_type,
            "message": message,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "extra": extra or {},
        }

        os.makedirs(os.path.dirname(self.log_file_txt) or ".", exist_ok=True)
        os.makedirs(os.path.dirname(self.log_file_jsonl) or ".", exist_ok=True)

        with self._lock:
            with open(self.log_file_txt, "a", encoding="utf-8") as f:
                f.write(f"[{ts}] [{severity}] {event_type} {message}\n")

            with open(self.log_file_jsonl, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")

        self.emit_ui_event(event)
