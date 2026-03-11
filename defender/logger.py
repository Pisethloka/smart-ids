import json
from datetime import datetime
from shared.config import LOG_TEXT_FILE, LOG_JSON_FILE


class EventLogger:
    def __init__(self, text_file=LOG_TEXT_FILE, json_file=LOG_JSON_FILE):
        self.text_file = text_file
        self.json_file = json_file

    def log_text(self, level, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] [{level}] {message}"

        with open(self.text_file, "a", encoding="utf-8") as file:
            file.write(line + "\n")

        return line

    def log_event(self, level, event_type, src_ip, dst_ip, message):
        record = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "level": level,
            "event_type": event_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "message": message
        }

        with open(self.json_file, "a", encoding="utf-8") as file:
            file.write(json.dumps(record, ensure_ascii=False) + "\n")

        return record