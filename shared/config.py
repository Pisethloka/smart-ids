import json
import os


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(BASE_DIR, "configs")
DEFAULT_CONFIG_PATH = os.path.join(CONFIG_DIR, "default.json")


def load_config(config_path=DEFAULT_CONFIG_PATH):
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as file:
        return json.load(file)


CONFIG = load_config()

APP_NAME = CONFIG.get("app_name", "SMART-IDS")
LOG_TEXT_FILE = os.path.join(BASE_DIR, CONFIG.get("log_text_file", "ids_log.txt"))
LOG_JSON_FILE = os.path.join(BASE_DIR, CONFIG.get("log_json_file", "ids_log.jsonl"))
UI_REFRESH_MS = CONFIG.get("ui_refresh_ms", 250)

DETECTION = CONFIG.get("detection", {})
DEFAULTS = CONFIG.get("defaults", {})