import argparse
import sys
import time

from ids.config import load_config
from ids.detectors import IDSDetectors
from ids.interface_picker import pick_interface_cross_platform
from ids.logger import EventLogger
from ids.sniffer import IDSSniffer


def parse_args():
    parser = argparse.ArgumentParser(description="Smart IDS v1.2")
    parser.add_argument("--config", default="configs/default.json", help="Path to config JSON")
    parser.add_argument("--iface-mode", choices=["auto", "index"], help="Override interface_mode")
    parser.add_argument("--iface-index", type=int, help="Override interface_index")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cfg = load_config(args.config)

    if args.iface_mode:
        cfg.interface_mode = args.iface_mode
    if args.iface_index is not None:
        cfg.interface_index = args.iface_index

    try:
        chosen_interface = pick_interface_cross_platform(
            mode=cfg.interface_mode,
            index=cfg.interface_index,
        )
    except Exception as exc:
        print("ERROR: Interface picker failed.")
        print(f"Details: {exc}")
        return 1

    logger = EventLogger(cfg.log_file_txt, cfg.log_file_jsonl)
    detectors = IDSDetectors(cfg, logger)
    sniffer = IDSSniffer(chosen_interface, cfg.bpf_filter, detectors)

    print("Starting Smart IDS v1.2...")
    print(f"Listening on: {chosen_interface}")
    print(f"Filter: {cfg.bpf_filter}")
    print(f"Logging TXT  -> {cfg.log_file_txt}")
    print(f"Logging JSON -> {cfg.log_file_jsonl}")
    print("Press Ctrl+C to stop...\n")

    try:
        sniffer.start()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping IDS...")
        sniffer.stop()
        return 0
    except PermissionError:
        print("\nERROR: Run the terminal with elevated privileges.")
        return 1
    except Exception as exc:
        print(f"\nERROR: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
