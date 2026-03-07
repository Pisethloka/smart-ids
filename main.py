import argparse
import sys
import time

from ids.config import load_config
from ids.detectors import IDSDetectors
from ids.logger import EventLogger
from ids.sniffer import IDSSniffer


def parse_args():
    ap = argparse.ArgumentParser(description="Smart IDS v1.2 (Scapy)")
    ap.add_argument(
        "--config", default="configs/default.json", help="Path to config JSON"
    )
    ap.add_argument(
        "--iface-mode", choices=["auto", "index"], help="Override interface_mode"
    )
    ap.add_argument("--iface-index", type=int, help="Override interface_index")
    return ap.parse_args()


def main():
    args = parse_args()
    cfg = load_config(args.config)

    # Apply CLI overrides
    if args.iface_mode:
        cfg.interface_mode = args.iface_mode
    if args.iface_index is not None:
        cfg.interface_index = args.iface_index

    # Interface picker
    try:
        from ids.interface_picker import pick_interface_cross_platform

        chosen_interface = pick_interface_cross_platform(
            mode=cfg.interface_mode, index=cfg.interface_index
        )

    except Exception as e:
        print("ERROR: Interface picker failed.")
        print(f"Details: {e}")
        sys.exit(1)

    print("Starting Smart IDS v1.2 ...")

    logger = EventLogger(cfg.log_file_txt, cfg.log_file_jsonl)
    detectors = IDSDetectors(cfg, logger)
    sniffer = IDSSniffer(chosen_interface, cfg.bpf_filter, detectors)

    print(f"\nListening on: {chosen_interface}")
    print(f"Filter: {cfg.bpf_filter}")
    print(f"Logging TXT  -> {cfg.log_file_txt}")
    print(f"Logging JSON -> {cfg.log_file_jsonl}")
    print("Press Ctrl+C to stop...\n")

    try:
        sniffer.start()

        # Keep program alive while AsyncSniffer runs
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nStopping IDS...")
        sniffer.stop()

    except PermissionError:
        print("\nERROR: Run terminal as Administrator.")

    except Exception as e:
        print(f"\nERROR: {e}")


if __name__ == "__main__":
    main()
