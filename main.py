import argparse
import sys

from ids.config import load_config
from ids.detectors import IDSDetectors
from ids.logger import EventLogger
from ids.sniffer import IDSSniffer


def parse_args():
    ap = argparse.ArgumentParser(description="Smart IDS v1.0 (Scapy)")
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

    # Apply CLI overrides (if provided)
    if args.iface_mode:
        cfg.interface_mode = args.iface_mode
    if args.iface_index is not None:
        cfg.interface_index = args.iface_index

    # Windows interface picker import here so project can still be extended later for Linux/macOS
    try:
        from ids.interface_win import pick_interface
    except Exception as e:
        print("ERROR: Windows interface picker failed to import.")
        print("Make sure you are on Windows + have scapy installed correctly.")
        print(f"Details: {e}")
        sys.exit(1)

    print("Starting Smart IDS v1.0 ...")

    chosen_interface = pick_interface(
        mode=cfg.interface_mode, index=cfg.interface_index
    )
    logger = EventLogger(cfg.log_file_txt, cfg.log_file_jsonl)
    detectors = IDSDetectors(cfg, logger)
    sniffer = IDSSniffer(chosen_interface, cfg.bpf_filter, detectors)

    print(f"\nListening on: {chosen_interface}")
    print(f"Filter: {cfg.bpf_filter}")
    print(f"Logging TXT  -> {cfg.log_file_txt}")
    print(f"Logging JSON -> {cfg.log_file_jsonl}")
    print("Press Ctrl+C to stop...\n")

    try:
        sniffer.run()
    except KeyboardInterrupt:
        print("\nIDS stopped.")
    except PermissionError:
        print("\nERROR: Run PowerShell as Administrator.")
    except Exception as e:
        print(f"\nERROR: {e}")


if __name__ == "__main__":
    main()
