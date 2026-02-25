import queue
import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

from ids.config import load_config
from ids.detectors import IDSDetectors
from ids.interface_win import pick_interface
from ids.logger import EventLogger
from ids.sniffer import IDSSniffer


class IDSUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Smart IDS v1.2 (Live UI)")
        self.root.geometry("850x550")

        # --- Queue for thread-safe UI updates ---
        self.ui_queue = queue.Queue()

        # --- Top controls frame ---
        top = tk.Frame(self.root)
        top.pack(fill=tk.X, pady=8)

        self.start_btn = tk.Button(
            top, text="Start IDS", width=14, command=self.start_ids
        )
        self.start_btn.pack(side=tk.LEFT, padx=8)

        self.stop_btn = tk.Button(
            top, text="Stop IDS", width=14, command=self.stop_ids, state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=8)

        # --- Counters ---
        self.low_var = tk.StringVar(value="0")
        self.med_var = tk.StringVar(value="0")
        self.high_var = tk.StringVar(value="0")

        counter = tk.Frame(self.root)
        counter.pack(fill=tk.X, pady=5)

        tk.Label(counter, text="LOW:").pack(side=tk.LEFT, padx=(10, 2))
        tk.Label(counter, textvariable=self.low_var, width=5).pack(side=tk.LEFT)

        tk.Label(counter, text="MEDIUM:").pack(side=tk.LEFT, padx=(20, 2))
        tk.Label(counter, textvariable=self.med_var, width=5).pack(side=tk.LEFT)

        tk.Label(counter, text="HIGH:").pack(side=tk.LEFT, padx=(20, 2))
        tk.Label(counter, textvariable=self.high_var, width=5).pack(side=tk.LEFT)

        # --- Log box ---
        self.log_box = ScrolledText(self.root, height=26)
        self.log_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- IDS objects ---
        self.sniffer = None
        self.running = False
        self.low_count = 0
        self.med_count = 0
        self.high_count = 0

        # Poll queue regularly
        self.root.after(100, self.process_ui_queue)

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------- UI helpers ----------
    def log_line(self, msg: str):
        self.log_box.insert(tk.END, msg + "\n")
        self.log_box.see(tk.END)

    def ui_event_callback(self, event: dict):
        """
        Called from IDS thread via logger.
        Must NOT update Tk directly -> put event into queue.
        """
        self.ui_queue.put(event)

    def process_ui_queue(self):
        """Process queued events safely in Tk main thread."""
        try:
            while True:
                event = self.ui_queue.get_nowait()
                sev = event.get("severity", "INFO")
                typ = event.get("type", "EVENT")
                msg = event.get("message", "")
                ts = event.get("time", "")

                # Update counters
                if sev == "LOW":
                    self.low_count += 1
                    self.low_var.set(str(self.low_count))
                elif sev == "MEDIUM":
                    self.med_count += 1
                    self.med_var.set(str(self.med_count))
                elif sev == "HIGH":
                    self.high_count += 1
                    self.high_var.set(str(self.high_count))

                # Print line
                self.log_line(f"[{ts}] {sev}: {typ} - {msg}")

        except queue.Empty:
            pass

        self.root.after(100, self.process_ui_queue)

    # ---------- IDS control ----------
    def start_ids(self):
        if self.running:
            return

        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)

        self.log_line("Starting IDS...")

        t = threading.Thread(target=self.run_ids, daemon=True)
        t.start()

    def stop_ids(self):
        if not self.running:
            return

        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

        if self.sniffer:
            try:
                self.sniffer.stop()
                self.log_line("IDS stopped.")
            except Exception as e:
                self.log_line(f"Stop error: {e}")
            finally:
                self.sniffer = None

    # ---------- Background IDS ----------
    def run_ids(self):
        try:
            cfg = load_config("configs/default.json")
            iface = pick_interface(mode=cfg.interface_mode, index=cfg.interface_index)

            logger = EventLogger(
                cfg.log_file_txt, cfg.log_file_jsonl, ui_callback=self.ui_event_callback
            )
            detectors = IDSDetectors(cfg, logger)

            self.sniffer = IDSSniffer(iface, cfg.bpf_filter, detectors)

            # Send a UI message through queue (safe)
            self.ui_queue.put(
                {
                    "time": "",
                    "severity": "INFO",
                    "type": "STATUS",
                    "message": f"Listening on: {iface} | filter={cfg.bpf_filter}",
                }
            )

            self.sniffer.start()

        except Exception as e:
            self.ui_queue.put(
                {"time": "", "severity": "HIGH", "type": "ERROR", "message": str(e)}
            )
            self.running = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)

    def on_close(self):
        # Stop sniffer when closing window
        try:
            self.stop_ids()
        except Exception:
            pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    IDSUI().run()
