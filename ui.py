import queue
import threading
import time
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

from ids.config import load_config
from ids.detectors import IDSDetectors
from ids.interface_picker import pick_interface_cross_platform
from ids.logger import EventLogger
from ids.sniffer import IDSSniffer


class IDSUI:
    """
    Smart IDS v1.2+ Cyber Dashboard UI (Tkinter)
    - Dark "SOC dashboard" theme
    - KPI cards (Total/HIGH/MED/LOW/Attackers/Packets)
    - Top attackers panel
    - Severity filter + search by IP
    - Thread-safe UI updates via queue only (no Tk calls from worker thread)
    """

    # ---------------- Theme ----------------
    COL_BG = "#0b0f19"
    COL_PANEL = "#111827"
    COL_PANEL_2 = "#0a1220"
    COL_BORDER = "#1f2937"
    COL_TEXT = "#e5e7eb"
    COL_MUTED = "#9ca3af"
    COL_RED = "#ef4444"
    COL_YELLOW = "#f59e0b"
    COL_GREEN = "#22c55e"
    COL_CYAN = "#22d3ee"
    COL_BLUE = "#60a5fa"

    FONT = ("Consolas", 12)
    FONT_TITLE = ("Consolas", 13, "bold")
    FONT_H2 = ("Consolas", 11, "bold")
    FONT_KPI = ("Consolas", 20, "bold")

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Smart IDS – Cyber Dashboard (v1.2)")
        self.root.geometry("1100x650")
        self.root.configure(bg=self.COL_BG)

        # Thread-safe queue: worker thread -> UI thread
        self.ui_queue: "queue.Queue[dict]" = queue.Queue()

        # IDS runtime state
        self.sniffer = None
        self.running = False

        # Counters / stats
        self.low_count = 0
        self.med_count = 0
        self.high_count = 0
        self.total_alerts = 0
        self.pkt_count = 0
        self._pkt_window_count = 0
        self._pkt_window_start = time.time()

        # Attacker stats:
        # ip -> {"alerts": int, "last": str, "last_type": str, "last_sev": str}
        self.attacker_stats = {}

        # UI vars
        self.status_var = tk.StringVar(value="STOPPED")
        self.iface_var = tk.StringVar(value="-")
        self.filter_var = tk.StringVar(value="-")
        self.pktrate_var = tk.StringVar(value="0.0/s")

        self.low_var = tk.StringVar(value="0")
        self.med_var = tk.StringVar(value="0")
        self.high_var = tk.StringVar(value="0")
        self.total_var = tk.StringVar(value="0")
        self.attackers_var = tk.StringVar(value="0")
        self.packets_var = tk.StringVar(value="0")

        self.last_alert_var = tk.StringVar(value="NO ALERTS YET!")

        # Filters
        self.sev_filter_var = tk.StringVar(value="ALL")
        self.search_var = tk.StringVar(value="")

        self._build_style()
        self._build_layout()

        # Poll queue regularly
        self.root.after(100, self.process_ui_queue)

        # Update packet rate every second
        self.root.after(1000, self.update_packet_rate)

        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    # ---------------- UI Building ----------------
    # ---------------- UI Building ----------------
    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "TCombobox",
            fieldbackground=self.COL_PANEL_2,
            background=self.COL_PANEL,
            foreground=self.COL_TEXT,
            bordercolor=self.COL_BORDER,
            arrowcolor=self.COL_RED,
        )

        # --- THE READONLY COLOR ---
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", self.COL_PANEL_2)],
            selectbackground=[("readonly", self.COL_PANEL_2)],
            selectforeground=[("readonly", self.COL_RED)],
        )

    def _panel(self, parent, pad=(10, 10), fill=tk.BOTH, expand=False):
        frame = tk.Frame(
            parent,
            bg=self.COL_PANEL,
            highlightthickness=1,
            highlightbackground=self.COL_BORDER,
        )
        frame.pack(fill=fill, expand=expand, padx=pad[0], pady=pad[1])
        return frame

    def _kpi_card(self, parent, title, var, color):
        card = tk.Frame(
            parent,
            bg=self.COL_PANEL,
            highlightthickness=1,
            highlightbackground=self.COL_BORDER,
        )
        card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        tk.Label(
            card, text=title, bg=self.COL_PANEL, fg=self.COL_MUTED, font=self.FONT
        ).pack(anchor="w", padx=10, pady=(8, 0))
        tk.Label(
            card, textvariable=var, bg=self.COL_PANEL, fg=color, font=self.FONT_KPI
        ).pack(anchor="w", padx=10, pady=(0, 8))
        return card

    def _build_layout(self):
        # ---------- Header ----------
        header = tk.Frame(self.root, bg=self.COL_BG)
        header.pack(fill=tk.X, padx=12, pady=(12, 6))

        tk.Label(
            header,
            text="SMART IDS — LIVE THREAT MONITOR",
            bg=self.COL_BG,
            fg=self.COL_TEXT,
            font=self.FONT_TITLE,
        ).pack(side=tk.LEFT)

        self.status_pill = tk.Label(
            header,
            textvariable=self.status_var,
            bg=self.COL_BORDER,
            fg=self.COL_MUTED,
            font=("Consolas", 10, "bold"),
            padx=10,
            pady=4,
        )
        self.status_pill.pack(side=tk.RIGHT)

        # ---------- Controls Row ----------
        controls = tk.Frame(self.root, bg=self.COL_BG)
        controls.pack(fill=tk.X, padx=12, pady=(0, 10))

        self.start_btn = tk.Button(
            controls,
            text="▶ Start IDS",
            width=12,
            command=self.start_ids,
            bg=self.COL_BLUE,
            fg="#081018",
            relief=tk.FLAT,
            font=("Consolas", 10, "bold"),
        )
        self.start_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.stop_btn = tk.Button(
            controls,
            text="■ Stop",
            width=12,
            command=self.stop_ids,
            state=tk.DISABLED,
            bg=self.COL_BORDER,
            fg=self.COL_TEXT,
            relief=tk.FLAT,
            font=("Consolas", 10, "bold"),
        )
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 12))

        info = tk.Frame(controls, bg=self.COL_BG)
        info.pack(side=tk.LEFT)

        tk.Label(
            info, text="iface:", bg=self.COL_BG, fg=self.COL_MUTED, font=self.FONT
        ).grid(row=0, column=0, sticky="w")
        tk.Label(
            info,
            textvariable=self.iface_var,
            bg=self.COL_BG,
            fg=self.COL_TEXT,
            font=self.FONT,
        ).grid(row=0, column=1, sticky="w", padx=(6, 16))
        tk.Label(
            info, text="filter:", bg=self.COL_BG, fg=self.COL_MUTED, font=self.FONT
        ).grid(row=0, column=2, sticky="w")
        tk.Label(
            info,
            textvariable=self.filter_var,
            bg=self.COL_BG,
            fg=self.COL_TEXT,
            font=self.FONT,
        ).grid(row=0, column=3, sticky="w", padx=(6, 16))
        tk.Label(
            info, text="pkts:", bg=self.COL_BG, fg=self.COL_MUTED, font=self.FONT
        ).grid(row=0, column=4, sticky="w")
        tk.Label(
            info,
            textvariable=self.pktrate_var,
            bg=self.COL_BG,
            fg=self.COL_CYAN,
            font=self.FONT,
        ).grid(row=0, column=5, sticky="w", padx=(6, 0))

        filters = tk.Frame(controls, bg=self.COL_BG)
        filters.pack(side=tk.RIGHT)

        tk.Label(
            filters, text="Show:", bg=self.COL_BG, fg=self.COL_MUTED, font=self.FONT
        ).pack(side=tk.LEFT, padx=(0, 6))
        self.sev_combo = ttk.Combobox(
            filters,
            values=["ALL", "HIGH", "MEDIUM", "LOW", "INFO"],
            textvariable=self.sev_filter_var,
            width=8,
            state="readonly",
            font=("Segoe UI", 11, "bold"),
        )
        self.sev_combo.pack(side=tk.LEFT, padx=(0, 10))

        tk.Label(
            filters,
            text="Search IP:",
            bg=self.COL_BG,
            fg=self.COL_MUTED,
            font=self.FONT,
        ).pack(side=tk.LEFT, padx=(0, 6))
        self.search_entry = tk.Entry(
            filters,
            textvariable=self.search_var,
            width=18,
            bg=self.COL_PANEL_2,
            fg=self.COL_TEXT,
            insertbackground=self.COL_TEXT,
            relief=tk.FLAT,
            highlightthickness=1,
            highlightbackground=self.COL_BORDER,
        )
        self.search_entry.pack(side=tk.LEFT)

        clear_btn = tk.Button(
            filters,
            text="Clear",
            command=self.clear_search,
            bg=self.COL_BORDER,
            fg=self.COL_TEXT,
            relief=tk.FLAT,
            padx=10,
        )
        clear_btn.pack(side=tk.LEFT, padx=(10, 0))

        # ---------- Main dashboard ----------
        main = tk.Frame(self.root, bg=self.COL_BG)
        main.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))

        left = tk.Frame(main, bg=self.COL_BG)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        right = tk.Frame(main, bg=self.COL_BG, width=330)
        right.pack(side=tk.RIGHT, fill=tk.Y)
        right.pack_propagate(False)

        kpi_row = tk.Frame(left, bg=self.COL_BG)
        kpi_row.pack(fill=tk.X, pady=(0, 10))

        self._kpi_card(kpi_row, "TOTAL ALERTS", self.total_var, self.COL_CYAN)
        self._kpi_card(kpi_row, "HIGH", self.high_var, self.COL_RED)
        self._kpi_card(kpi_row, "MEDIUM", self.med_var, self.COL_YELLOW)
        self._kpi_card(kpi_row, "LOW", self.low_var, self.COL_GREEN)
        self._kpi_card(kpi_row, "ATTACKERS", self.attackers_var, self.COL_BLUE)
        self._kpi_card(kpi_row, "PACKETS", self.packets_var, self.COL_TEXT)

        log_panel = self._panel(left, pad=(0, 0), expand=True)
        tk.Label(
            log_panel,
            text="LIVE EVENTS",
            bg=self.COL_PANEL,
            fg=self.COL_TEXT,
            font=self.FONT_H2,
        ).pack(anchor="w", padx=10, pady=(10, 6))

        self.log_box = ScrolledText(
            log_panel,
            bg=self.COL_PANEL_2,
            fg=self.COL_TEXT,
            insertbackground=self.COL_TEXT,
            relief=tk.FLAT,
            font=self.FONT,
            height=20,
        )
        self.log_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        self.log_box.tag_config("HIGH", foreground=self.COL_RED)
        self.log_box.tag_config("MEDIUM", foreground=self.COL_YELLOW)
        self.log_box.tag_config("LOW", foreground=self.COL_GREEN)
        self.log_box.tag_config("INFO", foreground=self.COL_MUTED)
        self.log_box.tag_config("DEBUG", foreground=self.COL_BLUE)

        last_panel = self._panel(right, pad=(0, (0, 10)), fill=tk.X, expand=False)
        tk.Label(
            last_panel,
            text="LAST ALERT",
            bg=self.COL_PANEL,
            fg=self.COL_TEXT,
            font=self.FONT_H2,
        ).pack(anchor="w", padx=10, pady=(10, 6))

        self.last_alert_lbl = tk.Label(
            last_panel,
            textvariable=self.last_alert_var,
            bg=self.COL_PANEL_2,
            fg=self.COL_CYAN,
            font=self.FONT,
            justify="left",
            wraplength=300,
            padx=10,
            pady=10,
        )
        self.last_alert_lbl.pack(fill=tk.X, padx=10, pady=(0, 10))

        atk_panel = self._panel(right, pad=(0, (0, 10)), fill=tk.BOTH, expand=True)
        tk.Label(
            atk_panel,
            text="TOP ATTACKERS",
            bg=self.COL_PANEL,
            fg=self.COL_TEXT,
            font=self.FONT_H2,
        ).pack(anchor="w", padx=10, pady=(10, 6))

        self.atk_list = ScrolledText(
            atk_panel,
            bg=self.COL_PANEL_2,
            fg=self.COL_TEXT,
            insertbackground=self.COL_TEXT,
            relief=tk.FLAT,
            font=self.FONT,
            height=12,
        )
        self.atk_list.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.atk_list.config(state=tk.DISABLED)

        tips_panel = self._panel(right, pad=(0, 0), fill=tk.X, expand=False)
        tk.Label(
            tips_panel,
            text="QUICK TESTS",
            bg=self.COL_PANEL,
            fg=self.COL_TEXT,
            font=self.FONT_H2,
        ).pack(anchor="w", padx=100, pady=(2, 2))

        tips = (
            "• ICMP: ping -c 3 8.8.8.8\n"
            "• Port scan: nmap -Pn -T4 -p 1-200 <target>\n"
            "• SYN scan: sudo nmap -sS -Pn -T4 -p 1-200 <target>\n"
            "• Suspicious: scan/try port 23 or 4444\n"
        )
        tk.Label(
            tips_panel,
            text=tips,
            bg=self.COL_PANEL_2,
            fg=self.COL_MUTED,
            font=self.FONT,
            justify="left",
            padx=10,
            pady=10,
        ).pack(fill=tk.X, padx=2, pady=(0, 10))

    # ---------------- UI helpers ----------------
    def clear_search(self):
        self.search_var.set("")

    def _set_status_running(self, running: bool):
        if running:
            self.status_var.set("RUNNING")
            self.status_pill.configure(bg="#052e1a", fg=self.COL_GREEN)
        else:
            self.status_var.set("STOPPED")
            self.status_pill.configure(bg=self.COL_BORDER, fg=self.COL_MUTED)

    def log_line(self, msg: str, tag: str = "INFO"):
        self.log_box.configure(state="normal")
        self.log_box.insert(tk.END, msg + "\n", tag)
        self.log_box.see(tk.END)
        self.log_box.configure(state="disabled")

    def ui_event_callback(self, event: dict):
        self.ui_queue.put(event)

    def refresh_attackers(self):
        top = sorted(
            self.attacker_stats.items(),
            key=lambda kv: kv[1].get("alerts", 0),
            reverse=True,
        )[:10]

        self.atk_list.config(state=tk.NORMAL)
        self.atk_list.delete("1.0", tk.END)

        if not top:
            self.atk_list.insert(tk.END, "No attacker data yet.\n")
        else:
            for ip, st in top:
                alerts = st.get("alerts", 0)
                last = st.get("last", "")
                last_type = st.get("last_type", "")
                last_sev = st.get("last_sev", "")

                self.atk_list.insert(tk.END, f"{ip}\n")
                self.atk_list.insert(
                    tk.END,
                    f"  alerts: {alerts}   last: {last}\n  type: {last_type}   sev: {last_sev}\n\n",
                )

        self.atk_list.config(state=tk.DISABLED)

    # ---------------- Queue processing ----------------
    def process_ui_queue(self):
        try:
            while True:
                event = self.ui_queue.get_nowait()

                sev = str(event.get("severity", "INFO"))
                typ = str(event.get("type", "EVENT"))
                msg = str(event.get("message", ""))
                ts = str(event.get("time", ""))

                if typ == "PACKET":
                    self.pkt_count += 1
                    self._pkt_window_count += 1
                    self.packets_var.set(str(self.pkt_count))
                    continue

                if typ == "UI" and msg == "__RESET_BUTTONS__":
                    self.running = False
                    self.start_btn.config(state=tk.NORMAL)
                    self.stop_btn.config(state=tk.DISABLED)
                    self._set_status_running(False)
                    continue

                if typ == "UIINFO":
                    self.iface_var.set(str(event.get("message", "-")))
                    self.filter_var.set(str(event.get("extra", {}).get("filter", "-")))
                    continue

                if sev in ("LOW", "MEDIUM", "HIGH"):
                    self.total_alerts += 1
                    self.total_var.set(str(self.total_alerts))

                    if sev == "LOW":
                        self.low_count += 1
                        self.low_var.set(str(self.low_count))
                    elif sev == "MEDIUM":
                        self.med_count += 1
                        self.med_var.set(str(self.med_count))
                    elif sev == "HIGH":
                        self.high_count += 1
                        self.high_var.set(str(self.high_count))

                    src_ip = event.get("src_ip", "?")
                    self.last_alert_var.set(f"{sev} — {typ}\nfrom {src_ip}\n{msg}")
                    if sev == "HIGH":
                        self.last_alert_lbl.configure(fg=self.COL_RED)
                    elif sev == "MEDIUM":
                        self.last_alert_lbl.configure(fg=self.COL_YELLOW)
                    else:
                        self.last_alert_lbl.configure(fg=self.COL_GREEN)

                    if src_ip and src_ip != "?":
                        st = self.attacker_stats.get(
                            src_ip,
                            {"alerts": 0, "last": "", "last_type": "", "last_sev": ""},
                        )
                        st["alerts"] += 1
                        st["last"] = ts
                        st["last_type"] = typ
                        st["last_sev"] = sev
                        self.attacker_stats[src_ip] = st
                        self.attackers_var.set(str(len(self.attacker_stats)))
                        self.refresh_attackers()

                if not self._passes_filters(event):
                    continue

                tag = sev if sev in ("LOW", "MEDIUM", "HIGH", "INFO") else "INFO"
                if typ == "DEBUG":
                    tag = "DEBUG"

                icon = {"HIGH": "🚨", "MEDIUM": "🟠", "LOW": "🟢", "INFO": "•"}.get(
                    sev, "•"
                )
                line = f"[{ts}] {icon} {sev}: {typ} - {msg}"
                self.log_line(line, tag=tag)

        except queue.Empty:
            pass

        self.root.after(100, self.process_ui_queue)

    def _passes_filters(self, event: dict) -> bool:
        sev_filter = self.sev_filter_var.get().strip().upper()
        search = self.search_var.get().strip()

        sev = str(event.get("severity", "INFO")).upper()
        if sev_filter != "ALL" and sev != sev_filter:
            return False

        if search:
            src_ip = str(event.get("src_ip", ""))
            dst_ip = str(event.get("dst_ip", ""))
            msg = str(event.get("message", ""))
            if search not in src_ip and search not in dst_ip and search not in msg:
                return False

        return True

    # ---------------- Packet rate ----------------
    def update_packet_rate(self):
        now = time.time()
        elapsed = max(0.001, now - self._pkt_window_start)

        rate = self._pkt_window_count / elapsed
        self.pktrate_var.set(f"{rate:.1f}/s")

        self._pkt_window_start = now
        self._pkt_window_count = 0

        self.root.after(1000, self.update_packet_rate)

    # ---------------- IDS control ----------------
    def start_ids(self):
        if self.running:
            return

        self.running = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self._set_status_running(True)

        t = threading.Thread(target=self.run_ids, daemon=True)
        t.start()

    def stop_ids(self):
        if not self.running:
            return

        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self._set_status_running(False)

        if self.sniffer:
            try:
                self.sniffer.stop()
                self.ui_queue.put(
                    {
                        "time": self._now_str(),
                        "severity": "INFO",
                        "type": "STATUS",
                        "message": "IDS stopped.",
                    }
                )
            except Exception as e:
                self.ui_queue.put(
                    {
                        "time": self._now_str(),
                        "severity": "HIGH",
                        "type": "ERROR",
                        "message": f"Stop error: {e}",
                    }
                )
            finally:
                self.sniffer = None

    def _now_str(self):
        return time.strftime("%Y-%m-%d %H:%M:%S")

    # ---------------- Background IDS thread ----------------
    def run_ids(self):
        try:
            cfg = load_config("configs/default.json")

            iface = pick_interface_cross_platform(
                mode=cfg.interface_mode, index=cfg.interface_index
            )

            self.ui_queue.put(
                {
                    "time": "",
                    "severity": "INFO",
                    "type": "DEBUG",
                    "message": f"cfg: mode={cfg.interface_mode}, index={cfg.interface_index}, filter={cfg.bpf_filter}",
                }
            )

            logger = EventLogger(
                cfg.log_file_txt, cfg.log_file_jsonl, ui_callback=self.ui_event_callback
            )
            detectors = IDSDetectors(cfg, logger)
            self.sniffer = IDSSniffer(iface, cfg.bpf_filter, detectors)

            self.ui_queue.put(
                {
                    "time": "",
                    "severity": "INFO",
                    "type": "STATUS",
                    "message": f"Listening on: {iface} | filter={cfg.bpf_filter}",
                }
            )

            self.ui_queue.put(
                {
                    "time": "",
                    "severity": "INFO",
                    "type": "UIINFO",
                    "message": iface,
                    "extra": {"filter": cfg.bpf_filter},
                }
            )

            self.sniffer.start()

        except Exception as e:
            self.ui_queue.put(
                {"time": "", "severity": "HIGH", "type": "ERROR", "message": str(e)}
            )
            self.ui_queue.put(
                {
                    "time": "",
                    "severity": "INFO",
                    "type": "UI",
                    "message": "__RESET_BUTTONS__",
                }
            )

    # ---------------- Close ----------------
    def on_close(self):
        try:
            self.stop_ids()
        except Exception:
            pass
        self.root.destroy()

    # ---------------- Run ----------------
    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    IDSUI().run()
