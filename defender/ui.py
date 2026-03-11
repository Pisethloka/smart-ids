import os
import sys
import queue
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from defender.sniffer import IDSSniffer
from defender.detectors import IDSDetectors
from defender.logger import EventLogger
from shared.config import UI_REFRESH_MS, DEFAULTS


BG = "#040816"
TOP = "#0a1228"
PANEL = "#0b132b"
PANEL_2 = "#08101f"
BORDER = "#1d325e"

TEXT = "#d7e7ff"
TEXT_SOFT = "#9cb3d9"

CYAN = "#19e3ff"
BLUE = "#63a8ff"
RED = "#ff5a7a"
AMBER = "#ffb020"
GREEN = "#34e27a"


def style_treeview():
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass

    style.configure(
        "Cyber.Treeview",
        background=PANEL_2,
        foreground=TEXT,
        fieldbackground=PANEL_2,
        bordercolor=BORDER,
        lightcolor=BORDER,
        darkcolor=BORDER,
        rowheight=28,
        font=("Consolas", 11, "bold")
    )

    style.configure(
        "Cyber.Treeview.Heading",
        background=TOP,
        foreground=TEXT,
        relief="flat",
        borderwidth=1,
        font=("Consolas", 11, "bold")
    )

    style.map(
        "Cyber.Treeview",
        background=[("selected", "#14325c")],
        foreground=[("selected", CYAN)]
    )

    style.map(
        "Cyber.Treeview.Heading",
        background=[("active", "#102041")]
    )


class CyberButton(tk.Button):
    def __init__(self, master, normal_bg, hover_bg, press_bg, **kwargs):
        super().__init__(
            master,
            bg=normal_bg,
            fg=TEXT,
            activebackground=press_bg,
            activeforeground=TEXT,
            relief="flat",
            bd=0,
            cursor="hand2",
            font=("Consolas", 12, "bold"),
            padx=14,
            pady=9,
            **kwargs
        )
        self.normal_bg = normal_bg
        self.hover_bg = hover_bg
        self.press_bg = press_bg

        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonPress-1>", self._on_press)
        self.bind("<ButtonRelease-1>", self._on_release)

    def _on_enter(self, _):
        if self["state"] != "disabled":
            self.configure(bg=self.hover_bg)

    def _on_leave(self, _):
        if self["state"] != "disabled":
            self.configure(bg=self.normal_bg, padx=14, pady=9)

    def _on_press(self, _):
        if self["state"] != "disabled":
            self.configure(bg=self.press_bg, padx=12, pady=8)

    def _on_release(self, _):
        if self["state"] != "disabled":
            self.configure(bg=self.hover_bg, padx=14, pady=9)


class StatCard(tk.Frame):
    def __init__(self, master, title, color):
        super().__init__(master, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        self.title_label = tk.Label(
            self,
            text=title,
            bg=PANEL,
            fg=TEXT_SOFT,
            font=("Consolas", 11, "bold")
        )
        self.title_label.pack(anchor="w", padx=14, pady=(10, 4))

        self.value_label = tk.Label(
            self,
            text="0",
            bg=PANEL,
            fg=color,
            font=("Consolas", 24, "bold")
        )
        self.value_label.pack(anchor="w", padx=14, pady=(0, 10))

    def set(self, value):
        self.value_label.config(text=str(value))


class SmartIDSDefenderUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Defender Dashboard")
        self.root.geometry("1380x820")
        self.root.configure(bg=BG)

        style_treeview()

        self.packet_queue = queue.Queue()
        self.detector = IDSDetectors()
        self.logger = EventLogger()
        self.sniffer = None

        self.total_packets = 0
        self.total_alerts = 0
        self.high_alerts = 0
        self.medium_alerts = 0
        self.attacker_counts = {}
        self.last_alert_message = "NO ALERTS"

        self._build_ui()
        self._update_loop()

    def _panel(self, parent, title):
        frame = tk.Frame(parent, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        title_label = tk.Label(
            frame,
            text=title,
            bg=PANEL,
            fg=TEXT,
            font=("Consolas", 13, "bold")
        )
        title_label.pack(anchor="w", padx=12, pady=(10, 8))
        return frame

    def _build_ui(self):
        topbar = tk.Frame(self.root, bg=TOP, highlightthickness=1, highlightbackground=BORDER)
        topbar.pack(fill="x", padx=10, pady=(10, 6))

        title = tk.Label(
            topbar,
            text="SMART IDS - DEFENDER DASHBOARD",
            bg=TOP,
            fg=TEXT,
            font=("Consolas", 17, "bold")
        )
        title.pack(side="left", padx=12, pady=10)

        self.state_label = tk.Label(
            topbar,
            text="IDLE",
            bg="#132340",
            fg=AMBER,
            font=("Consolas", 12, "bold"),
            padx=12,
            pady=6
        )
        self.state_label.pack(side="right", padx=10, pady=8)

        control = tk.Frame(self.root, bg=BG)
        control.pack(fill="x", padx=10, pady=(0, 8))

        self.start_btn = CyberButton(
            control,
            text="▶ START IDS",
            command=self.start_monitoring,
            normal_bg="#1c5fb8",
            hover_bg="#2d7ae0",
            press_bg="#11468c"
        )
        self.start_btn.pack(side="left", padx=(0, 8))

        self.stop_btn = CyberButton(
            control,
            text="■ STOP",
            command=self.stop_monitoring,
            normal_bg="#334155",
            hover_bg="#475569",
            press_bg="#1f2937",
            state="disabled"
        )
        self.stop_btn.pack(side="left", padx=(0, 14))

        tk.Label(
            control,
            text="iface:",
            bg=BG,
            fg=TEXT_SOFT,
            font=("Consolas", 12, "bold")
        ).pack(side="left")

        self.interface_var = tk.StringVar(value=DEFAULTS.get("defender_interface", "lo"))
        self.interface_entry = tk.Entry(
            control,
            textvariable=self.interface_var,
            bg=PANEL_2,
            fg=CYAN,
            insertbackground=CYAN,
            relief="flat",
            font=("Consolas", 12, "bold"),
            width=10
        )
        self.interface_entry.pack(side="left", padx=(6, 16), ipady=5)

        self.status_var = tk.StringVar(value="status: waiting")
        self.status_text = tk.Label(
            control,
            textvariable=self.status_var,
            bg=BG,
            fg=TEXT_SOFT,
            font=("Consolas", 12, "bold")
        )
        self.status_text.pack(side="left")

        stats = tk.Frame(self.root, bg=BG)
        stats.pack(fill="x", padx=10, pady=(0, 8))

        self.card_total = StatCard(stats, "TOTAL ALERTS", CYAN)
        self.card_total.pack(side="left", fill="both", expand=True, padx=(0, 8))

        self.card_high = StatCard(stats, "HIGH", RED)
        self.card_high.pack(side="left", fill="both", expand=True, padx=4)

        self.card_medium = StatCard(stats, "MEDIUM", AMBER)
        self.card_medium.pack(side="left", fill="both", expand=True, padx=4)

        self.card_attackers = StatCard(stats, "ATTACKERS", GREEN)
        self.card_attackers.pack(side="left", fill="both", expand=True, padx=4)

        self.card_packets = StatCard(stats, "PACKETS", BLUE)
        self.card_packets.pack(side="left", fill="both", expand=True, padx=4)

        right_summary = tk.Frame(stats, bg=PANEL, highlightthickness=1, highlightbackground=BORDER, width=250)
        right_summary.pack(side="left", fill="both", padx=(8, 0))
        right_summary.pack_propagate(False)

        tk.Label(
            right_summary,
            text="LAST ALERT",
            bg=PANEL,
            fg=TEXT,
            font=("Consolas", 12, "bold")
        ).pack(anchor="w", padx=14, pady=(10, 6))

        self.last_alert_label = tk.Label(
            right_summary,
            text=self.last_alert_message,
            bg=PANEL_2,
            fg=CYAN,
            font=("Consolas", 12, "bold"),
            wraplength=220,
            justify="left",
            padx=12,
            pady=12
        )
        self.last_alert_label.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        left = self._panel(body, "LIVE EVENTS")
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))

        tree_wrap = tk.Frame(left, bg=PANEL)
        tree_wrap.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        columns = ("time", "level", "type", "source", "target", "message")
        self.event_tree = ttk.Treeview(
            tree_wrap,
            columns=columns,
            show="headings",
            style="Cyber.Treeview"
        )

        self.event_tree.heading("time", text="TIME")
        self.event_tree.heading("level", text="LEVEL")
        self.event_tree.heading("type", text="TYPE")
        self.event_tree.heading("source", text="SOURCE")
        self.event_tree.heading("target", text="TARGET")
        self.event_tree.heading("message", text="MESSAGE")

        self.event_tree.column("time", width=90, anchor="w")
        self.event_tree.column("level", width=90, anchor="w")
        self.event_tree.column("type", width=130, anchor="w")
        self.event_tree.column("source", width=150, anchor="w")
        self.event_tree.column("target", width=150, anchor="w")
        self.event_tree.column("message", width=420, anchor="w")

        tree_scroll = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.event_tree.yview)
        self.event_tree.configure(yscrollcommand=tree_scroll.set)

        self.event_tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")

        right = tk.Frame(body, bg=BG, width=290)
        right.pack(side="left", fill="y")
        right.pack_propagate(False)

        top_attackers = self._panel(right, "TOP ATTACKERS")
        top_attackers.pack(fill="both", expand=True, pady=(0, 8))

        attacker_wrap = tk.Frame(top_attackers, bg=PANEL)
        attacker_wrap.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.attacker_list = tk.Listbox(
            attacker_wrap,
            bg=PANEL_2,
            fg=TEXT,
            selectbackground="#12325a",
            selectforeground=CYAN,
            relief="flat",
            font=("Consolas", 11, "bold"),
            highlightthickness=0,
            bd=0
        )
        self.attacker_list.pack(fill="both", expand=True)

        log_panel = self._panel(right, "SYSTEM LOG")
        log_panel.pack(fill="both", expand=True)

        log_wrap = tk.Frame(log_panel, bg=PANEL)
        log_wrap.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.log_text = tk.Text(
            log_wrap,
            bg=PANEL_2,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            wrap="word",
            font=("Consolas", 10, "bold"),
            highlightthickness=0,
            bd=0
        )
        self.log_text.pack(fill="both", expand=True)
        self.log_text.configure(state="disabled")

    def add_log(self, text, color=TEXT):
        self.log_text.configure(state="normal")
        tag_name = f"tag_{abs(hash((text, color, datetime.now().timestamp())))}"
        self.log_text.tag_configure(tag_name, foreground=color)
        self.log_text.insert("end", text + "\n", tag_name)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def add_event_row(self, severity, alert_type, src_ip, dst_ip, message):
        now = datetime.now().strftime("%H:%M:%S")
        item_id = self.event_tree.insert(
            "",
            0,
            values=(now, severity, alert_type, src_ip, dst_ip, message)
        )

        row_color = CYAN
        if severity == "MEDIUM":
            row_color = AMBER
        elif severity == "HIGH":
            row_color = RED

        tag_name = f"row_{item_id}"
        self.event_tree.tag_configure(tag_name, foreground=row_color)
        self.event_tree.item(item_id, tags=(tag_name,))

    def refresh_attackers(self):
        self.attacker_list.delete(0, "end")
        sorted_attackers = sorted(self.attacker_counts.items(), key=lambda x: x[1], reverse=True)

        for ip, count in sorted_attackers[:20]:
            self.attacker_list.insert("end", f"{ip}   [{count}]")

    def start_monitoring(self):
        interface = self.interface_var.get().strip()
        if not interface:
            messagebox.showwarning("Missing Interface", "Enter interface like lo, eth0, or wlan0.")
            return

        self.sniffer = IDSSniffer(
            interface=interface,
            packet_callback=self.on_packet,
            status_callback=self.on_status
        )
        self.sniffer.start()

        self.start_btn.configure(state="disabled", bg="#334155")
        self.stop_btn.configure(state="normal", bg="#8f2034")
        self.state_label.configure(text="RUNNING", fg=GREEN, bg="#102a1f")
        self.status_var.set(f"status: monitoring on {interface}")

        line = self.logger.log_text("INFO", f"Monitoring started on {interface}")
        self.add_log(line, CYAN)

    def stop_monitoring(self):
        if self.sniffer:
            self.sniffer.stop()

        self.start_btn.configure(state="normal", bg="#1c5fb8")
        self.stop_btn.configure(state="disabled", bg="#334155")
        self.state_label.configure(text="STOPPED", fg=AMBER, bg="#2a2230")
        self.status_var.set("status: stopped")

        line = self.logger.log_text("INFO", "Monitoring stopped")
        self.add_log(line, AMBER)

    def on_status(self, text):
        self.packet_queue.put(("status", text))

    def on_packet(self, packet_info):
        self.packet_queue.put(("packet", packet_info))

    def _handle_status(self, text):
        self.status_var.set(f"status: {text.lower()}")
        line = self.logger.log_text("INFO", text)
        self.add_log(line, BLUE)

    def _handle_packet(self, packet_info):
        self.total_packets += 1
        alerts = self.detector.process_packet(packet_info)

        for alert in alerts:
            self.total_alerts += 1

            if alert["severity"] == "HIGH":
                self.high_alerts += 1
            elif alert["severity"] == "MEDIUM":
                self.medium_alerts += 1

            src_ip = alert["src_ip"]
            self.attacker_counts[src_ip] = self.attacker_counts.get(src_ip, 0) + 1

            self.last_alert_message = f"{alert['type']} from {alert['src_ip']}"
            self.last_alert_label.config(
                text=self.last_alert_message,
                fg=RED if alert["severity"] == "HIGH" else AMBER
            )

            self.add_event_row(
                alert["severity"],
                alert["type"],
                alert["src_ip"],
                alert["dst_ip"],
                alert["message"]
            )

            log_color = RED if alert["severity"] == "HIGH" else AMBER
            line = self.logger.log_text(alert["severity"], alert["message"])
            self.add_log(line, log_color)

            self.logger.log_event(
                level=alert["severity"],
                event_type=alert["type"],
                src_ip=alert["src_ip"],
                dst_ip=alert["dst_ip"],
                message=alert["message"]
            )

    def _refresh_stats(self):
        self.card_total.set(self.total_alerts)
        self.card_high.set(self.high_alerts)
        self.card_medium.set(self.medium_alerts)
        self.card_attackers.set(len(self.attacker_counts))
        self.card_packets.set(self.total_packets)
        self.refresh_attackers()

    def _update_loop(self):
        try:
            while True:
                item_type, payload = self.packet_queue.get_nowait()
                if item_type == "status":
                    self._handle_status(payload)
                elif item_type == "packet":
                    self._handle_packet(payload)
        except queue.Empty:
            pass

        self._refresh_stats()
        self.root.after(UI_REFRESH_MS, self._update_loop)


def main(root=None):
    if root is None:
        root = tk.Tk()
        SmartIDSDefenderUI(root)
        root.mainloop()
    else:
        return SmartIDSDefenderUI(root)


if __name__ == "__main__":
    main()