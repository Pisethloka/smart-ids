import os
import sys
import tkinter as tk
from tkinter import messagebox

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from attacker.simulator import AttackSimulator
from shared.config import DEFAULTS


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


class StatMini(tk.Frame):
    def __init__(self, master, title, value, color):
        super().__init__(master, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        tk.Label(
            self,
            text=title,
            bg=PANEL,
            fg=TEXT_SOFT,
            font=("Consolas", 11, "bold")
        ).pack(anchor="w", padx=12, pady=(10, 4))

        self.value_lbl = tk.Label(
            self,
            text=value,
            bg=PANEL,
            fg=color,
            font=("Consolas", 18, "bold")
        )
        self.value_lbl.pack(anchor="w", padx=12, pady=(0, 10))


class AttackSimulatorUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Attack Simulator")
        self.root.geometry("1280x780")
        self.root.configure(bg=BG)

        self.simulator = AttackSimulator(log_callback=self.add_log)
        self._build_ui()

    def _panel(self, parent, title):
        frame = tk.Frame(parent, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        tk.Label(
            frame,
            text=title,
            bg=PANEL,
            fg=TEXT,
            font=("Consolas", 13, "bold")
        ).pack(anchor="w", padx=12, pady=(10, 8))
        return frame

    def _build_ui(self):
        topbar = tk.Frame(self.root, bg=TOP, highlightthickness=1, highlightbackground=BORDER)
        topbar.pack(fill="x", padx=10, pady=(10, 6))

        tk.Label(
            topbar,
            text="ATTACK SIMULATOR",
            bg=TOP,
            fg=RED,
            font=("Consolas", 17, "bold")
        ).pack(side="left", padx=12, pady=10)

        self.mode_label = tk.Label(
            topbar,
            text="READY",
            bg="#28141d",
            fg=RED,
            font=("Consolas", 12, "bold"),
            padx=12,
            pady=6
        )
        self.mode_label.pack(side="right", padx=10, pady=8)

        config_row = tk.Frame(self.root, bg=BG)
        config_row.pack(fill="x", padx=10, pady=(0, 8))

        left_form = self._panel(config_row, "TARGET")
        left_form.pack(side="left", fill="x", expand=True, padx=(0, 8))

        form = tk.Frame(left_form, bg=PANEL)
        form.pack(fill="x", padx=12, pady=(0, 12))

        self.target_var = tk.StringVar(value=DEFAULTS.get("attacker_target", "127.0.0.1"))
        self.start_port_var = tk.StringVar(value=str(DEFAULTS.get("port_scan_start", 20)))
        self.end_port_var = tk.StringVar(value=str(DEFAULTS.get("port_scan_end", 60)))
        self.tcp_port_var = tk.StringVar(value=str(DEFAULTS.get("tcp_port", 8000)))
        self.connections_var = tk.StringVar(value=str(DEFAULTS.get("tcp_connections", 50)))
        self.ping_count_var = tk.StringVar(value=str(DEFAULTS.get("ping_count", 25)))

        self._field(form, "Host / IP", self.target_var, 0, 0)
        self._field(form, "Start Port", self.start_port_var, 0, 1)
        self._field(form, "End Port", self.end_port_var, 0, 2)
        self._field(form, "TCP Port", self.tcp_port_var, 1, 0)
        self._field(form, "Connections", self.connections_var, 1, 1)
        self._field(form, "Ping Count", self.ping_count_var, 1, 2)

        right_stats = tk.Frame(config_row, bg=BG, width=300)
        right_stats.pack(side="left", fill="y")
        right_stats.pack_propagate(False)

        StatMini(right_stats, "PORT SCAN", "TCP CONNECT", CYAN).pack(fill="x", pady=(0, 8))
        StatMini(right_stats, "PING BURST", "ICMP", AMBER).pack(fill="x", pady=(0, 8))
        StatMini(right_stats, "TCP BURST", "MULTI CONNECT", RED).pack(fill="x")

        actions = tk.Frame(self.root, bg=BG)
        actions.pack(fill="x", padx=10, pady=(0, 8))

        self.port_btn = CyberButton(
            actions,
            text="RUN PORT SCAN",
            command=self.run_port_scan,
            normal_bg="#115aa3",
            hover_bg="#1e78d5",
            press_bg="#0f467e"
        )
        self.port_btn.pack(side="left", padx=(0, 8))

        self.ping_btn = CyberButton(
            actions,
            text="RUN PING BURST",
            command=self.run_ping_burst,
            normal_bg="#8a5a00",
            hover_bg="#b97600",
            press_bg="#714700"
        )
        self.ping_btn.pack(side="left", padx=8)

        self.tcp_btn = CyberButton(
            actions,
            text="RUN TCP BURST",
            command=self.run_tcp_burst,
            normal_bg="#9a233b",
            hover_bg="#c53050",
            press_bg="#751a2d"
        )
        self.tcp_btn.pack(side="left", padx=8)

        self.stop_btn = CyberButton(
            actions,
            text="STOP",
            command=self.stop_simulation,
            normal_bg="#334155",
            hover_bg="#475569",
            press_bg="#1f2937"
        )
        self.stop_btn.pack(side="left", padx=8)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        log_panel = self._panel(body, "SIMULATION LOG")
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
            font=("Consolas", 11, "bold"),
            highlightthickness=0,
            bd=0
        )
        self.log_text.pack(fill="both", expand=True)

    def _field(self, parent, label_text, variable, row, column):
        wrap = tk.Frame(parent, bg=PANEL)
        wrap.grid(row=row, column=column, sticky="ew", padx=8, pady=6)

        tk.Label(
            wrap,
            text=label_text,
            bg=PANEL,
            fg=TEXT_SOFT,
            font=("Consolas", 11, "bold")
        ).pack(anchor="w")

        entry = tk.Entry(
            wrap,
            textvariable=variable,
            bg=PANEL_2,
            fg=CYAN,
            insertbackground=CYAN,
            relief="flat",
            font=("Consolas", 12, "bold"),
            width=18
        )
        entry.pack(fill="x", pady=(4, 0), ipady=6)

    def add_log(self, text, color=TEXT):
        tag_name = f"tag_{abs(hash((text, color, self.log_text.index('end'))))}"
        self.log_text.tag_configure(tag_name, foreground=color)
        self.log_text.insert("end", text + "\n", tag_name)
        self.log_text.see("end")

    def _get_target(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning("Missing Target", "Enter a target host or IP.")
            return None
        return target

    def run_port_scan(self):
        target = self._get_target()
        if not target:
            return

        try:
            start_port = int(self.start_port_var.get())
            end_port = int(self.end_port_var.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "Start Port and End Port must be numbers.")
            return

        self.mode_label.config(text="PORT SCAN", fg=CYAN, bg="#0f2340")
        self.simulator.run_in_thread(self.simulator.simulate_port_scan, target, start_port, end_port)

    def run_ping_burst(self):
        target = self._get_target()
        if not target:
            return

        try:
            count = int(self.ping_count_var.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "Ping Count must be a number.")
            return

        self.mode_label.config(text="PING BURST", fg=AMBER, bg="#2d210a")
        self.simulator.run_in_thread(self.simulator.simulate_ping_burst, target, count)

    def run_tcp_burst(self):
        target = self._get_target()
        if not target:
            return

        try:
            port = int(self.tcp_port_var.get())
            connections = int(self.connections_var.get())
        except ValueError:
            messagebox.showerror("Invalid Input", "TCP Port and Connections must be numbers.")
            return

        self.mode_label.config(text="TCP BURST", fg=RED, bg="#2b1016")
        self.simulator.run_in_thread(self.simulator.simulate_tcp_burst, target, port, connections)

    def stop_simulation(self):
        self.mode_label.config(text="STOPPED", fg=TEXT_SOFT, bg="#202938")
        self.simulator.stop()


def main(root=None):
    if root is None:
        root = tk.Tk()
        AttackSimulatorUI(root)
        root.mainloop()
    else:
        return AttackSimulatorUI(root)


if __name__ == "__main__":
    main()