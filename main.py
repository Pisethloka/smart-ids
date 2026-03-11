import tkinter as tk

from defender.ui import SmartIDSDefenderUI
from attacker.ui import AttackSimulatorUI


BG = "#040816"
PANEL = "#0b132b"
BORDER = "#1d325e"
TEXT = "#d7e7ff"
TEXT_SOFT = "#9cb3d9"
CYAN = "#19e3ff"
RED = "#ff5a7a"


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
            padx=16,
            pady=10,
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
        self.configure(bg=self.hover_bg)

    def _on_leave(self, _):
        self.configure(bg=self.normal_bg, padx=16, pady=10)

    def _on_press(self, _):
        self.configure(bg=self.press_bg, padx=14, pady=9)

    def _on_release(self, _):
        self.configure(bg=self.hover_bg, padx=16, pady=10)


class LauncherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SMART-IDS")
        self.root.geometry("720x360")
        self.root.configure(bg=BG)
        self.root.resizable(False, False)

        self.defender_window = None
        self.attacker_window = None

        self._build_ui()

    def _build_ui(self):
        panel = tk.Frame(self.root, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        panel.pack(fill="both", expand=True, padx=18, pady=18)

        tk.Label(
            panel,
            text="SMART-IDS",
            bg=PANEL,
            fg=TEXT,
            font=("Consolas", 24, "bold")
        ).pack(pady=(28, 12))

        tk.Label(
            panel,
            text="Lightweight intrusion detection with live monitoring and built-in attack simulation.",
            bg=PANEL,
            fg=TEXT_SOFT,
            font=("Consolas", 11, "bold")
        ).pack(pady=(0, 24))

        btn_wrap = tk.Frame(panel, bg=PANEL)
        btn_wrap.pack(fill="x", padx=120)

        CyberButton(
            btn_wrap,
            text="Defender Dashboard",
            command=self.open_defender,
            normal_bg="#1c5fb8",
            hover_bg="#2d7ae0",
            press_bg="#11468c"
        ).pack(fill="x", pady=8)

        CyberButton(
            btn_wrap,
            text="Attack Simulator",
            command=self.open_attacker,
            normal_bg="#9a233b",
            hover_bg="#c53050",
            press_bg="#751a2d"
        ).pack(fill="x", pady=8)

        tk.Label(
            panel,
            text="Both windows can run at the same time.",
            bg=PANEL,
            fg=CYAN,
            font=("Consolas", 10, "bold")
        ).pack(pady=(18, 0))

    def open_defender(self):
        if self.defender_window is None or not self.defender_window.winfo_exists():
            self.defender_window = tk.Toplevel(self.root)
            SmartIDSDefenderUI(self.defender_window)
        else:
            self.defender_window.lift()
            self.defender_window.focus_force()

    def open_attacker(self):
        if self.attacker_window is None or not self.attacker_window.winfo_exists():
            self.attacker_window = tk.Toplevel(self.root)
            AttackSimulatorUI(self.attacker_window)
        else:
            self.attacker_window.lift()
            self.attacker_window.focus_force()


def main():
    root = tk.Tk()
    LauncherApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()