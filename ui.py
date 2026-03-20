import ctypes
import queue
import random
import threading
import time
import tkinter as tk
from collections import deque
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

try:
    import winsound

    _HAS_WINSOUND = True
except ImportError:
    _HAS_WINSOUND = False

try:
    from ids.config import load_config
    from ids.detectors import IDSDetectors
    from ids.interface_picker import pick_interface_cross_platform
    from ids.logger import EventLogger
    from ids.sniffer import IDSSniffer

    _HAS_IDS = True
except ImportError:
    _HAS_IDS = False


class Tooltip:
    def __init__(self, widget, text_getter=None, bg="#111111", fg="#e8e8e8"):
        self.widget = widget
        self.text_getter = (
            text_getter if callable(text_getter) else lambda: str(text_getter or "")
        )
        self.bg = bg
        self.fg = fg
        self.tip = None

    def show(self, x_root, y_root):
        text = self.text_getter()
        if not text:
            self.hide()
            return

        self.hide()
        self.tip = tk.Toplevel(self.widget)
        self.tip.overrideredirect(True)
        self.tip.attributes("-topmost", True)
        self.tip.configure(bg=self.bg)

        frame = tk.Frame(
            self.tip,
            bg=self.bg,
            highlightthickness=1,
            highlightbackground="#2f2f2f",
            bd=0,
        )
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            frame,
            text=text,
            bg=self.bg,
            fg=self.fg,
            justify="left",
            padx=8,
            pady=6,
            font=("Segoe UI", 9, "bold"),
        ).pack()

        self.tip.geometry(f"+{x_root + 14}+{y_root + 12}")

    def hide(self):
        if self.tip:
            try:
                self.tip.destroy()
            except Exception:
                pass
            self.tip = None


class HoverLabel(tk.Label):
    def __init__(self, parent, tooltip_text_getter, **kwargs):
        super().__init__(parent, **kwargs)
        self._tooltip = Tooltip(self, tooltip_text_getter)
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", lambda e: self._tooltip.hide())
        self.bind("<Motion>", self._on_motion)

    def _on_enter(self, event):
        self._tooltip.show(event.x_root, event.y_root)

    def _on_motion(self, event):
        self._tooltip.show(event.x_root, event.y_root)


class SparklineCanvas(tk.Frame):
    def __init__(
        self,
        parent,
        width=420,
        height=110,
        max_points=60,
        line_color="#00ffcc",
        fill_color="#03332d",
        bg="#080808",
    ):
        super().__init__(parent, bg=bg, width=width, height=height)
        self.pack_propagate(False)
        self.max_points = max_points
        self.line_color = line_color
        self.fill_color = fill_color
        self.bg = bg
        self.canvas_width = width
        self.canvas_height = height
        self._data = deque([0.0] * max_points, maxlen=max_points)

        self._cv = tk.Canvas(
            self,
            bg=bg,
            bd=0,
            highlightthickness=0,
            width=width,
            height=height,
        )
        self._cv.pack(fill=tk.BOTH, expand=True)
        self._cv.bind("<Configure>", self._on_resize)

    def _on_resize(self, event):
        self.canvas_width = event.width
        self.canvas_height = event.height
        self._redraw()

    def push(self, value: float):
        self._data.append(value)
        self._redraw()

    def _draw_grid(self, w, h, pad_l, pad_r, pad_t, pad_b):
        for i in range(6):
            y = pad_t + i * (h - pad_t - pad_b) / 5
            self._cv.create_line(pad_l, y, w - pad_r, y, fill="#111111")
        for i in range(9):
            x = pad_l + i * (w - pad_l - pad_r) / 8
            self._cv.create_line(x, pad_t, x, h - pad_b, fill="#0d0d0d")

    def _redraw(self):
        self._cv.delete("all")
        data = list(self._data)
        w, h = self.canvas_width, self.canvas_height
        pad_l, pad_r, pad_t, pad_b = 34, 12, 10, 22

        self._draw_grid(w, h, pad_l, pad_r, pad_t, pad_b)

        mx = max(data) or 1.0
        n = len(data)
        pts_line = []
        pts_fill = []

        for i, v in enumerate(data):
            x = pad_l + (i / max(1, n - 1)) * (w - pad_l - pad_r)
            y = h - pad_b - (v / mx) * (h - pad_t - pad_b)
            pts_line.extend([x, y])
            pts_fill.extend([x, y])

        if pts_fill:
            pts_fill.extend([pts_fill[-2], h - pad_b, pad_l, h - pad_b])
            bands = [
                ("#021916", 6),
                ("#032420", 4),
                (self.fill_color, 0),
            ]
            for color, offset in bands:
                shifted = []
                for i in range(0, len(pts_fill) - 4, 2):
                    shifted.extend(
                        [pts_fill[i], min(h - pad_b, pts_fill[i + 1] + offset)]
                    )
                shifted.extend([pts_fill[-4], h - pad_b, pad_l, h - pad_b])
                self._cv.create_polygon(shifted, fill=color, outline="")

        if len(pts_line) >= 4:
            self._cv.create_line(pts_line, fill=self.line_color, width=2, smooth=True)

        self._cv.create_text(
            8,
            pad_t,
            text=f"{mx:.0f}",
            anchor="nw",
            fill="#777777",
            font=("Consolas", 8, "bold"),
        )
        self._cv.create_text(
            8,
            h - pad_b - 8,
            text="0",
            anchor="nw",
            fill="#777777",
            font=("Consolas", 8, "bold"),
        )
        self._cv.create_text(
            w - 8,
            6,
            text=f"{data[-1]:.1f}/s",
            anchor="ne",
            fill=self.line_color,
            font=("Consolas", 10, "bold"),
        )
        self._cv.create_text(
            w - 8,
            h - 8,
            text="rolling window: 60s",
            anchor="se",
            fill="#7a7a7a",
            font=("Segoe UI", 8, "bold"),
        )
        self._cv.create_text(
            38,
            h - 8,
            text="time",
            anchor="sw",
            fill="#7a7a7a",
            font=("Segoe UI", 8, "bold"),
        )


class MiniSparkline(tk.Canvas):
    def __init__(self, parent, width=90, height=20, bg="#080808"):
        super().__init__(
            parent,
            width=width,
            height=height,
            bg=bg,
            bd=0,
            highlightthickness=0,
        )
        self.w = width
        self.h = height

    def draw(self, values, line="#ff003c", fill="#2a0a12"):
        self.delete("all")
        if not values:
            return

        n = len(values)
        mx = max(values) or 1
        pad = 2

        pts = []
        fill_pts = []

        for i, v in enumerate(values):
            x = pad + (i / max(1, n - 1)) * (self.w - 2 * pad)
            y = self.h - pad - (v / mx) * (self.h - 2 * pad)
            pts.extend([x, y])
            fill_pts.extend([x, y])

        fill_pts.extend([fill_pts[-2], self.h - pad, pad, self.h - pad])
        self.create_polygon(fill_pts, fill=fill, outline="")
        if len(pts) >= 4:
            self.create_line(pts, fill=line, width=1, smooth=True)


class ThreatTimeline(tk.Frame):
    SEV_COLOR = {
        "HIGH": "#ff003c",
        "MEDIUM": "#ffcc00",
        "LOW": "#00ff66",
        "INFO": "#1e90ff",
    }

    def __init__(self, parent, height=34):
        super().__init__(parent, bg="#080808", height=height)
        self.pack_propagate(False)
        self.canvas_height = height
        self.canvas_width = 1
        self._slots = deque(
            [{"severity": None, "type": "", "timestamp": ""} for _ in range(60)],
            maxlen=60,
        )
        self._hover_index = None
        self._tooltip = Tooltip(self, self._tooltip_text)

        self._cv = tk.Canvas(
            self,
            bg="#080808",
            bd=0,
            highlightthickness=0,
            height=height,
        )
        self._cv.pack(fill=tk.BOTH, expand=True)
        self._cv.bind("<Configure>", self._on_resize)
        self._cv.bind("<Motion>", self._on_motion)
        self._cv.bind("<Leave>", self._on_leave)

    def _tooltip_text(self):
        if self._hover_index is None:
            return ""
        item = list(self._slots)[self._hover_index]
        if not item["severity"]:
            return ""
        return (
            f"Time: {item['timestamp']}\n"
            f"Type: {item['type']}\n"
            f"Severity: {item['severity']}"
        )

    def _on_motion(self, event):
        slots = list(self._slots)
        if not slots:
            return
        bar_w = max(1, self.canvas_width / len(slots))
        idx = min(len(slots) - 1, max(0, int(event.x / bar_w)))
        self._hover_index = idx
        item = slots[idx]
        if item["severity"]:
            self._tooltip.show(event.x_root, event.y_root)
        else:
            self._tooltip.hide()

    def _on_leave(self, _event):
        self._hover_index = None
        self._tooltip.hide()

    def _on_resize(self, event):
        self.canvas_width = event.width
        self.canvas_height = event.height
        self._redraw()

    def tick(self):
        self._slots.append({"severity": None, "type": "", "timestamp": ""})
        self._redraw()

    def record(self, severity: str, threat_type: str = "EVENT", timestamp: str = ""):
        item = {
            "severity": severity,
            "type": threat_type,
            "timestamp": timestamp,
        }
        self._slots[-1] = item
        self._redraw()

    def _redraw(self):
        self._cv.delete("all")
        w = self.canvas_width or 640
        h = self.canvas_height
        slots = list(self._slots)
        n = len(slots)
        bar_w = max(1, w / n)

        for i in range(0, w, 14):
            self._cv.create_line(i, 0, i, h, fill="#0e0e0e")
        self._cv.create_line(0, h - 1, w, h - 1, fill="#151515")

        for i, item in enumerate(slots):
            sev = item["severity"]
            if sev is None:
                continue
            x0 = i * bar_w
            x1 = x0 + bar_w - 1
            color = self.SEV_COLOR.get(sev, "#444444")
            self._cv.create_rectangle(x0, 4, x1, h - 4, fill=color, outline="")

        playhead_x = w - 2
        self._cv.create_line(playhead_x, 1, playhead_x, h - 2, fill="#00ffcc", width=2)
        self._cv.create_text(
            w - 8,
            4,
            text="60s",
            anchor="ne",
            fill="#7c7c7c",
            font=("Consolas", 8, "bold"),
        )


class Toast(tk.Toplevel):
    def __init__(
        self, parent, message: str, color: str = "#ff003c", duration_ms: int = 4000
    ):
        super().__init__(parent)
        self.overrideredirect(True)
        self.attributes("-topmost", True)
        self.configure(bg="#111111")

        sw = parent.winfo_screenwidth()
        sh = parent.winfo_screenheight()
        self.geometry(f"360x92+{sw - 390}+{sh - 140}")

        tk.Frame(self, bg=color, width=4).pack(side=tk.LEFT, fill=tk.Y)
        body = tk.Frame(self, bg="#111111", padx=12, pady=10)
        body.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            body,
            text="HIGH SEVERITY ALERT",
            bg="#111111",
            fg=color,
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w")

        tk.Label(
            body,
            text=message,
            bg="#111111",
            fg="#d4d4d4",
            font=("Consolas", 10, "bold"),
            wraplength=305,
            justify="left",
        ).pack(anchor="w")

        tk.Button(
            self,
            text="X",
            command=self.destroy,
            bg="#111111",
            fg="#777777",
            bd=0,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2",
        ).place(relx=1.0, rely=0, anchor="ne", x=-4, y=4)

        self.after(duration_ms, self.destroy)


class IDSUI:
    COL_BG = "#050505"
    COL_PANEL = "#0f0f0f"
    COL_PANEL_2 = "#080808"
    COL_BORDER = "#1f1f1f"
    COL_BORDER_B = "#2b2b2b"
    COL_TEXT = "#f2f2f2"
    COL_MUTED = "#8b8b8b"
    COL_MUTED_2 = "#a2a2a2"

    COL_RED = "#ff003c"
    COL_RED_SOFT = "#2a0d14"
    COL_YELLOW = "#ffcc00"
    COL_YELLOW_SOFT = "#30270a"
    COL_GREEN = "#00ff66"
    COL_GREEN_SOFT = "#082515"
    COL_CYAN = "#00ffcc"
    COL_BLUE = "#1e90ff"
    COL_PURPLE = "#b366ff"

    FONT_UI = ("Segoe UI", 11, "bold")
    FONT_DATA = ("Consolas", 11, "bold")
    FONT_DATA_SMALL = ("Consolas", 10, "bold")
    FONT_H2 = ("Segoe UI", 12, "bold")
    FONT_KPI = ("Consolas", 31, "bold")
    FONT_TITLE = ("Segoe UI", 18, "bold")
    FONT_SUBTITLE = ("Segoe UI", 15, "bold")

    MAX_LOG_LINES = 2000

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Smart IDS v2.0 - Cyber Dashboard")
        self.root.geometry("1440x860")
        self.root.minsize(1160, 720)
        self.root.configure(bg=self.COL_BG)

        self.ui_queue = queue.Queue()
        self.sniffer = None
        self.running = False
        self._start_ts = 0.0
        self._autoscroll = True
        self._log_line_count = 0
        self._latest_alert_glow_on = False
        self._pulse_danger_on = False
        self._iface_full = "-"
        self._last_packet_seen_at = 0.0
        self._self_test_running = False

        self.low_count = 0
        self.med_count = 0
        self.high_count = 0
        self.total_alerts = 0
        self.pkt_count = 0
        self._pkt_window_count = 0
        self._pkt_window_start = time.time()
        self.attacker_stats = {}

        self.status_var = tk.StringVar(value="OFFLINE")
        self.iface_var = tk.StringVar(value="-")
        self.filter_var = tk.StringVar(value="-")
        self.pktrate_var = tk.StringVar(value="0.0 /s")
        self.low_var = tk.StringVar(value="0")
        self.med_var = tk.StringVar(value="0")
        self.high_var = tk.StringVar(value="0")
        self.total_var = tk.StringVar(value="0")
        self.attackers_var = tk.StringVar(value="0")
        self.packets_var = tk.StringVar(value="0")
        self.last_alert_var = tk.StringVar(value="No alerts yet.")
        self.sev_filter_var = tk.StringVar(value="ALL")
        self.search_var = tk.StringVar(value="")
        self.uptime_var = tk.StringVar(value="UPTIME  -")
        self.engine_stats_var = tk.StringVar(
            value="ENGINE: OFFLINE   PACKET PATH: IDLE   SELF-TEST: READY"
        )

        self._build_ui()
        self._set_running(False)
        self.root.update_idletasks()
        self._apply_dark_title_bar()
        self._bind_keys()

        self.root.after(100, self._poll_queue)
        self.root.after(1000, self._tick_packet_rate)
        self.root.after(1000, self._tick_uptime)
        self.root.after(1000, self._tick_timeline)
        self.root.after(650, self._animate_danger_host)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _apply_dark_title_bar(self):
        try:
            hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
            value = ctypes.c_int(1)
            for attr in (20, 19):
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd,
                    attr,
                    ctypes.byref(value),
                    ctypes.sizeof(value),
                )
        except Exception:
            pass

    def _build_style(self):
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except Exception:
            pass

        self.root.option_add("*TCombobox*Listbox*Background", self.COL_PANEL_2)
        self.root.option_add("*TCombobox*Listbox*Foreground", self.COL_TEXT)
        self.root.option_add("*TCombobox*Listbox*selectBackground", self.COL_BORDER_B)
        self.root.option_add("*TCombobox*Listbox*selectForeground", self.COL_CYAN)

        s.configure(
            "Cyber.TCombobox",
            fieldbackground=self.COL_PANEL_2,
            background=self.COL_PANEL_2,
            foreground=self.COL_CYAN,
            bordercolor=self.COL_BORDER_B,
            darkcolor=self.COL_PANEL_2,
            lightcolor=self.COL_PANEL_2,
            arrowcolor=self.COL_CYAN,
            relief="flat",
            padding=4,
            font=self.FONT_UI,
        )
        s.map(
            "Cyber.TCombobox",
            fieldbackground=[("readonly", self.COL_PANEL_2)],
            background=[("readonly", self.COL_PANEL_2)],
            foreground=[("readonly", self.COL_CYAN)],
            selectbackground=[("readonly", self.COL_PANEL_2)],
            selectforeground=[("readonly", self.COL_CYAN)],
            arrowcolor=[("readonly", self.COL_CYAN)],
        )

        s.configure(
            "Vertical.TScrollbar",
            background=self.COL_PANEL,
            troughcolor=self.COL_PANEL_2,
            bordercolor=self.COL_BORDER,
            arrowcolor=self.COL_CYAN,
            darkcolor=self.COL_PANEL,
            lightcolor=self.COL_PANEL,
        )

    def _btn(self, parent, text, command, bg, fg, width=None, state=tk.NORMAL):
        kw = dict(
            text=text,
            command=command,
            bg=bg,
            fg=fg,
            bd=0,
            activebackground=self.COL_TEXT,
            activeforeground=self.COL_BG,
            cursor="hand2",
            font=("Segoe UI", 11, "bold"),
            relief="flat",
            state=state,
        )
        if width:
            kw["width"] = width
        return tk.Button(parent, **kw)

    def _truncate_middle(self, text, max_len=36):
        if len(text) <= max_len:
            return text
        half = (max_len - 3) // 2
        return f"{text[:half]}...{text[-half:]}"

    def _set_iface_display(self, text):
        self._iface_full = text
        self.iface_var.set(self._truncate_middle(text, 34))

    def _panel(self, parent, pad=(6, 6), fill=tk.BOTH, expand=False):
        frame = tk.Frame(
            parent,
            bg=self.COL_PANEL,
            bd=0,
            highlightthickness=1,
            highlightbackground=self.COL_BORDER,
        )
        frame.pack(fill=fill, expand=expand, padx=pad[0], pady=pad[1])
        return frame

    def _kpi_card(self, parent, title, var, color):
        card = tk.Frame(
            parent,
            bg=self.COL_PANEL,
            bd=0,
            highlightthickness=1,
            highlightbackground=self.COL_BORDER,
        )
        card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)

        tk.Label(
            card,
            text=title,
            bg=self.COL_PANEL,
            fg=self.COL_MUTED_2,
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", padx=12, pady=(10, 0))

        tk.Label(
            card,
            textvariable=var,
            bg=self.COL_PANEL,
            fg=color,
            font=self.FONT_KPI,
        ).pack(anchor="w", padx=10, pady=(2, 8))
        return card

    def _build_ui(self):
        hdr = tk.Frame(self.root, bg=self.COL_BG)
        hdr.pack(fill=tk.X, padx=14, pady=(12, 0))

        tk.Label(
            hdr,
            text="SMART IDS",
            bg=self.COL_BG,
            fg=self.COL_TEXT,
            font=self.FONT_TITLE,
        ).pack(side=tk.LEFT)

        tk.Label(
            hdr,
            text=" // LIVE THREAT MONITOR v2.0",
            bg=self.COL_BG,
            fg=self.COL_MUTED,
            font=self.FONT_SUBTITLE,
        ).pack(side=tk.LEFT, pady=(2, 0))

        right_hdr = tk.Frame(hdr, bg=self.COL_BG)
        right_hdr.pack(side=tk.RIGHT)

        self._dot = tk.Label(
            right_hdr,
            text="●",
            bg=self.COL_BG,
            fg=self.COL_MUTED,
            font=("Consolas", 16, "bold"),
        )
        self._dot.pack(side=tk.LEFT, padx=(0, 6))

        tk.Label(
            right_hdr,
            textvariable=self.status_var,
            bg=self.COL_BG,
            fg=self.COL_MUTED,
            font=("Consolas", 12, "bold"),
        ).pack(side=tk.LEFT)

        tk.Frame(self.root, bg=self.COL_BORDER, height=1).pack(
            fill=tk.X, padx=14, pady=(8, 0)
        )

        ctrl = tk.Frame(self.root, bg=self.COL_BG)
        ctrl.pack(fill=tk.X, padx=14, pady=(8, 8))

        self.start_btn = self._btn(
            ctrl, "▶ START", self.start_ids, self.COL_CYAN, self.COL_BG, width=10
        )
        self.start_btn.pack(side=tk.LEFT, padx=(0, 6), ipady=5)

        self.stop_btn = self._btn(
            ctrl,
            "■ STOP",
            self.stop_ids,
            self.COL_RED,
            self.COL_TEXT,
            width=9,
            state=tk.DISABLED,
        )
        self.stop_btn.pack(side=tk.LEFT, padx=(0, 6), ipady=5)

        self.selftest_btn = self._btn(
            ctrl,
            "⚡ SELF-TEST",
            self.run_self_test,
            self.COL_PURPLE,
            self.COL_TEXT,
            width=12,
        )
        self.selftest_btn.pack(side=tk.LEFT, padx=(0, 6), ipady=5)

        self._btn(
            ctrl, "⬇ EXPORT", self._export_log, self.COL_PANEL, self.COL_TEXT, width=10
        ).pack(side=tk.LEFT, padx=(0, 6), ipady=5)
        self._btn(
            ctrl, "✕ CLEAR", self._clear_all, self.COL_PANEL, self.COL_MUTED, width=9
        ).pack(side=tk.LEFT, padx=(0, 18), ipady=5)

        info = tk.Frame(ctrl, bg=self.COL_BG)
        info.pack(side=tk.LEFT)

        tk.Label(
            info, text="IFACE:", bg=self.COL_BG, fg=self.COL_MUTED, font=self.FONT_UI
        ).grid(row=0, column=0, sticky="w")
        self.iface_label = HoverLabel(
            info,
            tooltip_text_getter=lambda: self._iface_full,
            textvariable=self.iface_var,
            bg=self.COL_BG,
            fg=self.COL_TEXT,
            font=self.FONT_DATA,
            anchor="w",
        )
        self.iface_label.grid(row=0, column=1, sticky="w", padx=(5, 18))

        tk.Label(
            info, text="FILTER:", bg=self.COL_BG, fg=self.COL_MUTED, font=self.FONT_UI
        ).grid(row=0, column=2, sticky="w")
        tk.Label(
            info,
            textvariable=self.filter_var,
            bg=self.COL_BG,
            fg=self.COL_TEXT,
            font=self.FONT_DATA,
        ).grid(row=0, column=3, sticky="w", padx=(5, 18))

        flt = tk.Frame(ctrl, bg=self.COL_BG)
        flt.pack(side=tk.RIGHT)

        tk.Label(
            flt, text="LEVEL:", bg=self.COL_BG, fg=self.COL_MUTED, font=self.FONT_UI
        ).pack(side=tk.LEFT, padx=(0, 5))

        self.sev_combo = ttk.Combobox(
            flt,
            values=["ALL", "HIGH", "MEDIUM", "LOW", "INFO"],
            textvariable=self.sev_filter_var,
            width=8,
            state="readonly",
            style="Cyber.TCombobox",
            font=self.FONT_UI,
        )
        self.sev_combo.pack(side=tk.LEFT, padx=(0, 14), ipady=2)

        tk.Label(
            flt,
            text="SEARCH IP/MSG:",
            bg=self.COL_BG,
            fg=self.COL_MUTED,
            font=self.FONT_UI,
        ).pack(side=tk.LEFT, padx=(0, 5))

        self.search_entry = tk.Entry(
            flt,
            textvariable=self.search_var,
            width=18,
            bg=self.COL_PANEL_2,
            fg=self.COL_CYAN,
            insertbackground=self.COL_CYAN,
            bd=0,
            highlightthickness=1,
            highlightbackground=self.COL_BORDER,
            font=self.FONT_DATA,
        )
        self.search_entry.pack(side=tk.LEFT, ipady=5)

        self._btn(
            flt,
            "X",
            lambda: self.search_var.set(""),
            self.COL_BORDER,
            self.COL_MUTED_2,
            width=3,
        ).pack(side=tk.LEFT, padx=(6, 0), ipady=3)

        kpi_row = tk.Frame(self.root, bg=self.COL_BG)
        kpi_row.pack(fill=tk.X, padx=14, pady=(0, 8))

        self._kpi_card(kpi_row, "TOTAL ALERTS", self.total_var, self.COL_CYAN)
        self._kpi_card(kpi_row, "CRITICAL", self.high_var, self.COL_RED)
        self._kpi_card(kpi_row, "WARNING", self.med_var, self.COL_YELLOW)
        self._kpi_card(kpi_row, "NOTICE", self.low_var, self.COL_GREEN)
        self._kpi_card(kpi_row, "UNIQUE HOSTS", self.attackers_var, self.COL_BLUE)
        self._kpi_card(kpi_row, "PACKETS", self.packets_var, self.COL_MUTED_2)

        tl_frame = tk.Frame(self.root, bg=self.COL_BG)
        tl_frame.pack(fill=tk.X, padx=14, pady=(0, 6))

        tl_panel = tk.Frame(
            tl_frame,
            bg=self.COL_PANEL,
            bd=0,
            highlightthickness=1,
            highlightbackground=self.COL_BORDER,
        )
        tl_panel.pack(fill=tk.X)

        tl_hdr = tk.Frame(tl_panel, bg=self.COL_PANEL)
        tl_hdr.pack(fill=tk.X, padx=12, pady=(7, 2))

        tk.Label(
            tl_hdr,
            text="60-SECOND THREAT TIMELINE",
            bg=self.COL_PANEL,
            fg=self.COL_MUTED_2,
            font=("Segoe UI", 10, "bold"),
        ).pack(side=tk.LEFT)

        legend = tk.Frame(tl_hdr, bg=self.COL_PANEL)
        legend.pack(side=tk.RIGHT)

        for name, color in [
            ("HIGH", self.COL_RED),
            ("MEDIUM", self.COL_YELLOW),
            ("LOW", self.COL_GREEN),
            ("INFO", self.COL_BLUE),
        ]:
            tk.Label(
                legend,
                text="■",
                bg=self.COL_PANEL,
                fg=color,
                font=("Consolas", 10, "bold"),
            ).pack(side=tk.LEFT, padx=(0, 2))
            tk.Label(
                legend,
                text=name,
                bg=self.COL_PANEL,
                fg=self.COL_MUTED_2,
                font=("Segoe UI", 8, "bold"),
            ).pack(side=tk.LEFT, padx=(0, 10))

        self.timeline = ThreatTimeline(tl_panel, height=34)
        self.timeline.pack(fill=tk.X, padx=10, pady=(0, 8))

        stats_strip = tk.Frame(
            self.root,
            bg=self.COL_PANEL,
            highlightthickness=1,
            highlightbackground=self.COL_BORDER,
        )
        stats_strip.pack(fill=tk.X, padx=14, pady=(0, 8))

        tk.Label(
            stats_strip,
            text="ENGINE STATUS",
            bg=self.COL_PANEL,
            fg=self.COL_MUTED_2,
            font=("Segoe UI", 10, "bold"),
        ).pack(side=tk.LEFT, padx=(10, 8), pady=6)

        tk.Label(
            stats_strip,
            textvariable=self.engine_stats_var,
            bg=self.COL_PANEL,
            fg=self.COL_CYAN,
            font=("Consolas", 10, "bold"),
            anchor="w",
        ).pack(side=tk.LEFT, padx=(0, 8), pady=6)

        paned = tk.PanedWindow(
            self.root,
            orient=tk.HORIZONTAL,
            bg=self.COL_BG,
            sashwidth=6,
            bd=0,
            sashrelief="flat",
        )
        paned.pack(fill=tk.BOTH, expand=True, padx=14, pady=(0, 10))

        left_frame = tk.Frame(paned, bg=self.COL_BG)
        right_frame = tk.Frame(paned, bg=self.COL_BG, width=420)

        paned.add(left_frame, minsize=500)
        paned.add(right_frame, minsize=350)

        self._build_log_panel(left_frame)
        self._build_right_panel(right_frame)

        sb = tk.Frame(self.root, bg=self.COL_BORDER_B, height=24)
        sb.pack(fill=tk.X, side=tk.BOTTOM)
        sb.pack_propagate(False)

        tk.Label(
            sb,
            textvariable=self.uptime_var,
            bg=self.COL_BORDER_B,
            fg=self.COL_MUTED_2,
            font=("Consolas", 9, "bold"),
        ).pack(side=tk.LEFT, padx=10)

        tk.Label(
            sb,
            text="Ctrl+R Start | Ctrl+S Stop | Ctrl+E Export | Esc Clear Search",
            bg=self.COL_BORDER_B,
            fg=self.COL_MUTED_2,
            font=("Consolas", 9, "bold"),
        ).pack(side=tk.RIGHT, padx=10)

    def _build_log_panel(self, parent):
        panel = tk.Frame(
            parent,
            bg=self.COL_PANEL,
            bd=0,
            highlightthickness=1,
            highlightbackground=self.COL_BORDER,
        )
        panel.pack(fill=tk.BOTH, expand=True)

        hdr = tk.Frame(panel, bg=self.COL_PANEL)
        hdr.pack(fill=tk.X, padx=10, pady=(8, 4))

        tk.Label(
            hdr,
            text="NETWORK TELEMETRY",
            bg=self.COL_PANEL,
            fg=self.COL_MUTED_2,
            font=self.FONT_H2,
        ).pack(side=tk.LEFT)

        self._autoscroll_btn = self._btn(
            hdr,
            "AUTO-SCROLL ON",
            self._toggle_autoscroll,
            self.COL_CYAN,
            self.COL_BG,
        )
        self._autoscroll_btn.pack(side=tk.RIGHT, padx=(8, 0), ipady=3)

        graph_panel = tk.Frame(
            panel,
            bg=self.COL_PANEL_2,
            highlightthickness=1,
            highlightbackground="#171717",
            bd=0,
        )
        graph_panel.pack(fill=tk.X, padx=8, pady=(0, 6))

        graph_top = tk.Frame(graph_panel, bg=self.COL_PANEL_2)
        graph_top.pack(fill=tk.X, padx=8, pady=(6, 0))

        tk.Label(
            graph_top,
            text="PKT/s",
            bg=self.COL_PANEL_2,
            fg=self.COL_MUTED_2,
            font=("Segoe UI", 9, "bold"),
        ).pack(side=tk.LEFT)

        tk.Label(
            graph_top,
            textvariable=self.pktrate_var,
            bg=self.COL_PANEL_2,
            fg=self.COL_RED,
            font=("Consolas", 10, "bold"),
        ).pack(side=tk.LEFT, padx=(8, 0))

        self.sparkline = SparklineCanvas(graph_panel, width=420, height=110)
        self.sparkline.pack(fill=tk.X, padx=8, pady=(2, 8))

        self.log_box = ScrolledText(
            panel,
            bg=self.COL_PANEL_2,
            fg=self.COL_TEXT,
            insertbackground=self.COL_TEXT,
            bd=0,
            highlightthickness=0,
            font=self.FONT_DATA_SMALL,
            padx=10,
            pady=8,
        )
        self.log_box.pack(fill=tk.BOTH, expand=True, padx=2, pady=(0, 2))
        self.log_box.configure(state="disabled")

        self.log_box.tag_config(
            "HIGH", foreground=self.COL_RED, background=self.COL_RED_SOFT
        )
        self.log_box.tag_config(
            "MEDIUM", foreground=self.COL_YELLOW, background=self.COL_YELLOW_SOFT
        )
        self.log_box.tag_config(
            "LOW", foreground=self.COL_GREEN, background=self.COL_GREEN_SOFT
        )
        self.log_box.tag_config("INFO", foreground=self.COL_MUTED_2)
        self.log_box.tag_config("DEBUG", foreground=self.COL_BLUE)
        self.log_box.tag_config("SYSTEM", foreground=self.COL_PURPLE)

        self.log_box.tag_config("HIGH_FLASH", background="#4a0f1c")
        self.log_box.tag_config("MEDIUM_FLASH", background="#574509")
        self.log_box.tag_config("LOW_FLASH", background="#0f3a20")

        self.log_box.bind("<Button-3>", self._log_right_click)

    def _build_right_panel(self, parent):
        self.latest_panel = tk.Frame(
            parent,
            bg=self.COL_PANEL,
            bd=0,
            highlightthickness=1,
            highlightbackground=self.COL_BORDER,
        )
        self.latest_panel.pack(fill=tk.X, padx=0, pady=(0, 8))

        tk.Label(
            self.latest_panel,
            text="LATEST ALERT",
            bg=self.COL_PANEL,
            fg=self.COL_MUTED_2,
            font=self.FONT_H2,
        ).pack(anchor="w", padx=10, pady=(8, 2))

        self.last_alert_lbl = tk.Label(
            self.latest_panel,
            textvariable=self.last_alert_var,
            bg=self.COL_PANEL_2,
            fg=self.COL_CYAN,
            font=self.FONT_DATA_SMALL,
            justify="left",
            wraplength=390,
            padx=10,
            pady=12,
            anchor="w",
        )
        self.last_alert_lbl.pack(fill=tk.X, padx=10, pady=(0, 10))

        self.hosts_panel = self._panel(parent, pad=(0, 0), fill=tk.BOTH, expand=True)

        tk.Label(
            self.hosts_panel,
            text="ACTIVE HOSTS (TOP 10)",
            bg=self.COL_PANEL,
            fg=self.COL_MUTED_2,
            font=self.FONT_H2,
        ).pack(anchor="w", padx=10, pady=(8, 4))

        header = tk.Frame(self.hosts_panel, bg=self.COL_BORDER_B)
        header.pack(fill=tk.X, padx=10, pady=(0, 0))

        headers = [
            ("HOST IP", 18),
            ("HITS", 6),
            ("SEV", 8),
            ("LATEST", 14),
            ("TREND", 10),
        ]
        for i, (txt, width) in enumerate(headers):
            tk.Label(
                header,
                text=txt,
                width=width,
                anchor="w",
                bg=self.COL_BORDER_B,
                fg=self.COL_CYAN,
                font=("Segoe UI", 10, "bold"),
                padx=6,
                pady=5,
            ).grid(row=0, column=i, sticky="w")

        self.host_rows_frame = tk.Frame(self.hosts_panel, bg=self.COL_PANEL_2)
        self.host_rows_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        self.host_row_widgets = []

    def _bind_keys(self):
        self.root.bind("<Control-r>", lambda e: self.start_ids())
        self.root.bind("<Control-s>", lambda e: self.stop_ids())
        self.root.bind("<Control-e>", lambda e: self._export_log())
        self.root.bind("<Escape>", lambda e: self.search_var.set(""))

    def _flash_latest_alert_panel(self, severity):
        if severity != "HIGH":
            self.latest_panel.configure(highlightbackground=self.COL_BORDER)
            self._latest_alert_glow_on = False
            return
        self._latest_alert_glow_on = True
        self._pulse_latest_alert()

    def _pulse_latest_alert(self):
        if not self._latest_alert_glow_on:
            self.latest_panel.configure(highlightbackground=self.COL_BORDER)
            return
        cur = self.latest_panel.cget("highlightbackground")
        nxt = self.COL_RED if cur != self.COL_RED else "#5a101f"
        self.latest_panel.configure(highlightbackground=nxt)
        self.root.after(450, self._pulse_latest_alert)

    def _log_line(self, msg: str, tag: str = "INFO", flash=False):
        self.log_box.configure(state="normal")

        if self._log_line_count >= self.MAX_LOG_LINES:
            self.log_box.delete("1.0", "500.end+1c")
            self._log_line_count -= 500

        start_index = self.log_box.index(tk.END)
        self.log_box.insert(tk.END, msg + "\n", tag)
        end_index = self.log_box.index(tk.END)

        if flash and tag in ("HIGH", "MEDIUM", "LOW"):
            flash_tag = f"{tag}_FLASH"
            self.log_box.tag_add(flash_tag, start_index, f"{end_index} -1c")
            self.root.after(
                700,
                lambda s=start_index, e=f"{end_index} -1c", ft=flash_tag: (
                    self._remove_flash_tag(ft, s, e)
                ),
            )

        self._log_line_count += 1

        if self._autoscroll:
            self.log_box.see(tk.END)

        self.log_box.configure(state="disabled")

    def _remove_flash_tag(self, flash_tag, start, end):
        try:
            self.log_box.configure(state="normal")
            self.log_box.tag_remove(flash_tag, start, end)
            self.log_box.configure(state="disabled")
        except Exception:
            pass

    def _toggle_autoscroll(self):
        self._autoscroll = not self._autoscroll
        if self._autoscroll:
            self._autoscroll_btn.configure(
                text="AUTO-SCROLL ON", bg=self.COL_CYAN, fg=self.COL_BG
            )
        else:
            self._autoscroll_btn.configure(
                text="AUTO-SCROLL OFF", bg=self.COL_BORDER_B, fg=self.COL_MUTED_2
            )

    def _log_right_click(self, event):
        try:
            sel = self.log_box.get(tk.SEL_FIRST, tk.SEL_LAST)
        except tk.TclError:
            idx = self.log_box.index(f"@{event.x},{event.y} linestart")
            sel = self.log_box.get(idx, f"{idx} lineend")

        if sel:
            self.root.clipboard_clear()
            self.root.clipboard_append(sel)

    def _render_hosts_panel(self):
        for row in self.host_row_widgets:
            row.destroy()
        self.host_row_widgets.clear()

        items = sorted(
            self.attacker_stats.items(),
            key=lambda kv: kv[1].get("alerts", 0),
            reverse=True,
        )[:10]

        top_ip = items[0][0] if items else None

        for idx, (ip, st) in enumerate(items):
            row_bg = "#0b0b0b" if idx % 2 == 0 else "#101010"
            if ip == top_ip and st.get("last_sev", "") == "HIGH":
                row_bg = "#16080d" if self._pulse_danger_on else "#220b12"

            row = tk.Frame(
                self.host_rows_frame,
                bg=row_bg,
                highlightthickness=1,
                highlightbackground="#1b1b1b" if ip != top_ip else self.COL_RED,
            )
            row.pack(fill=tk.X, pady=1)
            self.host_row_widgets.append(row)

            sev = st.get("last_sev", "")
            sev_fg = (
                self.COL_RED
                if sev == "HIGH"
                else self.COL_YELLOW
                if sev == "MEDIUM"
                else self.COL_GREEN
            )

            tk.Label(
                row,
                text=ip,
                width=18,
                anchor="w",
                bg=row_bg,
                fg=self.COL_TEXT,
                font=("Consolas", 10, "bold"),
                padx=6,
                pady=6,
            ).grid(row=0, column=0, sticky="w")

            tk.Label(
                row,
                text=str(st.get("alerts", 0)),
                width=6,
                anchor="w",
                bg=row_bg,
                fg=self.COL_TEXT,
                font=("Consolas", 10, "bold"),
                padx=6,
            ).grid(row=0, column=1, sticky="w")

            tk.Label(
                row,
                text=sev,
                width=8,
                anchor="w",
                bg=row_bg,
                fg=sev_fg,
                font=("Consolas", 10, "bold"),
                padx=6,
            ).grid(row=0, column=2, sticky="w")

            tk.Label(
                row,
                text=st.get("last_type", ""),
                width=14,
                anchor="w",
                bg=row_bg,
                fg=sev_fg,
                font=("Consolas", 10, "bold"),
                padx=6,
            ).grid(row=0, column=3, sticky="w")

            spark = MiniSparkline(row, width=90, height=20, bg=row_bg)
            spark.grid(row=0, column=4, sticky="w", padx=(4, 6))
            spark.draw(
                list(st.get("trend", [0])),
                line=sev_fg,
                fill="#241016"
                if sev == "HIGH"
                else "#2a2409"
                if sev == "MEDIUM"
                else "#0f2516",
            )

    def _animate_danger_host(self):
        self._pulse_danger_on = not self._pulse_danger_on
        self._render_hosts_panel()
        self.root.after(650, self._animate_danger_host)

    def _export_log(self):
        ts = time.strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=".log",
            initialfile=f"ids_export_{ts}.log",
            filetypes=[
                ("Log files", "*.log"),
                ("Text files", "*.txt"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return

        try:
            content = self.log_box.get("1.0", tk.END)
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            messagebox.showinfo("Export", f"Log saved to:\n{path}", parent=self.root)
        except Exception as e:
            messagebox.showerror("Export Failed", str(e), parent=self.root)

    def _clear_all(self):
        if not messagebox.askyesno(
            "Clear All", "Reset all counters and clear the log?", parent=self.root
        ):
            return

        self.low_count = 0
        self.med_count = 0
        self.high_count = 0
        self.total_alerts = 0
        self.pkt_count = 0
        self._pkt_window_count = 0
        self.attacker_stats.clear()
        self._log_line_count = 0

        for var in [
            self.low_var,
            self.med_var,
            self.high_var,
            self.total_var,
            self.attackers_var,
            self.packets_var,
        ]:
            var.set("0")

        self.last_alert_var.set("No alerts yet.")
        self.last_alert_lbl.configure(fg=self.COL_CYAN)
        self.latest_panel.configure(highlightbackground=self.COL_BORDER)
        self._latest_alert_glow_on = False

        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", tk.END)
        self.log_box.configure(state="disabled")

        self.timeline = None
        # recreate timeline history cleanly
        self._rebuild_timeline()

        self._render_hosts_panel()

    def _rebuild_timeline(self):
        parent = self.timeline_widget_parent
        self.timeline.destroy()
        self.timeline = ThreatTimeline(parent, height=34)
        self.timeline.pack(fill=tk.X, padx=10, pady=(0, 8))

    def _set_running(self, running: bool):
        self.running = running

        if running:
            self._start_ts = time.time()
            self.status_var.set("RUNNING")
            self._dot.configure(fg=self.COL_GREEN)
            self.start_btn.configure(
                bg=self.COL_BORDER, fg=self.COL_MUTED, state=tk.DISABLED
            )
            self.stop_btn.configure(bg=self.COL_RED, fg=self.COL_TEXT, state=tk.NORMAL)
        else:
            self.status_var.set("OFFLINE")
            self._dot.configure(fg=self.COL_MUTED)
            self.start_btn.configure(bg=self.COL_CYAN, fg=self.COL_BG, state=tk.NORMAL)
            self.stop_btn.configure(
                bg=self.COL_BORDER,
                fg="#555555",  # darker grey
                state=tk.DISABLED,
            )

        self._update_engine_stats()

    def _animate_dot(self):
        if not self.running:
            return
        cur = self._dot.cget("fg")
        self._dot.configure(fg=self.COL_GREEN if cur != self.COL_GREEN else "#005533")
        self.root.after(600, self._animate_dot)

    def _flash_title(self, count=6):
        if count <= 0:
            self.root.title("Smart IDS v2.0 - Cyber Dashboard")
            return
        self.root.title(
            "HIGH ALERT - Smart IDS v2.0"
            if count % 2 == 0
            else "Smart IDS v2.0 - Cyber Dashboard"
        )
        self.root.after(400, lambda: self._flash_title(count - 1))

    def _show_toast(self, message: str):
        try:
            Toast(self.root, message, color=self.COL_RED)
        except Exception:
            pass

    def _play_alert(self):
        if _HAS_WINSOUND:
            try:
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            except Exception:
                pass
        else:
            try:
                self.root.bell()
            except Exception:
                pass

    def _tick_packet_rate(self):
        now = time.time()
        elapsed = max(0.001, now - self._pkt_window_start)
        rate = self._pkt_window_count / elapsed
        self.pktrate_var.set(f"{rate:.1f} /s")
        self.sparkline.push(rate)
        self._pkt_window_start = now
        self._pkt_window_count = 0
        self._update_engine_stats()
        self.root.after(1000, self._tick_packet_rate)

    def _tick_uptime(self):
        if self.running and self._start_ts:
            elapsed = int(time.time() - self._start_ts)
            h, rem = divmod(elapsed, 3600)
            m, s = divmod(rem, 60)
            self.uptime_var.set(f"UPTIME  {h:02d}:{m:02d}:{s:02d}")
        else:
            self.uptime_var.set("UPTIME  -")
        self.root.after(1000, self._tick_uptime)

    def _tick_timeline(self):
        self.timeline.tick()
        self.root.after(1000, self._tick_timeline)

    def _update_engine_stats(self):
        packet_path = (
            "ACTIVE" if time.time() - self._last_packet_seen_at < 3 else "IDLE"
        )
        self.engine_stats_var.set(
            f"ENGINE: {'RUNNING' if self.running else 'OFFLINE'}   "
            f"PACKET PATH: {packet_path}   "
            f"SELF-TEST: {'BUSY' if self._self_test_running else 'READY'}   "
            f"HOSTS: {len(self.attacker_stats)}"
        )

    def _passes_filter(self, ev: dict) -> bool:
        sf = self.sev_filter_var.get().strip().upper()
        src = self.search_var.get().strip().lower()
        sev = str(ev.get("severity", "INFO")).upper()

        if sf != "ALL" and sev != sf:
            return False

        if src:
            haystack = " ".join(
                [
                    str(ev.get("src_ip", "")),
                    str(ev.get("dst_ip", "")),
                    str(ev.get("message", "")),
                ]
            ).lower()
            if src not in haystack:
                return False

        return True

    def _poll_queue(self):
        try:
            while True:
                ev = self.ui_queue.get_nowait()
                sev = str(ev.get("severity", "INFO")).upper()
                typ = str(ev.get("type", "EVENT")).upper()
                msg = str(ev.get("message", ""))
                ts = str(ev.get("time", ""))
                src_ip = ev.get("src_ip", "?")

                if typ == "PACKET":
                    self.pkt_count += 1
                    self._pkt_window_count += 1
                    self.packets_var.set(str(self.pkt_count))
                    self._last_packet_seen_at = time.time()
                    continue

                if typ == "UI" and msg == "__RESET_BUTTONS__":
                    self._set_running(False)
                    continue

                if typ == "UIINFO":
                    self._set_iface_display(msg)
                    self.filter_var.set(str(ev.get("extra", {}).get("filter", "-")))
                    self._update_engine_stats()
                    continue

                if sev in ("LOW", "MEDIUM", "HIGH"):
                    self.total_alerts += 1
                    self.total_var.set(str(self.total_alerts))
                    self.timeline.record(sev, typ, ts)

                    if sev == "LOW":
                        self.low_count += 1
                        self.low_var.set(str(self.low_count))
                    elif sev == "MEDIUM":
                        self.med_count += 1
                        self.med_var.set(str(self.med_count))
                    elif sev == "HIGH":
                        self.high_count += 1
                        self.high_var.set(str(self.high_count))

                    self.last_alert_var.set(f"[{sev}] {typ}\nSRC > {src_ip}\n{msg}")
                    color_map = {
                        "HIGH": self.COL_RED,
                        "MEDIUM": self.COL_YELLOW,
                        "LOW": self.COL_GREEN,
                    }
                    self.last_alert_lbl.configure(fg=color_map.get(sev, self.COL_CYAN))
                    self._flash_latest_alert_panel("HIGH" if sev == "HIGH" else "LOW")

                    if src_ip and src_ip != "?":
                        st = self.attacker_stats.setdefault(
                            src_ip,
                            {
                                "alerts": 0,
                                "last": "",
                                "last_type": "",
                                "last_sev": "",
                                "trend": deque([0] * 12, maxlen=12),
                            },
                        )
                        st["alerts"] += 1
                        st["last"] = ts
                        st["last_type"] = typ
                        st["last_sev"] = sev
                        st["trend"][-1] += 1
                        self.attackers_var.set(str(len(self.attacker_stats)))
                        self._render_hosts_panel()

                    if sev == "HIGH":
                        self._flash_title()
                        self._play_alert()
                        self._show_toast(f"{typ}: {msg[:80]}")

                if not self._passes_filter(ev):
                    continue

                icon = {"HIGH": "X", "MEDIUM": "!", "LOW": "+", "INFO": "."}.get(
                    sev, "."
                )
                tag = (
                    sev
                    if sev in ("LOW", "MEDIUM", "HIGH", "INFO")
                    else "DEBUG"
                    if typ == "DEBUG"
                    else "SYSTEM"
                )
                line = f"[{ts}] {icon} {typ:<12} {msg}"
                self._log_line(line, tag=tag, flash=sev in ("LOW", "MEDIUM", "HIGH"))

        except queue.Empty:
            pass

        self.root.after(100, self._poll_queue)

    def _rotate_host_trends(self):
        for st in self.attacker_stats.values():
            if "trend" not in st:
                st["trend"] = deque([0] * 12, maxlen=12)
            else:
                st["trend"].append(0)

    def _now(self):
        return time.strftime("%H:%M:%S")

    def _enqueue(self, severity, typ, message, **extra):
        self.ui_queue.put(
            {
                "time": self._now(),
                "severity": severity,
                "type": typ,
                "message": message,
                **extra,
            }
        )

    def ui_event_callback(self, event: dict):
        self.ui_queue.put(event)

    def start_ids(self):
        if self.running:
            return
        self._set_running(True)
        threading.Thread(target=self._run_ids, daemon=True).start()
        self._animate_dot()
        self._host_trend_timer()

    def _host_trend_timer(self):
        if self.running:
            self._rotate_host_trends()
            self._render_hosts_panel()
            self.root.after(5000, self._host_trend_timer)

    def run_self_test(self):
        if self._self_test_running:
            return

        self._self_test_running = True
        self._update_engine_stats()

        def worker():
            samples = [
                {
                    "severity": "LOW",
                    "type": "ICMP",
                    "message": "ICMP type=8 code=0 from 127.0.0.1 to 127.0.0.1",
                    "src_ip": "127.0.0.1",
                    "dst_ip": "127.0.0.1",
                },
                {
                    "severity": "MEDIUM",
                    "type": "SUSPICIOUS_PORT",
                    "message": "dport=4444 from 127.0.0.1:55320 -> 127.0.0.1:4444",
                    "src_ip": "127.0.0.1",
                    "dst_ip": "127.0.0.1",
                },
                {
                    "severity": "HIGH",
                    "type": "PORT_SCAN",
                    "message": "127.0.0.1 touched 9 unique ports in 10s [21,22,23,25,53,80,110,443,4444]",
                    "src_ip": "127.0.0.1",
                    "dst_ip": "",
                },
                {
                    "severity": "HIGH",
                    "type": "SYN_BURST",
                    "message": "127.0.0.1 sent 18 SYN packets to port 80 in 10s",
                    "src_ip": "127.0.0.1",
                    "dst_ip": "",
                },
            ]

            for ev in samples:
                ev["time"] = self._now()
                self.ui_queue.put(ev)
                time.sleep(0.9)

            self._self_test_running = False
            self._update_engine_stats()

        threading.Thread(target=worker, daemon=True).start()

    def stop_ids(self):
        if not self.running:
            return

        self._set_running(False)

        if self.sniffer:
            try:
                self.sniffer.stop()
                self._enqueue("INFO", "STATUS", "IDS halted by user.")
            except Exception as e:
                self._enqueue("HIGH", "ERROR", f"Halt error: {e}")
            finally:
                self.sniffer = None

    def _run_ids(self):
        if not _HAS_IDS:
            self._enqueue(
                "HIGH",
                "ERROR",
                "IDS engine modules not found (ids.*). Running in UI-demo mode.",
            )
            self.ui_queue.put(
                {
                    "time": "",
                    "severity": "INFO",
                    "type": "UI",
                    "message": "__RESET_BUTTONS__",
                }
            )
            return

        try:
            cfg = load_config("configs/default.json")

            self._enqueue(
                "INFO",
                "DEBUG",
                f"INIT mode={cfg.interface_mode} index={cfg.interface_index} filter={cfg.bpf_filter}",
            )

            iface = pick_interface_cross_platform(
                mode=cfg.interface_mode,
                index=cfg.interface_index,
            )

            logger = EventLogger(
                cfg.log_file_txt,
                cfg.log_file_jsonl,
                ui_callback=self.ui_event_callback,
            )
            detectors = IDSDetectors(cfg, logger)
            self.sniffer = IDSSniffer(iface, cfg.bpf_filter, detectors)

            self.ui_queue.put(
                {
                    "time": "",
                    "severity": "INFO",
                    "type": "UIINFO",
                    "message": iface,
                    "extra": {"filter": cfg.bpf_filter},
                }
            )

            self._enqueue("INFO", "STATUS", f"Listening on {iface}")
            self.sniffer.start()

        except FileNotFoundError as e:
            self._enqueue("HIGH", "ERROR", f"Missing file: {e}")
            self.ui_queue.put(
                {
                    "time": "",
                    "severity": "INFO",
                    "type": "UI",
                    "message": "__RESET_BUTTONS__",
                }
            )

        except PermissionError:
            self._enqueue(
                "HIGH",
                "ERROR",
                "Permission denied. Run Command Prompt as Administrator.",
            )
            self.ui_queue.put(
                {
                    "time": "",
                    "severity": "INFO",
                    "type": "UI",
                    "message": "__RESET_BUTTONS__",
                }
            )

        except Exception as e:
            self._enqueue("HIGH", "ERROR", f"Startup failed: {e}")
            self.ui_queue.put(
                {
                    "time": "",
                    "severity": "INFO",
                    "type": "UI",
                    "message": "__RESET_BUTTONS__",
                }
            )

    def _on_close(self):
        try:
            self.stop_ids()
        except Exception:
            pass
        self.root.destroy()

    @property
    def timeline_widget_parent(self):
        return self.timeline.master

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    IDSUI().run()
