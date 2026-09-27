#!/usr/bin/env python3
"""
CCTV Cam Scanner Radar
Coded by Cyber Security Engineer Mr Sabaz Ali Khan

Authorized-use only:
- Scans private/local IP ranges only.
- Uses TCP connection checks and lightweight HTTP HEAD requests.
- Does NOT try passwords, exploit devices, or access video streams.
"""

import csv
import ipaddress
import queue
import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanner import scan_host, get_default_private_cidr

BANNER = r"""
   ______ ______ _______      __   ____  ___    ____  ___    ____
  / ____// ____//_  __/ | /| / /  / __ \/   |  / __ \/   |  / __ \
 / /    / /      / /  | |/ |/ /  / /_/ / /| | / / / / /| | / /_/ /
/ /___ / /___   / /   |__/|__/  / _, _/ ___ |/ /_/ / ___ |/ _, _/
\____/ \____/  /_/              /_/ |_/_/  |_/_____/_/  |_/_/ |_|

        CCTV CAM SCANNER RADAR
        Coded by Cyber Security Engineer Mr Sabaz Ali Khan
        Authorized private-network discovery only
"""

APP_BG = "#07110b"
PANEL_BG = "#0b1a10"
FG = "#d7ffe2"
ACCENT = "#32ff78"
WARN = "#ffd166"
GRID = "#164d2b"

class CCTVScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CCTV Cam Scanner Radar - Mr Sabaz Ali Khan")
        self.geometry("1180x760")
        self.minsize(980, 650)
        self.configure(bg=APP_BG)

        self.msg_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.results = []
        self.target_ips = []
        self.current_index = 0

        self._build_ui()
        self.after(100, self._process_queue)
        self.after(80, self._animate_radar)

    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("Treeview",
                        background=PANEL_BG, fieldbackground=PANEL_BG,
                        foreground=FG, rowheight=25)
        style.configure("Treeview.Heading",
                        background="#12331d", foreground=FG)
        style.map("Treeview",
                  background=[("selected", "#1f5b32")],
                  foreground=[("selected", "#ffffff")])

        top = tk.Frame(self, bg=APP_BG)
        top.pack(fill="x", padx=12, pady=(10, 4))

        banner = tk.Text(top, height=10, bg=APP_BG, fg=ACCENT,
                         insertbackground=FG, bd=0, font=("Consolas", 9))
        banner.insert("1.0", BANNER)
        banner.configure(state="disabled")
        banner.pack(fill="x")

        controls = tk.Frame(self, bg=PANEL_BG, bd=1, relief="solid")
        controls.pack(fill="x", padx=12, pady=6)

        tk.Label(controls, text="Private subnet/CIDR:",
                 bg=PANEL_BG, fg=FG, font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, padx=8, pady=10, sticky="w"
        )

        self.cidr_var = tk.StringVar(value=get_default_private_cidr())
        self.cidr_entry = tk.Entry(
            controls, textvariable=self.cidr_var, width=24,
            bg="#06120a", fg=FG, insertbackground=FG, relief="flat"
        )
        self.cidr_entry.grid(row=0, column=1, padx=4, pady=10)

        tk.Label(controls, text="Timeout:",
                 bg=PANEL_BG, fg=FG).grid(row=0, column=2, padx=(16, 4))
        self.timeout_var = tk.DoubleVar(value=0.35)
        tk.Spinbox(
            controls, from_=0.1, to=3.0, increment=0.1,
            textvariable=self.timeout_var, width=6,
            bg="#06120a", fg=FG, insertbackground=FG,
            buttonbackground=PANEL_BG
        ).grid(row=0, column=3, padx=4)

        tk.Label(controls, text="Workers:",
                 bg=PANEL_BG, fg=FG).grid(row=0, column=4, padx=(16, 4))
        self.workers_var = tk.IntVar(value=48)
        tk.Spinbox(
            controls, from_=4, to=64, increment=4,
            textvariable=self.workers_var, width=6,
            bg="#06120a", fg=FG, insertbackground=FG,
            buttonbackground=PANEL_BG
        ).grid(row=0, column=5, padx=4)

        self.scan_btn = tk.Button(
            controls, text="START SCAN", command=self.start_scan,
            bg="#0e5e2b", fg="white", activebackground="#178b42",
            activeforeground="white", relief="flat", padx=14, pady=5
        )
        self.scan_btn.grid(row=0, column=6, padx=(20, 6))

        self.stop_btn = tk.Button(
            controls, text="STOP", command=self.stop_scan,
            bg="#6b1d1d", fg="white", activebackground="#9a2929",
            activeforeground="white", relief="flat", padx=14, pady=5,
            state="disabled"
        )
        self.stop_btn.grid(row=0, column=7, padx=6)

        self.export_btn = tk.Button(
            controls, text="EXPORT CSV", command=self.export_csv,
            bg="#2a3c61", fg="white", activebackground="#3a5687",
            activeforeground="white", relief="flat", padx=14, pady=5
        )
        self.export_btn.grid(row=0, column=8, padx=6)

        body = tk.Frame(self, bg=APP_BG)
        body.pack(fill="both", expand=True, padx=12, pady=6)

        left = tk.Frame(body, bg=PANEL_BG, bd=1, relief="solid")
        left.pack(side="left", fill="y", padx=(0, 8))

        tk.Label(left, text="RADAR",
                 bg=PANEL_BG, fg=ACCENT,
                 font=("Segoe UI", 12, "bold")).pack(pady=(8, 0))

        self.canvas = tk.Canvas(
            left, width=360, height=360, bg="#020b05",
            highlightthickness=0
        )
        self.canvas.pack(padx=10, pady=10)

        self.status_var = tk.StringVar(value="Ready. Scan only networks you own or administer.")
        tk.Label(
            left, textvariable=self.status_var,
            bg=PANEL_BG, fg=FG, wraplength=340,
            justify="left", font=("Segoe UI", 9)
        ).pack(fill="x", padx=10, pady=(0, 10))

        stats = tk.Frame(left, bg=PANEL_BG)
        stats.pack(fill="x", padx=10, pady=(0, 12))
        self.scanned_var = tk.StringVar(value="Scanned: 0")
        self.found_var = tk.StringVar(value="Possible cameras: 0")
        tk.Label(stats, textvariable=self.scanned_var, bg=PANEL_BG, fg=FG).pack(anchor="w")
        tk.Label(stats, textvariable=self.found_var, bg=PANEL_BG, fg=WARN).pack(anchor="w")

        right = tk.Frame(body, bg=PANEL_BG, bd=1, relief="solid")
        right.pack(side="left", fill="both", expand=True)

        cols = ("ip", "status", "ports", "type", "server", "latency")
        self.tree = ttk.Treeview(right, columns=cols, show="headings")
        headers = {
            "ip": "IP Address",
            "status": "Reachable",
            "ports": "Open Ports",
            "type": "Assessment",
            "server": "HTTP Server",
            "latency": "Latency ms",
        }
        widths = {"ip": 130, "status": 75, "ports": 150, "type": 180, "server": 220, "latency": 90}
        for col in cols:
            self.tree.heading(col, text=headers[col])
            self.tree.column(col, width=widths[col], anchor="w")

        vs = ttk.Scrollbar(right, orient="vertical", command=self.tree.yview)
        hs = ttk.Scrollbar(right, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        right.grid_rowconfigure(0, weight=1)
        right.grid_columnconfigure(0, weight=1)

        self.progress = ttk.Progressbar(self, mode="determinate")
        self.progress.pack(fill="x", padx=12, pady=(0, 12))

    def _validate_network(self):
        raw = self.cidr_var.get().strip()
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR: {exc}")

        if not (net.is_private or net.is_loopback or net.is_link_local):
            raise ValueError("Public/internet ranges are blocked. Use a private/local subnet only.")

        if net.version != 4:
            raise ValueError("This version scans IPv4 private networks only.")

        if net.num_addresses > 1024:
            raise ValueError("Range too large. Use /22 or smaller (maximum 1024 addresses).")

        return net

    def start_scan(self):
        try:
            net = self._validate_network()
        except ValueError as exc:
            messagebox.showerror("Target blocked", str(exc))
            return

        self.stop_event.clear()
        self.results.clear()
        self.current_index = 0
        self.target_ips = [str(ip) for ip in net.hosts()]

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.scan_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.progress.configure(maximum=max(1, len(self.target_ips)), value=0)
        self.scanned_var.set("Scanned: 0")
        self.found_var.set("Possible cameras: 0")
        self.status_var.set(f"Scanning {net} on private network...")

        thread = threading.Thread(target=self._scan_worker, daemon=True)
        thread.start()

    def stop_scan(self):
        self.stop_event.set()
        self.status_var.set("Stopping scan...")
        self.stop_btn.configure(state="disabled")

    def _scan_worker(self):
        total = len(self.target_ips)
        timeout = max(0.1, min(float(self.timeout_var.get()), 3.0))
        workers = max(4, min(int(self.workers_var.get()), 64))

        completed = 0
        found = 0

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_map = {
                executor.submit(scan_host, ip, timeout): ip
                for ip in self.target_ips
                if not self.stop_event.is_set()
            }

            for future in as_completed(future_map):
                if self.stop_event.is_set():
                    break

                completed += 1
                try:
                    result = future.result()
                except Exception as exc:
                    result = {
                        "ip": future_map[future],
                        "reachable": False,
                        "open_ports": [],
                        "assessment": f"Scan error: {type(exc).__name__}",
                        "server": "",
                        "latency_ms": "",
                        "possible_camera": False,
                    }

                if result["reachable"] or result["open_ports"]:
                    self.results.append(result)
                    if result["possible_camera"]:
                        found += 1
                    self.msg_queue.put(("result", result))

                self.msg_queue.put(("progress", completed, total, found))

        self.msg_queue.put(("done", completed, total, found, self.stop_event.is_set()))

    def _process_queue(self):
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                kind = msg[0]

                if kind == "result":
                    r = msg[1]
                    ports = ",".join(str(p) for p in r["open_ports"]) or "-"
                    reachable = "Yes" if r["reachable"] else "No"
                    latency = r["latency_ms"] if r["latency_ms"] != "" else "-"
                    self.tree.insert("", "end", values=(
                        r["ip"], reachable, ports, r["assessment"],
                        r["server"] or "-", latency
                    ))
                elif kind == "progress":
                    completed, total, found = msg[1:]
                    self.progress.configure(value=completed)
                    self.scanned_var.set(f"Scanned: {completed}/{total}")
                    self.found_var.set(f"Possible cameras: {found}")
                elif kind == "done":
                    completed, total, found, stopped = msg[1:]
                    self.scan_btn.configure(state="normal")
                    self.stop_btn.configure(state="disabled")
                    if stopped:
                        self.status_var.set(
                            f"Stopped. Checked {completed}/{total} hosts; "
                            f"{found} possible camera device(s) observed."
                        )
                    else:
                        self.status_var.set(
                            f"Finished. Checked {completed}/{total} hosts; "
                            f"{found} possible camera device(s) observed."
                        )
        except queue.Empty:
            pass

        self.after(100, self._process_queue)

    def _animate_radar(self):
        c = self.canvas
        c.delete("all")
        w, h = 360, 360
        cx, cy = w // 2, h // 2
        radius = 155

        # grid rings
        for r in (40, 80, 120, 155):
            c.create_oval(cx-r, cy-r, cx+r, cy+r, outline=GRID)
        c.create_line(cx-radius, cy, cx+radius, cy, fill=GRID)
        c.create_line(cx, cy-radius, cx, cy+radius, fill=GRID)

        # sweep
        import math, time
        angle = (time.time() * 70) % 360
        rad = math.radians(angle)
        x = cx + radius * math.cos(rad)
        y = cy - radius * math.sin(rad)
        c.create_line(cx, cy, x, y, fill=ACCENT, width=2)

        # plot discovered hosts
        for idx, result in enumerate(self.results[-80:]):
            seed = sum(ord(ch) for ch in result["ip"])
            rr = 30 + (seed % 120)
            aa = math.radians((seed * 7) % 360)
            px = cx + rr * math.cos(aa)
            py = cy - rr * math.sin(aa)
            color = WARN if result["possible_camera"] else "#74c0fc"
            size = 4 if result["possible_camera"] else 3
            c.create_oval(px-size, py-size, px+size, py+size, fill=color, outline="")

        c.create_text(cx, 18, text="PRIVATE LAN DISCOVERY RADAR",
                      fill=ACCENT, font=("Consolas", 10, "bold"))
        self.after(80, self._animate_radar)

    def export_csv(self):
        if not self.results:
            messagebox.showinfo("No data", "Run a scan first; there are no results to export.")
            return

        path = filedialog.asksaveasfilename(
            title="Export scan results",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile="cctv_radar_results.csv",
        )
        if not path:
            return

        fields = ["ip", "reachable", "open_ports", "assessment", "server", "latency_ms", "possible_camera"]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            for r in self.results:
                row = dict(r)
                row["open_ports"] = ",".join(str(p) for p in row["open_ports"])
                writer.writerow(row)

        messagebox.showinfo("Export complete", f"Saved:\n{path}")


if __name__ == "__main__":
    app = CCTVScannerApp()
    app.mainloop()
