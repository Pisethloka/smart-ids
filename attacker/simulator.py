import platform
import socket
import subprocess
import threading
import time


class AttackSimulator:
    def __init__(self, log_callback=None):
        self.log_callback = log_callback
        self.stop_event = threading.Event()
        self.worker = None

    def log(self, message):
        if self.log_callback:
            self.log_callback(message)

    def stop(self):
        self.stop_event.set()
        self.log("Stop requested")

    def run_in_thread(self, action, *args):
        if self.worker and self.worker.is_alive():
            self.log("Another action is already running")
            return

        self.stop_event.clear()
        self.worker = threading.Thread(target=action, args=args, daemon=True)
        self.worker.start()

    def simulate_port_scan(self, target, start_port=20, end_port=60):
        self.log(f"Port scan -> {target} [{start_port}-{end_port}]")

        for port in range(start_port, end_port + 1):
            if self.stop_event.is_set():
                self.log("Port scan stopped")
                return

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.2)
            try:
                sock.connect((target, port))
                self.log(f"OPEN   {target}:{port}")
            except Exception:
                self.log(f"CLOSED {target}:{port}")
            finally:
                sock.close()

            time.sleep(0.03)

        self.log("Port scan finished")

    def simulate_ping_burst(self, target, count=25):
        self.log(f"Ping burst -> {target} [{count}]")

        system_name = platform.system().lower()
        if "windows" in system_name:
            command = ["ping", "-n", str(count), target]
        else:
            command = ["ping", "-i", "0.2", "-c", str(count), target]

        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            while True:
                if self.stop_event.is_set():
                    process.terminate()
                    self.log("Ping burst stopped")
                    return

                line = process.stdout.readline()
                if not line:
                    break
                self.log(line.strip())

            process.wait()
            self.log("Ping burst finished")
        except Exception as error:
            self.log(f"Ping error: {error}")

    def simulate_tcp_burst(self, target, port=8000, connections=50):
        self.log(f"TCP burst -> {target}:{port} [{connections}]")

        success_count = 0
        fail_count = 0

        for index in range(connections):
            if self.stop_event.is_set():
                self.log("TCP burst stopped")
                return

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.25)

            try:
                sock.connect((target, port))
                success_count += 1
                self.log(f"{index + 1}/{connections} connected")
            except Exception:
                fail_count += 1
                self.log(f"{index + 1}/{connections} failed")
            finally:
                sock.close()

            time.sleep(0.02)

        self.log(f"TCP burst finished | success={success_count} fail={fail_count}")