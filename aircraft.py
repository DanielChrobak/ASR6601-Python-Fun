import serial, threading, time, statistics, struct, platform
from datetime import datetime
from enum import Enum
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Console
from rich import box
import serial.tools.list_ports

class LinkStatus(Enum):
    NO_LINK, ESTABLISHING, LINKED, WEAK_SIGNAL, LINK_LOST = range(5)

DEFAULT_BAUD, HEARTBEAT_INTERVAL, LINK_TIMEOUT, WEAK_SIGNAL_THRESHOLD, LINK_THRESHOLD = 9600, 1.0, 3.0, 2000, 3
KEY = b"0123456789abcdef"  # 16 bytes for AES-128
MSG_TYPE_HEARTBEAT, MSG_TYPE_ACK, PACKET_SIZE = 1, 2, 33

def select_com_port():
    idstr = "USB-SERIAL CH340" if platform.system()=="Windows" else "USB Serial"
    ports = [p for p in serial.tools.list_ports.comports() if idstr.lower() in (p.description or "").lower()]
    if not ports:
        print(f"No ports matching '{idstr}'.")
        return None
    if len(ports) == 1: return ports[0].device
    for idx, p in enumerate(ports, 1): print(f"{idx}: {p.device} - {p.description}")
    while True:
        c = input(f"Select port (1-{len(ports)}): ").strip()
        if c.isdigit() and 1 <= int(c) <= len(ports): return ports[int(c)-1].device
        print("Invalid selection.")

def elapsed_sec_str(ts): return f"{int(time.time() - ts)}s ago" if ts else "N/A"

class Aircraft:
    def __init__(self, port):
        self.console = Console()
        self.port = port
        self.ser = None
        self._run = threading.Event(); self._run.set()
        self.link_status, self.last_ack_time, self.link_start_time = LinkStatus.NO_LINK, None, None
        self.consecutive_acks, self.heartbeat_id, self.sent_count, self.recv_count = 0, 0, 0, 0
        self.sent_times, self.latencies, self.ack_success_history = {}, [], []
        self.last_heartbeat_sent, self.link_uptime = None, 0
        self.lock = threading.Lock()

    def open_port(self):
        try:
            self.ser = serial.Serial(self.port, DEFAULT_BAUD, timeout=0.1)
            print(f"Aircraft opened port {self.port} at {DEFAULT_BAUD} baud.")
        except Exception as e: raise RuntimeError(f"Serial port error: {e}")

    def close_port(self):
        self._run.clear()
        if self.ser and self.ser.is_open: self.ser.close()

    def encrypt_and_send(self, t, i):
        nonce = get_random_bytes(12)
        cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(struct.pack(">BI", t, i))
        try: self.ser.write(nonce + ct + tag); self.ser.flush()
        except Exception: pass

    def decrypt_packet(self, p):
        try:
            cipher = AES.new(KEY, AES.MODE_GCM, nonce=p[:12])
            pt = cipher.decrypt_and_verify(p[12:-16], p[-16:])
            return struct.unpack(">BI", pt)
        except Exception: return (None, None)

    def send_heartbeat(self):
        with self.lock:
            self.heartbeat_id += 1
            hb_id = self.heartbeat_id
            now = time.time()
            self.sent_times[hb_id] = now
            self.sent_count += 1
            self.last_heartbeat_sent = now
        self.encrypt_and_send(MSG_TYPE_HEARTBEAT, hb_id)

    def update_link_status(self):
        now = time.time()
        with self.lock:
            time_since_ack = now - (self.last_ack_time or 0)
            recent_lats = self.latencies[-5:] or [0]
            state = self.link_status

            if self.last_ack_time is None: self.link_status = LinkStatus.NO_LINK
            elif state == LinkStatus.NO_LINK:
                if time_since_ack <= LINK_TIMEOUT: self.link_status, self.link_start_time, self.consecutive_acks = LinkStatus.ESTABLISHING, now, 1
            elif state == LinkStatus.ESTABLISHING:
                if time_since_ack <= LINK_TIMEOUT:
                    if self.consecutive_acks >= LINK_THRESHOLD:
                        self.link_status = LinkStatus.LINKED
                        self.link_start_time = now
                else: self.link_status, self.consecutive_acks = LinkStatus.NO_LINK, 0
            elif state == LinkStatus.LINKED:
                if time_since_ack > LINK_TIMEOUT: self.link_status = LinkStatus.LINK_LOST
                elif max(recent_lats) > WEAK_SIGNAL_THRESHOLD: self.link_status = LinkStatus.WEAK_SIGNAL
            elif state == LinkStatus.WEAK_SIGNAL:
                if time_since_ack > LINK_TIMEOUT: self.link_status = LinkStatus.LINK_LOST
                elif max(recent_lats) <= WEAK_SIGNAL_THRESHOLD: self.link_status = LinkStatus.LINKED
            elif state == LinkStatus.LINK_LOST:
                if time_since_ack <= LINK_TIMEOUT: self.link_status = LinkStatus.LINKED

    def calculate_link_quality(self):
        h = self.ack_success_history
        return (sum(h)/len(h))*100 if h else 0

    def read_loop(self):
        buffer = b""
        while self._run.is_set():
            try:
                if not self.ser or not self.ser.is_open: break
                buffer += self.ser.read(PACKET_SIZE - len(buffer))
                while len(buffer) >= PACKET_SIZE:
                    packet, buffer = buffer[:PACKET_SIZE], buffer[PACKET_SIZE:]
                    msg_type, msg_id = self.decrypt_packet(packet)
                    if msg_type == MSG_TYPE_ACK:
                        curr = time.time()
                        with self.lock:
                            self.ack_success_history.append(1)
                            if len(self.ack_success_history) > 20: self.ack_success_history.pop(0)
                            st = self.sent_times.pop(msg_id, None)
                            if st:
                                rtt = (curr - st)*1000
                                self.latencies.append(rtt)
                                if len(self.latencies) > 100: self.latencies.pop(0)
                            self.recv_count += 1
                            self.last_ack_time = curr
                            if self.link_status in (LinkStatus.NO_LINK, LinkStatus.ESTABLISHING): self.consecutive_acks += 1
            except Exception:
                with self.lock:
                    self.ack_success_history.append(0)
                    if len(self.ack_success_history)>20: self.ack_success_history.pop(0)
                time.sleep(0.1)

    def heartbeat_loop(self):
        while self._run.is_set():
            self.send_heartbeat()
            time.sleep(HEARTBEAT_INTERVAL)

    def link_monitor_loop(self):
        while self._run.is_set():
            self.update_link_status()
            time.sleep(0.1)

    def get_link_color(self):
        idx2clr = ["red", "yellow", "green", "orange", "red"]
        return idx2clr[self.link_status.value]

    def get_link_symbol(self):
        idx2sym = ["❌", "🔄", "✅", "📶", "⚠️"]
        return idx2sym[self.link_status.value]

    def build_display(self):
        layout = Layout()
        layout.split_column(Layout(name="header", size=3), Layout(name="main"), Layout(name="footer", size=3))
        # Header
        lc, ls = self.get_link_color(), self.get_link_symbol()
        layout["header"].update(Panel(f"{ls} Ground Station Link: [{lc}]{self.link_status.name}[/{lc}]", title="Aircraft Transmitter Status", box=box.ROUNDED))
        layout["main"].split_row(Layout(name="left"), Layout(name="right"))
        # Stats
        with self.lock:
            sent, recv, lats = self.sent_count, self.recv_count, self.latencies[:]
            la, lhb = self.last_ack_time, self.last_heartbeat_sent
            lq = self.calculate_link_quality()
            uptime_str = f"{int((time.time()-self.link_start_time)//60):02d}:{int((time.time()-self.link_start_time)%60):02d}" if self.link_status == LinkStatus.LINKED and self.link_start_time else "00:00"
            ploss = max(0.0, (sent-recv)/sent*100) if sent else 0
            tsa = (time.time()-la)*1000 if la else 0
            ack_col = "green" if tsa<=1500 else "yellow" if tsa<=3000 else "red"
            thb = (time.time()-lhb)*1000 if lhb else 0
        link_table = Table(title="📡 Ground Station Link", box=box.ROUNDED)
        link_table.add_column("Parameter"), link_table.add_column("Value", justify="right")
        link_table.add_row("Status", f"[{lc}]{self.link_status.name}[/{lc}]")
        link_table.add_row("Link Quality", f"[{'green' if lq>90 else 'yellow' if lq>70 else 'red'}]{lq:.1f}%[/]")
        link_table.add_row("Uptime", f"[cyan]{uptime_str}[/cyan]")
        link_table.add_row("Packet Loss", f"[{'green' if ploss<5 else 'yellow' if ploss<15 else 'red'}]{ploss:.1f}%[/]")
        link_table.add_row("Heartbeats Sent", str(sent))
        link_table.add_row("ACKs Recv'd", str(recv))
        link_table.add_row("Last Heartbeat", elapsed_sec_str(lhb))
        link_table.add_row("Last ACK", elapsed_sec_str(la))
        link_table.add_row("Time Since ACK", f"[{ack_col}]{tsa:.0f}ms[/{ack_col}]")
        layout["left"].update(link_table)
        # Performance
        min_lat = min(lats) if lats else 0
        max_lat = max(lats) if lats else 0
        avg_lat = (sum(lats)/len(lats)) if lats else 0
        std_lat = statistics.stdev(lats) if len(lats)>1 else 0
        perf_table = Table(title="⚡ Performance Metrics", box=box.ROUNDED)
        perf_table.add_column("Metric"), perf_table.add_column("Value", justify="right")
        perf_table.add_row("Min RTT", f"{min_lat:.2f}ms")
        perf_table.add_row("Max RTT", f"{max_lat:.2f}ms")
        perf_table.add_row("Avg RTT", f"{avg_lat:.2f}ms")
        perf_table.add_row("Last RTT", f"{lats[-1]:.2f}ms" if lats else "0.0ms")
        perf_table.add_row("RTT Jitter", f"{std_lat:.2f}ms")
        layout["right"].update(perf_table)
        # Status/Warnings
        foot = {
            LinkStatus.NO_LINK: "[red]❌ No ground station detected - Check radio connection[/red]",
            LinkStatus.ESTABLISHING: "[yellow]🔄 Establishing link...[/yellow]",
            LinkStatus.LINKED: "[green]✅ Aircraft ready[/green]",
            LinkStatus.WEAK_SIGNAL: "[orange]📶 Weak signal - Check range[/orange]",
            LinkStatus.LINK_LOST: "[red]⚠️ Link lost - Reconnecting[/red]",
        }
        layout["footer"].update(Panel(foot.get(self.link_status), box=box.ROUNDED))
        return layout

    def run(self):
        try: self.open_port()
        except RuntimeError as e: print(e); return
        threads = [
            threading.Thread(target=self.read_loop, daemon=True),
            threading.Thread(target=self.heartbeat_loop, daemon=True),
            threading.Thread(target=self.link_monitor_loop, daemon=True),
        ]
        for t in threads: t.start()
        try:
            with Live(self.build_display(), refresh_per_second=4) as live:
                while self._run.is_set():
                    time.sleep(0.25)
                    live.update(self.build_display())
        except KeyboardInterrupt:
            print("\nShutting down aircraft transmitter...")
        self._run.clear()
        for t in threads: t.join(1)
        self.close_port()

if __name__ == "__main__":
    print("=== RC Aircraft Transmitter ===")
    port = select_com_port()
    if port: Aircraft(port).run()
    else: print("Port selection failed. Exiting.")
