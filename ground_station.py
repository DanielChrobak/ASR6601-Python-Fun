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

class ConnState(Enum):
    DISCONNECTED, CONNECTING, CONNECTED, SIGNAL_LOST, FAILSAFE = range(5)
DEFAULT_BAUD, CONN_TIMEOUT, FAILSAFE_TIMEOUT, CONNECT_THRESHOLD = 9600, 3.0, 8.0, 3
KEY = b"0123456789abcdef"
MSG_TYPE_HEARTBEAT, MSG_TYPE_ACK, PACKET_SIZE = 1, 2, 33

def select_com_port():
    idstr = "USB-SERIAL CH340" if platform.system()=="Windows" else "USB Serial"
    ports = [p for p in serial.tools.list_ports.comports() if idstr.lower() in (p.description or "").lower()]
    if not ports:
        print(f"No ports matching '{idstr}'."); return None
    if len(ports)==1: return ports[0].device
    for idx,p in enumerate(ports,1): print(f"{idx}: {p.device} - {p.description}")
    while True:
        c = input(f"Select port (1-{len(ports)}): ").strip()
        if c.isdigit() and 1 <= int(c) <= len(ports): return ports[int(c)-1].device
        print("Invalid selection.")

def elapsed_sec_str(ts): return f"{int(time.time() - ts)}s ago" if ts else "N/A"

class GroundStation:
    def __init__(self, port):
        self.port = port; self.console = Console(); self.ser = None
        self._run = threading.Event(); self._run.set()
        # State
        self.connection_state, self.last_heartbeat_time, self.connection_start_time = ConnState.DISCONNECTED, None, None
        self.consecutive_heartbeats, self.received_count, self.ack_sent_count = 0, 0, 0
        self.heartbeat_intervals, self.last_heartbeat_id, self.packet_success_history = [], None, []
        self.lock = threading.Lock()

    def open_port(self):
        try:
            self.ser = serial.Serial(self.port, DEFAULT_BAUD, timeout=0.1)
            print(f"Ground Station opened port {self.port} at {DEFAULT_BAUD} baud.")
        except Exception as e:
            raise RuntimeError(f"Serial port error: {e}")

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

    def send_ack(self, hb_id):
        self.encrypt_and_send(MSG_TYPE_ACK, hb_id)
        with self.lock: self.ack_sent_count += 1

    def update_connection_state(self):
        now = time.time()
        with self.lock:
            tsl = now - (self.last_heartbeat_time or 0)
            state = self.connection_state
            if self.last_heartbeat_time is None: self.connection_state = ConnState.DISCONNECTED
            elif state == ConnState.DISCONNECTED:
                if tsl <= CONN_TIMEOUT:
                    self.connection_state, self.consecutive_heartbeats = ConnState.CONNECTING, 1
                    self.connection_start_time = now
            elif state == ConnState.CONNECTING:
                if tsl <= CONN_TIMEOUT:
                    if self.consecutive_heartbeats >= CONNECT_THRESHOLD:
                        self.connection_state, self.connection_start_time = ConnState.CONNECTED, now
                else: self.connection_state, self.consecutive_heartbeats = ConnState.DISCONNECTED, 0
            elif state == ConnState.CONNECTED:
                if tsl > FAILSAFE_TIMEOUT: self.connection_state = ConnState.FAILSAFE
                elif tsl > CONN_TIMEOUT: self.connection_state = ConnState.SIGNAL_LOST
            elif state == ConnState.SIGNAL_LOST:
                if tsl <= CONN_TIMEOUT: self.connection_state = ConnState.CONNECTED
                elif tsl > FAILSAFE_TIMEOUT: self.connection_state = ConnState.FAILSAFE
            elif state == ConnState.FAILSAFE:
                if tsl <= CONN_TIMEOUT: self.connection_state = ConnState.CONNECTED

    def calculate_signal_quality(self):
        h = self.packet_success_history
        return (sum(h) / len(h)) * 100 if h else 0

    def read_loop(self):
        buffer = b""
        while self._run.is_set():
            try:
                if not self.ser or not self.ser.is_open: break
                buffer += self.ser.read(PACKET_SIZE - len(buffer))
                while len(buffer) >= PACKET_SIZE:
                    packet, buffer = buffer[:PACKET_SIZE], buffer[PACKET_SIZE:]
                    msg_type, msg_id = self.decrypt_packet(packet)
                    if msg_type == MSG_TYPE_HEARTBEAT:
                        curr = time.time()
                        with self.lock:
                            self.packet_success_history.append(1)
                            if len(self.packet_success_history) > 20:
                                self.packet_success_history.pop(0)
                            self.received_count += 1
                            if self.last_heartbeat_time is not None:
                                intv = curr - self.last_heartbeat_time
                                self.heartbeat_intervals.append(intv * 1000)
                                if len(self.heartbeat_intervals) > 100: self.heartbeat_intervals.pop(0)
                            self.last_heartbeat_time = curr
                            self.last_heartbeat_id = msg_id
                            if self.connection_state in (ConnState.DISCONNECTED, ConnState.CONNECTING): self.consecutive_heartbeats += 1
                        self.send_ack(msg_id)
            except Exception:
                with self.lock:
                    self.packet_success_history.append(0)
                    if len(self.packet_success_history)>20: self.packet_success_history.pop(0)
                time.sleep(0.1)

    def connection_monitor_loop(self):
        while self._run.is_set():
            self.update_connection_state()
            time.sleep(0.1)

    def get_connection_color(self):
        return ["red", "yellow", "green", "orange", "magenta"][self.connection_state.value]

    def get_connection_symbol(self):
        return ["❌", "🔄", "✅", "⚠️", "🚨"][self.connection_state.value]

    def build_display(self):
        layout = Layout()
        layout.split_column(Layout(name="header", size=3), Layout(name="main"), Layout(name="footer", size=3))
        cc, cs = self.get_connection_color(), self.get_connection_symbol()
        layout["header"].update(Panel(f"{cs} Aircraft Connection: [{cc}]{self.connection_state.name}[/{cc}]", title="Ground Station Status", box=box.ROUNDED))
        layout["main"].split_row(Layout(name="left"), Layout(name="right"))
        with self.lock:
            rcvd, acsnt, ints = self.received_count, self.ack_sent_count, self.heartbeat_intervals[:]
            lht, lhid = self.last_heartbeat_time, self.last_heartbeat_id
            sigq = self.calculate_signal_quality()
            uptime_str = f"{int((time.time()-self.connection_start_time)//60):02d}:{int((time.time()-self.connection_start_time)%60):02d}" if self.connection_state==ConnState.CONNECTED and self.connection_start_time else "00:00"
            time_since_last = (time.time()-lht)*1000 if lht else 0
            time_col = "green" if time_since_last<=1500 else "yellow" if time_since_last<=3000 else "red"
        # Stats
        conn_table = Table(title="🛰️ Aircraft Link Status", box=box.ROUNDED)
        conn_table.add_column("Parameter"), conn_table.add_column("Value", justify="right")
        conn_table.add_row("State", f"[{cc}]{self.connection_state.name}[/{cc}]")
        conn_table.add_row("Signal Quality", f"[{'green' if sigq>80 else 'yellow' if sigq>50 else 'red'}]{sigq:.1f}%[/]")
        conn_table.add_row("Uptime", f"[cyan]{uptime_str}[/cyan]")
        conn_table.add_row("Heartbeats Recv'd", f"[blue]{rcvd}[/blue]")
        conn_table.add_row("Last Heartbeat ID", f"[blue]{lhid if lhid else 'N/A'}[/blue]")
        conn_table.add_row("Last Heartbeat", elapsed_sec_str(lht))
        conn_table.add_row("Time Since Last", f"[{time_col}]{time_since_last:.0f}ms[/{time_col}]")
        layout["left"].update(conn_table)
        # Metrics
        minint, maxint=(min(ints),max(ints)) if ints else (0,0)
        avgint = (sum(ints)/len(ints)) if ints else 0
        stdint = statistics.stdev(ints) if len(ints)>1 else 0
        tech_table = Table(title="📊 Technical Metrics", box=box.ROUNDED)
        tech_table.add_column("Metric"), tech_table.add_column("Value", justify="right")
        tech_table.add_row("Acks Sent", str(acsnt))
        tech_table.add_row("Min Interval", f"{minint:.2f}ms")
        tech_table.add_row("Max Interval", f"{maxint:.2f}ms")
        tech_table.add_row("Avg Interval", f"{avgint:.2f}ms")
        tech_table.add_row("Last Interval", f"{ints[-1]:.2f}ms" if ints else "0.0ms")
        tech_table.add_row("Jitter (StdDev)", f"{stdint:.2f}ms")
        tech_table.add_row("Consecutive HB", str(self.consecutive_heartbeats))
        layout["right"].update(tech_table)
        # Footer
        foot = {
            ConnState.FAILSAFE: "[red]⚠️ FAILSAFE MODE ACTIVE - NO AIRCRAFT CONTROL ⚠️[/red]",
            ConnState.SIGNAL_LOST: "[yellow]⚠️ Signal Lost - Reconnecting...[/yellow]",
            ConnState.CONNECTING: "[yellow]🔄 Establishing connection...[/yellow]",
            ConnState.CONNECTED: "[green]✅ Aircraft connected and ready for control[/green]",
            ConnState.DISCONNECTED: "[red]❌ No aircraft detected - Waiting for connection...[/red]",
        }
        layout["footer"].update(Panel(foot[self.connection_state], box=box.ROUNDED))
        return layout

    def run(self):
        try: self.open_port()
        except RuntimeError as e: print(e); return
        threads = [
            threading.Thread(target=self.read_loop, daemon=True),
            threading.Thread(target=self.connection_monitor_loop, daemon=True),
        ]
        for t in threads: t.start()
        try:
            with Live(self.build_display(), refresh_per_second=4) as live:
                while self._run.is_set():
                    time.sleep(0.25)
                    live.update(self.build_display())
        except KeyboardInterrupt: print("\nShutting down ground station...")
        self._run.clear()
        for t in threads: t.join(1)
        self.close_port()

if __name__ == "__main__":
    print("=== RC Aircraft Ground Station ===")
    port = select_com_port()
    if port: GroundStation(port).run()
    else: print("Port selection failed. Exiting.")
