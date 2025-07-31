import serial
import threading
import time
import statistics
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import struct
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Console
from rich import box
import serial.tools.list_ports
import platform
from datetime import datetime
from enum import Enum


def select_com_port():
    """
    Scan all available serial ports and let user select one whose description matches 
    the CH340 device identifier based on the operating system.
    Windows: "USB-SERIAL CH340"
    Linux/Other: "USB Serial"
    """
    # Detect OS and set appropriate device identifier
    if platform.system() == "Windows":
        device_identifier = "USB-SERIAL CH340"
    else:
        device_identifier = "USB Serial"
    
    ports = list(serial.tools.list_ports.comports())
    matches = [p for p in ports if device_identifier.lower() in (p.description or "").lower()]

    if not matches:
        print(f"No ports matching '{device_identifier}' found. Available ports:")
        for i, p in enumerate(ports, 1):
            print(f" {i}: {p.device} - {p.description}")
        return None

    if len(matches) == 1:
        print(f"Found port {matches[0].device} for device '{device_identifier}'")
        return matches[0].device

    # Multiple matches found. Prompt user to select one:
    print(f"Multiple ports matching '{device_identifier}' found:")
    for i, p in enumerate(matches, 1):
        print(f" {i}: {p.device} - {p.description}")
    while True:
        choice = input(f"Select port (1-{len(matches)}): ").strip()
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(matches):
                return matches[idx - 1].device
        print("Invalid selection, try again.")


class ConnectionState(Enum):
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    SIGNAL_LOST = "SIGNAL_LOST"
    FAILSAFE = "FAILSAFE"


DEFAULT_BAUD = 9600
CONNECTION_TIMEOUT = 3.0  # seconds - signal lost if no heartbeat
FAILSAFE_TIMEOUT = 8.0   # seconds - enter failsafe mode
CONNECT_THRESHOLD = 3    # consecutive heartbeats needed to establish connection

KEY = b"0123456789abcdef"  # AES-128 key (16 bytes)

MSG_TYPE_HEARTBEAT = 1
MSG_TYPE_ACK = 2

PACKET_SIZE = 33  # 12 nonce + 5 ciphertext + 16 tag


class GroundStation:
    def __init__(self, port):
        self.ser = None
        self.port = port
        self._run = threading.Event()
        self._run.set()
        self.console = Console()

        # Connection management
        self.connection_state = ConnectionState.DISCONNECTED
        self.last_heartbeat_time = None
        self.connection_start_time = None
        self.consecutive_heartbeats = 0
        
        # Statistics
        self.received_count = 0
        self.ack_sent_count = 0
        self.heartbeat_intervals = []
        self.last_heartbeat_id = None
        self.packet_success_history = []  # Track last 20 packets for signal quality
        self.expected_heartbeat_ids = set()
        self.connection_uptime = 0
        
        self.lock = threading.Lock()

    def open_port(self):
        try:
            self.ser = serial.Serial(self.port, DEFAULT_BAUD, timeout=0.1)
            print(f"Ground Station opened port {self.port} at {DEFAULT_BAUD} baud.")
        except Exception as e:
            raise RuntimeError(f"Failed to open serial port {self.port}: {e}")

    def close_port(self):
        self._run.clear()
        if self.ser and self.ser.is_open:
            self.ser.close()

    def encrypt_and_send(self, msg_type, msg_id):
        plaintext = struct.pack(">BI", msg_type, msg_id)
        nonce = get_random_bytes(12)
        cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        packet = nonce + ciphertext + tag
        try:
            self.ser.write(packet)
            self.ser.flush()
        except Exception:
            pass

    def decrypt_packet(self, packet):
        try:
            nonce = packet[:12]
            tag = packet[-16:]
            ciphertext = packet[12:-16]
            cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            msg_type, msg_id = struct.unpack(">BI", plaintext)
            return msg_type, msg_id
        except Exception:
            return None, None

    def send_ack(self, heartbeat_id):
        self.encrypt_and_send(MSG_TYPE_ACK, heartbeat_id)
        with self.lock:
            self.ack_sent_count += 1

    def update_connection_state(self):
        """Update connection state based on heartbeat timing"""
        current_time = time.time()
        
        with self.lock:
            if self.last_heartbeat_time is None:
                self.connection_state = ConnectionState.DISCONNECTED
                return

            time_since_last = current_time - self.last_heartbeat_time

            if self.connection_state == ConnectionState.DISCONNECTED:
                if time_since_last <= CONNECTION_TIMEOUT:
                    self.connection_state = ConnectionState.CONNECTING
                    self.consecutive_heartbeats = 1
                    self.connection_start_time = current_time

            elif self.connection_state == ConnectionState.CONNECTING:
                if time_since_last <= CONNECTION_TIMEOUT:
                    if self.consecutive_heartbeats >= CONNECT_THRESHOLD:
                        self.connection_state = ConnectionState.CONNECTED
                        self.connection_start_time = current_time
                else:
                    self.connection_state = ConnectionState.DISCONNECTED
                    self.consecutive_heartbeats = 0

            elif self.connection_state == ConnectionState.CONNECTED:
                if time_since_last > FAILSAFE_TIMEOUT:
                    self.connection_state = ConnectionState.FAILSAFE
                elif time_since_last > CONNECTION_TIMEOUT:
                    self.connection_state = ConnectionState.SIGNAL_LOST

            elif self.connection_state == ConnectionState.SIGNAL_LOST:
                if time_since_last <= CONNECTION_TIMEOUT:
                    self.connection_state = ConnectionState.CONNECTED
                elif time_since_last > FAILSAFE_TIMEOUT:
                    self.connection_state = ConnectionState.FAILSAFE

            elif self.connection_state == ConnectionState.FAILSAFE:
                if time_since_last <= CONNECTION_TIMEOUT:
                    self.connection_state = ConnectionState.CONNECTED

    def calculate_signal_quality(self):
        """Calculate signal quality percentage based on recent packet success"""
        if len(self.packet_success_history) == 0:
            return 0
        
        success_count = sum(self.packet_success_history)
        return (success_count / len(self.packet_success_history)) * 100

    def read_loop(self):
        buffer = b""
        while self._run.is_set():
            try:
                if not self.ser or not self.ser.is_open:
                    break
                data = self.ser.read(PACKET_SIZE - len(buffer))
                if not data:
                    continue
                buffer += data
                while len(buffer) >= PACKET_SIZE:
                    packet = buffer[:PACKET_SIZE]
                    buffer = buffer[PACKET_SIZE:]
                    msg_type, msg_id = self.decrypt_packet(packet)
                    if msg_type == MSG_TYPE_HEARTBEAT:
                        current_time = time.time()
                        with self.lock:
                            # Track packet success
                            self.packet_success_history.append(1)
                            if len(self.packet_success_history) > 20:
                                self.packet_success_history.pop(0)
                            
                            self.received_count += 1
                            if self.last_heartbeat_time is not None:
                                interval = current_time - self.last_heartbeat_time
                                self.heartbeat_intervals.append(interval * 1000)
                                if len(self.heartbeat_intervals) > 100:
                                    self.heartbeat_intervals.pop(0)
                            
                            self.last_heartbeat_time = current_time
                            self.last_heartbeat_id = msg_id
                            
                            # Update consecutive heartbeats for connection establishment
                            if self.connection_state in [ConnectionState.DISCONNECTED, ConnectionState.CONNECTING]:
                                self.consecutive_heartbeats += 1
                        
                        # Send ACK back
                        self.send_ack(msg_id)
            except Exception:
                with self.lock:
                    # Track packet failure
                    self.packet_success_history.append(0)
                    if len(self.packet_success_history) > 20:
                        self.packet_success_history.pop(0)
                time.sleep(0.1)

    def connection_monitor_loop(self):
        """Monitor connection state continuously"""
        while self._run.is_set():
            self.update_connection_state()
            time.sleep(0.1)

    def get_connection_color(self):
        """Get color for connection status display"""
        colors = {
            ConnectionState.DISCONNECTED: "red",
            ConnectionState.CONNECTING: "yellow",
            ConnectionState.CONNECTED: "green",
            ConnectionState.SIGNAL_LOST: "orange",
            ConnectionState.FAILSAFE: "magenta"
        }
        return colors.get(self.connection_state, "white")

    def get_connection_symbol(self):
        """Get symbol for connection status"""
        symbols = {
            ConnectionState.DISCONNECTED: "❌",
            ConnectionState.CONNECTING: "🔄",
            ConnectionState.CONNECTED: "✅",
            ConnectionState.SIGNAL_LOST: "⚠️",
            ConnectionState.FAILSAFE: "🚨"
        }
        return symbols.get(self.connection_state, "❓")

    def build_display(self):
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        # Header - Connection Status
        connection_color = self.get_connection_color()
        connection_symbol = self.get_connection_symbol()
        header_text = f"{connection_symbol} Aircraft Connection: [{connection_color}]{self.connection_state.value}[/{connection_color}]"
        layout["header"].update(Panel(header_text, title="Ground Station Status", box=box.ROUNDED))

        # Main content
        layout["main"].split_row(
            Layout(name="left"),
            Layout(name="right")
        )

        # Left side - Connection Stats
        with self.lock:
            received = self.received_count
            acks_sent = self.ack_sent_count
            intervals = self.heartbeat_intervals[:]
            last_hb_time = self.last_heartbeat_time
            last_hb_id = self.last_heartbeat_id
            signal_quality = self.calculate_signal_quality()

        # Calculate connection uptime
        if self.connection_state == ConnectionState.CONNECTED and self.connection_start_time:
            uptime = time.time() - self.connection_start_time
            uptime_str = f"{int(uptime//60):02d}:{int(uptime%60):02d}"
        else:
            uptime_str = "00:00"

        # Calculate time since last heartbeat
        if last_hb_time:
            time_since_last = (time.time() - last_hb_time) * 1000
            last_hb_timestamp = datetime.fromtimestamp(last_hb_time).strftime("%H:%M:%S.%f")[:-3]
            
            # Determine status color based on time since last
            if time_since_last <= 1500:  # Normal
                time_color = "green"
            elif time_since_last <= 3000:  # Warning
                time_color = "yellow"
            else:  # Critical
                time_color = "red"
        else:
            time_since_last = 0
            last_hb_timestamp = "N/A"
            time_color = "red"

        connection_table = Table(title="🛰️ Aircraft Link Status", box=box.ROUNDED)
        connection_table.add_column("Parameter", justify="left")
        connection_table.add_column("Value", justify="right")
        
        connection_table.add_row("Connection State", f"[{connection_color}]{self.connection_state.value}[/{connection_color}]")
        connection_table.add_row("Signal Quality", f"[{'green' if signal_quality > 80 else 'yellow' if signal_quality > 50 else 'red'}]{signal_quality:.1f}%[/]")
        connection_table.add_row("Connection Uptime", f"[cyan]{uptime_str}[/cyan]")
        connection_table.add_row("Heartbeats Received", f"[blue]{received}[/blue]")
        connection_table.add_row("Last Heartbeat ID", f"[blue]{last_hb_id if last_hb_id else 'N/A'}[/blue]")
        connection_table.add_row("Last Heartbeat", f"[blue]{last_hb_timestamp}[/blue]")
        connection_table.add_row("Time Since Last", f"[{time_color}]{time_since_last:.0f}ms[/{time_color}]")

        layout["left"].update(connection_table)

        # Right side - Technical Stats
        if intervals:
            min_interval = min(intervals)
            max_interval = max(intervals)
            avg_interval = sum(intervals) / len(intervals)
            last_interval = intervals[-1] if intervals else 0
            stddev_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
        else:
            min_interval = max_interval = avg_interval = last_interval = stddev_interval = 0.0

        tech_table = Table(title="📊 Technical Metrics", box=box.ROUNDED)
        tech_table.add_column("Metric", justify="left")
        tech_table.add_column("Value", justify="right")
        
        tech_table.add_row("Acks Sent", str(acks_sent))
        tech_table.add_row("Min Interval", f"{min_interval:.2f}ms")
        tech_table.add_row("Max Interval", f"{max_interval:.2f}ms")
        tech_table.add_row("Avg Interval", f"{avg_interval:.2f}ms")
        tech_table.add_row("Last Interval", f"{last_interval:.2f}ms")
        tech_table.add_row("Jitter (StdDev)", f"{stddev_interval:.2f}ms")
        tech_table.add_row("Consecutive HB", str(self.consecutive_heartbeats))

        layout["right"].update(tech_table)

        # Footer - Warnings/Status
        footer_text = ""
        if self.connection_state == ConnectionState.FAILSAFE:
            footer_text = "[red]⚠️ FAILSAFE MODE ACTIVE - NO AIRCRAFT CONTROL ⚠️[/red]"
        elif self.connection_state == ConnectionState.SIGNAL_LOST:
            footer_text = "[yellow]⚠️ Signal Lost - Attempting to reconnect...[/yellow]"
        elif self.connection_state == ConnectionState.CONNECTING:
            footer_text = "[yellow]🔄 Establishing connection to aircraft...[/yellow]"
        elif self.connection_state == ConnectionState.CONNECTED:
            footer_text = "[green]✅ Aircraft connected and ready for control[/green]"
        else:
            footer_text = "[red]❌ No aircraft detected - Waiting for connection...[/red]"

        layout["footer"].update(Panel(footer_text, box=box.ROUNDED))
        
        return layout

    def run(self):
        try:
            self.open_port()
        except RuntimeError as e:
            print(e)
            return

        threads = [
            threading.Thread(target=self.read_loop, daemon=True),
            threading.Thread(target=self.connection_monitor_loop, daemon=True),
        ]
        for t in threads:
            t.start()

        try:
            with Live(self.build_display(), refresh_per_second=4) as live:
                while self._run.is_set():
                    time.sleep(0.25)
                    live.update(self.build_display())
        except KeyboardInterrupt:
            print("\nShutting down ground station...")
            self._run.clear()
            for t in threads:
                t.join(timeout=1)
            self.close_port()


if __name__ == "__main__":
    print("=== RC Aircraft Ground Station ===")
    port = select_com_port()
    if port is None:
        print("Port selection failed. Exiting.")
    else:
        ground_station = GroundStation(port)
        ground_station.run()
