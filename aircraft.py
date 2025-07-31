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


class LinkStatus(Enum):
    NO_LINK = "NO_LINK"
    ESTABLISHING = "ESTABLISHING"
    LINKED = "LINKED"
    WEAK_SIGNAL = "WEAK_SIGNAL"
    LINK_LOST = "LINK_LOST"


DEFAULT_BAUD = 9600
HEARTBEAT_INTERVAL = 1.0  # seconds
LINK_TIMEOUT = 3.0       # seconds - consider link lost if no ACK
WEAK_SIGNAL_THRESHOLD = 2000  # ms - RTT threshold for weak signal
LINK_THRESHOLD = 3       # consecutive ACKs needed to establish link

KEY = b"0123456789abcdef"  # AES-128 key (16 bytes)

MSG_TYPE_HEARTBEAT = 1
MSG_TYPE_ACK = 2

PACKET_SIZE = 33  # 12 nonce + 5 ciphertext + 16 tag


class Aircraft:
    def __init__(self, port):
        self.ser = None
        self.port = port
        self._run = threading.Event()
        self._run.set()
        self.console = Console()

        # Link management
        self.link_status = LinkStatus.NO_LINK
        self.last_ack_time = None
        self.link_start_time = None
        self.consecutive_acks = 0
        
        # Statistics
        self.heartbeat_id = 0
        self.sent_times = {}  # heartbeat_id -> send timestamp
        self.latencies = []
        self.sent_count = 0
        self.recv_count = 0
        self.last_heartbeat_sent = None
        self.ack_success_history = []  # Track last 20 ACKs for link quality
        self.link_uptime = 0
        
        self.lock = threading.Lock()

    def open_port(self):
        try:
            self.ser = serial.Serial(self.port, DEFAULT_BAUD, timeout=0.1)
            print(f"Aircraft opened port {self.port} at {DEFAULT_BAUD} baud.")
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

    def send_heartbeat(self):
        current_time = time.time()
        with self.lock:
            self.heartbeat_id += 1
            hb_id = self.heartbeat_id
            self.sent_times[hb_id] = current_time
            self.sent_count += 1
            self.last_heartbeat_sent = current_time
        
        self.encrypt_and_send(MSG_TYPE_HEARTBEAT, hb_id)

    def update_link_status(self):
        """Update link status based on ACK timing"""
        current_time = time.time()
        
        with self.lock:
            if self.last_ack_time is None:
                self.link_status = LinkStatus.NO_LINK
                return

            time_since_ack = current_time - self.last_ack_time
            recent_latencies = self.latencies[-5:] if len(self.latencies) >= 5 else self.latencies

            if self.link_status == LinkStatus.NO_LINK:
                if time_since_ack <= LINK_TIMEOUT:
                    self.link_status = LinkStatus.ESTABLISHING
                    self.consecutive_acks = 1
                    self.link_start_time = current_time

            elif self.link_status == LinkStatus.ESTABLISHING:
                if time_since_ack <= LINK_TIMEOUT:
                    if self.consecutive_acks >= LINK_THRESHOLD:
                        self.link_status = LinkStatus.LINKED
                        self.link_start_time = current_time
                else:
                    self.link_status = LinkStatus.NO_LINK
                    self.consecutive_acks = 0

            elif self.link_status == LinkStatus.LINKED:
                if time_since_ack > LINK_TIMEOUT:
                    self.link_status = LinkStatus.LINK_LOST
                elif recent_latencies and max(recent_latencies) > WEAK_SIGNAL_THRESHOLD:
                    self.link_status = LinkStatus.WEAK_SIGNAL

            elif self.link_status == LinkStatus.WEAK_SIGNAL:
                if time_since_ack > LINK_TIMEOUT:
                    self.link_status = LinkStatus.LINK_LOST
                elif recent_latencies and max(recent_latencies) <= WEAK_SIGNAL_THRESHOLD:
                    self.link_status = LinkStatus.LINKED

            elif self.link_status == LinkStatus.LINK_LOST:
                if time_since_ack <= LINK_TIMEOUT:
                    self.link_status = LinkStatus.LINKED

    def calculate_link_quality(self):
        """Calculate link quality percentage based on recent ACK success"""
        if len(self.ack_success_history) == 0:
            return 0
        
        success_count = sum(self.ack_success_history)
        return (success_count / len(self.ack_success_history)) * 100

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
                    if msg_type == MSG_TYPE_ACK:
                        current_time = time.time()
                        with self.lock:
                            # Track ACK success
                            self.ack_success_history.append(1)
                            if len(self.ack_success_history) > 20:
                                self.ack_success_history.pop(0)
                            
                            # Check if this ACK corresponds to a sent heartbeat
                            send_time = self.sent_times.pop(msg_id, None)
                            if send_time:
                                rtt = (current_time - send_time) * 1000  # ms
                                self.latencies.append(rtt)
                                if len(self.latencies) > 100:
                                    self.latencies.pop(0)
                                self.recv_count += 1
                                self.last_ack_time = current_time
                                
                                # Update consecutive ACKs for link establishment
                                if self.link_status in [LinkStatus.NO_LINK, LinkStatus.ESTABLISHING]:
                                    self.consecutive_acks += 1
            except Exception:
                with self.lock:
                    # Track ACK failure
                    self.ack_success_history.append(0)
                    if len(self.ack_success_history) > 20:
                        self.ack_success_history.pop(0)
                time.sleep(0.1)

    def heartbeat_loop(self):
        """Send heartbeats at regular intervals"""
        while self._run.is_set():
            self.send_heartbeat()
            time.sleep(HEARTBEAT_INTERVAL)

    def link_monitor_loop(self):
        """Monitor link status continuously"""
        while self._run.is_set():
            self.update_link_status()
            time.sleep(0.1)

    def get_link_color(self):
        """Get color for link status display"""
        colors = {
            LinkStatus.NO_LINK: "red",
            LinkStatus.ESTABLISHING: "yellow",
            LinkStatus.LINKED: "green",
            LinkStatus.WEAK_SIGNAL: "orange",
            LinkStatus.LINK_LOST: "red"
        }
        return colors.get(self.link_status, "white")

    def get_link_symbol(self):
        """Get symbol for link status"""
        symbols = {
            LinkStatus.NO_LINK: "❌",
            LinkStatus.ESTABLISHING: "🔄",
            LinkStatus.LINKED: "✅",
            LinkStatus.WEAK_SIGNAL: "📶",
            LinkStatus.LINK_LOST: "⚠️"
        }
        return symbols.get(self.link_status, "❓")

    def build_display(self):
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        # Header - Link Status
        link_color = self.get_link_color()
        link_symbol = self.get_link_symbol()
        header_text = f"{link_symbol} Ground Station Link: [{link_color}]{self.link_status.value}[/{link_color}]"
        layout["header"].update(Panel(header_text, title="Aircraft Transmitter Status", box=box.ROUNDED))

        # Main content
        layout["main"].split_row(
            Layout(name="left"),
            Layout(name="right")
        )

        # Left side - Link Stats
        with self.lock:
            sent = self.sent_count
            recv = self.recv_count
            latencies = self.latencies[:]
            last_ack_time = self.last_ack_time
            last_hb_sent = self.last_heartbeat_sent
            link_quality = self.calculate_link_quality()

        # Calculate link uptime
        if self.link_status == LinkStatus.LINKED and self.link_start_time:
            uptime = time.time() - self.link_start_time
            uptime_str = f"{int(uptime//60):02d}:{int(uptime%60):02d}"
        else:
            uptime_str = "00:00"

        # Calculate packet loss
        packet_loss = max(0.0, (sent - recv) / sent * 100 if sent else 0)

        # Calculate time since last ACK
        if last_ack_time:
            time_since_ack = (time.time() - last_ack_time) * 1000
            last_ack_timestamp = datetime.fromtimestamp(last_ack_time).strftime("%H:%M:%S.%f")[:-3]
            
            # Determine status color based on time since last ACK
            if time_since_ack <= 1500:  # Normal
                ack_color = "green"
            elif time_since_ack <= 3000:  # Warning
                ack_color = "yellow"
            else:  # Critical
                ack_color = "red"
        else:
            time_since_ack = 0
            last_ack_timestamp = "N/A"
            ack_color = "red"

        # Calculate time since last heartbeat sent
        if last_hb_sent:
            time_since_hb = (time.time() - last_hb_sent) * 1000
            last_hb_timestamp = datetime.fromtimestamp(last_hb_sent).strftime("%H:%M:%S.%f")[:-3]
        else:
            time_since_hb = 0
            last_hb_timestamp = "N/A"

        link_table = Table(title="📡 Ground Station Link", box=box.ROUNDED)
        link_table.add_column("Parameter", justify="left")
        link_table.add_column("Value", justify="right")
        
        link_table.add_row("Link Status", f"[{link_color}]{self.link_status.value}[/{link_color}]")
        link_table.add_row("Link Quality", f"[{'green' if link_quality > 90 else 'yellow' if link_quality > 70 else 'red'}]{link_quality:.1f}%[/]")
        link_table.add_row("Link Uptime", f"[cyan]{uptime_str}[/cyan]")
        link_table.add_row("Packet Loss", f"[{'green' if packet_loss < 5 else 'yellow' if packet_loss < 15 else 'red'}]{packet_loss:.1f}%[/]")
        link_table.add_row("Last Heartbeat", f"[blue]{last_hb_timestamp}[/blue]")
        link_table.add_row("Last ACK", f"[blue]{last_ack_timestamp}[/blue]")
        link_table.add_row("Time Since ACK", f"[{ack_color}]{time_since_ack:.0f}ms[/{ack_color}]")

        layout["left"].update(link_table)

        # Right side - Performance Stats
        if latencies:
            min_lat = min(latencies)
            max_lat = max(latencies)
            avg_lat = sum(latencies) / len(latencies)
            last_lat = latencies[-1]
            stddev_lat = statistics.stdev(latencies) if len(latencies) > 1 else 0.0
        else:
            min_lat = max_lat = avg_lat = last_lat = stddev_lat = 0.0

        perf_table = Table(title="⚡ Performance Metrics", box=box.ROUNDED)
        perf_table.add_column("Metric", justify="left")
        perf_table.add_column("Value", justify="right")
        
        perf_table.add_row("Heartbeats Sent", str(sent))
        perf_table.add_row("ACKs Received", str(recv))
        perf_table.add_row("Min RTT", f"{min_lat:.2f}ms")
        perf_table.add_row("Max RTT", f"{max_lat:.2f}ms")
        perf_table.add_row("Avg RTT", f"{avg_lat:.2f}ms")
        perf_table.add_row("Last RTT", f"{last_lat:.2f}ms")
        perf_table.add_row("RTT Jitter", f"{stddev_lat:.2f}ms")

        layout["right"].update(perf_table)

        # Footer - Status Messages
        footer_text = ""
        if self.link_status == LinkStatus.NO_LINK:
            footer_text = "[red]❌ No ground station detected - Check radio connection[/red]"
        elif self.link_status == LinkStatus.ESTABLISHING:
            footer_text = "[yellow]🔄 Establishing link with ground station...[/yellow]"
        elif self.link_status == LinkStatus.LINKED:
            footer_text = "[green]✅ Aircraft ready for remote control[/green]"
        elif self.link_status == LinkStatus.WEAK_SIGNAL:
            footer_text = "[orange]📶 Weak signal detected - Check range and obstacles[/orange]"
        elif self.link_status == LinkStatus.LINK_LOST:
            footer_text = "[red]⚠️ Ground station link lost - Attempting reconnection[/red]"

        layout["footer"].update(Panel(footer_text, box=box.ROUNDED))
        
        return layout

    def run(self):
        try:
            self.open_port()
        except RuntimeError as e:
            print(e)
            return

        # Use the same threading approach as ground_station - daemon=True threads
        threads = [
            threading.Thread(target=self.read_loop, daemon=True),
            threading.Thread(target=self.heartbeat_loop, daemon=True),
            threading.Thread(target=self.link_monitor_loop, daemon=True),
        ]
        for t in threads:
            t.start()

        try:
            # Use same Live display approach as ground_station
            with Live(self.build_display(), refresh_per_second=4) as live:
                while self._run.is_set():
                    time.sleep(0.25)
                    live.update(self.build_display())
        except KeyboardInterrupt:
            print("\nShutting down aircraft transmitter...")
            self._run.clear()
            for t in threads:
                t.join(timeout=1)
            self.close_port()


if __name__ == "__main__":
    print("=== RC Aircraft Transmitter ===")
    port = select_com_port()
    if port is None:
        print("Port selection failed. Exiting.")
    else:
        aircraft = Aircraft(port)
        aircraft.run()
