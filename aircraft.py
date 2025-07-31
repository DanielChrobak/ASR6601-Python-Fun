import serial
import threading
import time
import statistics
import math
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import struct
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Console
from rich import box
from rich.progress import Progress, BarColumn, TextColumn
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


class FlightMode(Enum):
    MANUAL = "MANUAL"
    STABILIZE = "STABILIZE"
    AUTO = "AUTO"
    RTL = "RTL"  # Return to Launch
    LOITER = "LOITER"


DEFAULT_BAUD = 9600
HEARTBEAT_INTERVAL = 0.5  # seconds - faster for more responsive control
TELEMETRY_INTERVAL = 0.1  # 10Hz telemetry
LINK_TIMEOUT = 3.0
WEAK_SIGNAL_THRESHOLD = 2000
LINK_THRESHOLD = 3

KEY = b"0123456789abcdef"  # AES-128 key (16 bytes)

# Message types
MSG_TYPE_HEARTBEAT = 1
MSG_TYPE_ACK = 2
MSG_TYPE_TELEMETRY = 3
MSG_TYPE_CONTROL = 4

PACKET_SIZE = 64  # Increased for telemetry data


class FlightPhysics:
    """Simplified flight physics simulation"""
    def __init__(self):
        # Position (lat, lon in decimal degrees, alt in meters)
        self.lat = 41.7058  # Hickory Hills, IL
        self.lon = -87.8253
        self.altitude = 120.0  # meters AGL
        
        # Velocity (m/s)
        self.velocity_x = 0.0  # East
        self.velocity_y = 0.0  # North  
        self.velocity_z = 0.0  # Up
        self.ground_speed = 0.0
        self.airspeed = 0.0
        
        # Attitude (degrees)
        self.roll = 0.0
        self.pitch = 0.0
        self.yaw = 0.0  # Heading
        
        # Control inputs (-1000 to +1000)
        self.throttle = 0
        self.aileron = 0
        self.elevator = 0
        self.rudder = 0
        
        # Aircraft state
        self.battery_voltage = 22.2  # 6S LiPo
        self.battery_current = 0.0
        self.battery_consumed = 0.0
        self.rssi = 100
        self.flight_mode = FlightMode.MANUAL
        
        # Physics constants
        self.max_speed = 30.0  # m/s
        self.climb_rate = 0.0
        
        self.last_update = time.time()

    def update(self, dt):
        """Update physics simulation"""
        # Throttle affects speed and climb rate
        throttle_norm = self.throttle / 1000.0
        target_speed = max(0, throttle_norm * self.max_speed)
        
        # Smooth speed changes
        speed_diff = target_speed - self.airspeed
        self.airspeed += speed_diff * dt * 2.0  # 2 second time constant
        
        # Elevator affects climb rate
        elevator_norm = self.elevator / 1000.0
        self.climb_rate = elevator_norm * 10.0  # max 10 m/s climb rate
        self.velocity_z = self.climb_rate
        
        # Roll affects turn rate
        roll_norm = self.aileron / 1000.0
        self.roll = roll_norm * 45.0  # max 45 degree roll
        turn_rate = roll_norm * 30.0  # degrees per second
        self.yaw += turn_rate * dt
        self.yaw = self.yaw % 360
        
        # Pitch from elevator
        elevator_norm = self.elevator / 1000.0
        self.pitch = elevator_norm * 20.0  # max 20 degree pitch
        
        # Update position
        heading_rad = math.radians(self.yaw)
        self.velocity_x = self.airspeed * math.sin(heading_rad)
        self.velocity_y = self.airspeed * math.cos(heading_rad)
        
        # Ground speed
        self.ground_speed = math.sqrt(self.velocity_x**2 + self.velocity_y**2)
        
        # Update GPS position (rough approximation)
        lat_per_meter = 1.0 / 111320.0
        lon_per_meter = 1.0 / (111320.0 * math.cos(math.radians(self.lat)))
        
        self.lat += self.velocity_y * dt * lat_per_meter
        self.lon += self.velocity_x * dt * lon_per_meter
        self.altitude += self.velocity_z * dt
        
        # Keep altitude reasonable
        self.altitude = max(10.0, min(500.0, self.altitude))
        
        # Battery consumption
        power = abs(throttle_norm) * 500.0  # watts
        self.battery_current = power / self.battery_voltage
        self.battery_consumed += self.battery_current * dt / 3600.0  # Ah
        
        # Battery voltage drops with consumption
        voltage_drop = self.battery_consumed * 0.5
        self.battery_voltage = max(18.0, 22.2 - voltage_drop)
        
        # Add some noise/turbulence
        self.roll += random.uniform(-0.5, 0.5)
        self.pitch += random.uniform(-0.3, 0.3)
        self.altitude += random.uniform(-0.1, 0.1)


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
        self.sent_times = {}
        self.latencies = []
        self.sent_count = 0
        self.recv_count = 0
        self.telemetry_sent = 0
        self.commands_received = 0
        self.last_heartbeat_sent = None
        self.ack_success_history = []
        
        # Flight simulation
        self.physics = FlightPhysics()
        self.last_telemetry = time.time()
        self.last_physics_update = time.time()
        
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

    def encrypt_and_send(self, msg_type, data):
        """Send encrypted message with variable length data"""
        # Pack message type and data
        message = struct.pack(">B", msg_type) + data
        
        # Pad to fixed size for consistent encryption
        if len(message) < 48:  # Leave room for nonce and tag
            message += b'\x00' * (48 - len(message))
        
        nonce = get_random_bytes(12)
        cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        packet = nonce + ciphertext + tag
        
        try:
            self.ser.write(packet)
            self.ser.flush()
            return True
        except Exception:
            return False

    def decrypt_packet(self, packet):
        try:
            if len(packet) != PACKET_SIZE:
                return None, None
            nonce = packet[:12]
            tag = packet[-16:]
            ciphertext = packet[12:-16]
            cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            
            msg_type = plaintext[0]
            data = plaintext[1:].rstrip(b'\x00')  # Remove padding
            return msg_type, data
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
        
        # Pack heartbeat data
        data = struct.pack(">I", hb_id)
        self.encrypt_and_send(MSG_TYPE_HEARTBEAT, data)

    def send_telemetry(self):
        """Send comprehensive telemetry data"""
        current_time = time.time()
        
        with self.lock:
            # Pack all telemetry data
            telemetry_data = struct.pack(">ffffffff", 
                self.physics.lat,           # latitude (float)
                self.physics.lon,           # longitude (float) 
                self.physics.altitude,      # altitude (float)
                self.physics.ground_speed,  # ground speed (float)
                self.physics.airspeed,      # airspeed (float)
                self.physics.roll,          # roll angle (float)
                self.physics.pitch,         # pitch angle (float)
                self.physics.yaw            # yaw/heading (float)
            )
            
            # Add more telemetry
            telemetry_data += struct.pack(">fffhB",
                self.physics.battery_voltage,   # battery voltage (float)
                self.physics.battery_current,   # battery current (float)
                self.physics.climb_rate,        # climb rate (float)
                int(self.physics.rssi),         # RSSI (short)
                self.physics.flight_mode.value.encode()[0]  # flight mode (byte)
            )
            
            self.telemetry_sent += 1
        
        success = self.encrypt_and_send(MSG_TYPE_TELEMETRY, telemetry_data)
        return success

    def process_control_command(self, data):
        """Process control command from ground station"""
        try:
            # Unpack control data
            throttle, aileron, elevator, rudder, mode_byte = struct.unpack(">hhhhB", data[:9])
            
            with self.lock:
                self.physics.throttle = throttle
                self.physics.aileron = aileron  
                self.physics.elevator = elevator
                self.physics.rudder = rudder
                
                # Update flight mode
                mode_map = {0: FlightMode.MANUAL, 1: FlightMode.STABILIZE, 
                           2: FlightMode.AUTO, 3: FlightMode.RTL, 4: FlightMode.LOITER}
                self.physics.flight_mode = mode_map.get(mode_byte, FlightMode.MANUAL)
                
                self.commands_received += 1
                
        except Exception:
            pass

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
                    msg_type, msg_data = self.decrypt_packet(packet)
                    
                    if msg_type == MSG_TYPE_ACK:
                        current_time = time.time()
                        hb_id = struct.unpack(">I", msg_data)[0]
                        with self.lock:
                            self.ack_success_history.append(1)
                            if len(self.ack_success_history) > 20:
                                self.ack_success_history.pop(0)
                            
                            send_time = self.sent_times.pop(hb_id, None)
                            if send_time:
                                rtt = (current_time - send_time) * 1000
                                self.latencies.append(rtt)
                                if len(self.latencies) > 100:
                                    self.latencies.pop(0)
                                self.recv_count += 1
                                self.last_ack_time = current_time
                                
                                if self.link_status in [LinkStatus.NO_LINK, LinkStatus.ESTABLISHING]:
                                    self.consecutive_acks += 1
                                    
                    elif msg_type == MSG_TYPE_CONTROL:
                        self.process_control_command(msg_data)
                        
            except Exception:
                with self.lock:
                    self.ack_success_history.append(0)
                    if len(self.ack_success_history) > 20:
                        self.ack_success_history.pop(0)
                time.sleep(0.1)

    def heartbeat_loop(self):
        """Send heartbeats at regular intervals"""
        while self._run.is_set():
            self.send_heartbeat()
            time.sleep(HEARTBEAT_INTERVAL)

    def telemetry_loop(self):
        """Send telemetry at high frequency"""
        while self._run.is_set():
            if self.link_status in [LinkStatus.LINKED, LinkStatus.WEAK_SIGNAL]:
                self.send_telemetry()
            time.sleep(TELEMETRY_INTERVAL)

    def physics_loop(self):
        """Update flight physics"""
        while self._run.is_set():
            current_time = time.time()
            dt = current_time - self.last_physics_update
            self.last_physics_update = current_time
            
            if dt < 1.0:  # Prevent huge time steps
                self.physics.update(dt)
            
            time.sleep(0.02)  # 50Hz physics update

    def link_monitor_loop(self):
        """Monitor link status continuously"""
        while self._run.is_set():
            self.update_link_status()
            time.sleep(0.1)

    def get_link_color(self):
        colors = {
            LinkStatus.NO_LINK: "red",
            LinkStatus.ESTABLISHING: "yellow", 
            LinkStatus.LINKED: "green",
            LinkStatus.WEAK_SIGNAL: "orange",
            LinkStatus.LINK_LOST: "red"
        }
        return colors.get(self.link_status, "white")

    def get_link_symbol(self):
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
        
        # Header
        link_color = self.get_link_color()
        link_symbol = self.get_link_symbol()
        header_text = f"{link_symbol} Ground Station Link: [{link_color}]{self.link_status.value}[/{link_color}]"
        layout["header"].update(Panel(header_text, title="✈️ RC Aircraft Flight Computer", box=box.ROUNDED))

        # Main content - split into 3 columns
        layout["main"].split_row(
            Layout(name="flight_data"),
            Layout(name="controls"), 
            Layout(name="systems")
        )

        # Flight Data
        with self.lock:
            flight_table = Table(title="🛩️ Flight Data", box=box.ROUNDED)
            flight_table.add_column("Parameter", justify="left")
            flight_table.add_column("Value", justify="right")
            
            flight_table.add_row("GPS Latitude", f"{self.physics.lat:.6f}°")
            flight_table.add_row("GPS Longitude", f"{self.physics.lon:.6f}°")
            flight_table.add_row("Altitude AGL", f"[cyan]{self.physics.altitude:.1f}m[/cyan]")
            flight_table.add_row("Ground Speed", f"[green]{self.physics.ground_speed:.1f}m/s[/green]")
            flight_table.add_row("Airspeed", f"[blue]{self.physics.airspeed:.1f}m/s[/blue]")
            flight_table.add_row("Climb Rate", f"[yellow]{self.physics.climb_rate:+.1f}m/s[/yellow]")
            
            layout["flight_data"].update(flight_table)

            # Controls & Attitude
            controls_table = Table(title="🎮 Controls & Attitude", box=box.ROUNDED)
            controls_table.add_column("Control", justify="left")
            controls_table.add_column("Value", justify="right")
            
            # Control inputs with progress bars
            throttle_pct = (self.physics.throttle + 1000) / 20  # Convert to 0-100
            aileron_pct = (self.physics.aileron + 1000) / 20
            elevator_pct = (self.physics.elevator + 1000) / 20  
            rudder_pct = (self.physics.rudder + 1000) / 20
            
            controls_table.add_row("Throttle", f"[{'green' if throttle_pct > 50 else 'yellow'}]{self.physics.throttle:+4d}[/]")
            controls_table.add_row("Aileron", f"[{'red' if abs(self.physics.aileron) > 200 else 'white'}]{self.physics.aileron:+4d}[/]")
            controls_table.add_row("Elevator", f"[{'red' if abs(self.physics.elevator) > 200 else 'white'}]{self.physics.elevator:+4d}[/]")
            controls_table.add_row("Rudder", f"[{'red' if abs(self.physics.rudder) > 200 else 'white'}]{self.physics.rudder:+4d}[/]")
            controls_table.add_row("", "")
            controls_table.add_row("Roll", f"[{'red' if abs(self.physics.roll) > 30 else 'green'}]{self.physics.roll:+5.1f}°[/]")
            controls_table.add_row("Pitch", f"[{'red' if abs(self.physics.pitch) > 15 else 'green'}]{self.physics.pitch:+5.1f}°[/]")
            controls_table.add_row("Heading", f"[cyan]{self.physics.yaw:05.1f}°[/cyan]")
            controls_table.add_row("Flight Mode", f"[magenta]{self.physics.flight_mode.value}[/magenta]")
            
            layout["controls"].update(controls_table)

            # Systems
            systems_table = Table(title="⚡ Aircraft Systems", box=box.ROUNDED)
            systems_table.add_column("System", justify="left")
            systems_table.add_column("Status", justify="right")
            
            # Battery status with color coding
            batt_color = "green" if self.physics.battery_voltage > 20.0 else "yellow" if self.physics.battery_voltage > 19.0 else "red"
            systems_table.add_row("Battery Voltage", f"[{batt_color}]{self.physics.battery_voltage:.1f}V[/{batt_color}]")
            systems_table.add_row("Battery Current", f"[blue]{self.physics.battery_current:.1f}A[/blue]")
            systems_table.add_row("Power Consumed", f"[yellow]{self.physics.battery_consumed:.2f}Ah[/yellow]")
            
            # Link stats  
            packet_loss = max(0.0, (self.sent_count - self.recv_count) / self.sent_count * 100 if self.sent_count else 0)
            link_quality = sum(self.ack_success_history) / len(self.ack_success_history) * 100 if self.ack_success_history else 0
            
            systems_table.add_row("", "")
            systems_table.add_row("Link Quality", f"[{'green' if link_quality > 90 else 'yellow' if link_quality > 70 else 'red'}]{link_quality:.0f}%[/]")
            systems_table.add_row("Packet Loss", f"[{'green' if packet_loss < 5 else 'red'}]{packet_loss:.1f}%[/]")
            systems_table.add_row("Commands RX", f"[blue]{self.commands_received}[/blue]")
            systems_table.add_row("Telemetry TX", f"[green]{self.telemetry_sent}[/green]")
            
            # Show latest RTT if available
            if self.latencies:
                last_rtt = self.latencies[-1]
                rtt_color = "green" if last_rtt < 100 else "yellow" if last_rtt < 200 else "red"
                systems_table.add_row("Link RTT", f"[{rtt_color}]{last_rtt:.0f}ms[/{rtt_color}]")
            
            layout["systems"].update(systems_table)

        # Footer
        footer_text = ""
        if self.link_status == LinkStatus.NO_LINK:
            footer_text = "[red]❌ NO GROUND STATION LINK - AIRCRAFT AUTONOMOUS[/red]"
        elif self.link_status == LinkStatus.ESTABLISHING:
            footer_text = "[yellow]🔄 Establishing link with ground station...[/yellow]"
        elif self.link_status == LinkStatus.LINKED:
            footer_text = "[green]✅ AIRCRAFT UNDER REMOTE CONTROL[/green]"
        elif self.link_status == LinkStatus.WEAK_SIGNAL:
            footer_text = "[orange]📶 WEAK SIGNAL - CHECK RANGE AND OBSTACLES[/orange]"
        elif self.link_status == LinkStatus.LINK_LOST:
            footer_text = "[red]⚠️ LINK LOST - ENTERING FAILSAFE MODE[/red]"

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
            threading.Thread(target=self.heartbeat_loop, daemon=True),
            threading.Thread(target=self.telemetry_loop, daemon=True),
            threading.Thread(target=self.physics_loop, daemon=True),
            threading.Thread(target=self.link_monitor_loop, daemon=True),
        ]
        for t in threads:
            t.start()

        try:
            with Live(self.build_display(), refresh_per_second=10) as live:  # 10Hz display update
                while self._run.is_set():
                    time.sleep(0.1)
                    live.update(self.build_display())
        except KeyboardInterrupt:
            print("\nShutting down aircraft...")
            self._run.clear()
            for t in threads:
                t.join(timeout=1)
            self.close_port()


if __name__ == "__main__":
    print("=== RC Aircraft Flight Computer ===")
    port = select_com_port()
    if port is None:
        print("Port selection failed. Exiting.")
    else:
        aircraft = Aircraft(port)
        aircraft.run()
