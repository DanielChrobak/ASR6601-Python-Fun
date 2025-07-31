import serial
import threading

DEFAULT_PORT = "COM6"
DEFAULT_BAUD = 9600

class SerialTerminal:
    def __init__(self):
        self.port = DEFAULT_PORT
        self.baud = DEFAULT_BAUD
        self.ser = None
        self.read_thread = None
        self._run = threading.Event()
        self._run.set()
        self._lock = threading.Lock()

    def open_port(self):
        self.close_port()
        try:
            self.ser = serial.Serial(self.port, self.baud, timeout=1)
            print(f"Opened {self.port} at {self.baud} baud.")
            self.start_read_thread()
        except Exception as e:
            self.ser = None
            print(f"[Connection Error] Could not open serial port: {e}")

    def close_port(self):
        if self.read_thread and self.read_thread.is_alive():
            self._run.clear()
            self.read_thread.join()
        if self.ser and self.ser.is_open:
            self.ser.close()
        self._run.set()

    def read_from_port(self):
        while self._run.is_set():
            try:
                if self.ser and self.ser.is_open:
                    data = self.ser.readline()
                    if data:
                        print(data.decode(errors="ignore").strip())
                else:
                    break
            except Exception as e:
                print(f"[Read Error] {e}")
                break

    def start_read_thread(self):
        self.read_thread = threading.Thread(target=self.read_from_port, daemon=True)
        self.read_thread.start()

    def close(self):
        self.close_port()

    def run(self):
        self.open_port()
        print("--- Serial Terminal ---")
        print("Type commands and press Enter. Ctrl+C to exit.")
        print("To set the port:    /port COMX")
        print("To set the baud:    /baud 115200\n")
        print(f"Current: {self.port} @ {self.baud}")

        while True:
            try:
                cmd = input()
                if not cmd:
                    continue
                if cmd.startswith("/port "):
                    new_port = cmd.split(maxsplit=1)[1]
                    self.port = new_port
                    print(f"Switching to port {self.port}...")
                    self.open_port()
                elif cmd.startswith("/baud "):
                    try:
                        new_baud = int(cmd.split(maxsplit=1)[1])
                        self.baud = new_baud
                        print(f"Switching to baud {self.baud}...")
                        self.open_port()
                    except ValueError:
                        print("Invalid baud rate.")
                elif self.ser and self.ser.is_open:
                    self.ser.write((cmd + '\r\n').encode())
                else:
                    print("Serial port is not open.")
            except KeyboardInterrupt:
                print("\nExiting.")
                break
            except Exception as e:
                print(f"[Error] {e}")
                continue
        self.close()

if __name__ == "__main__":
    SerialTerminal().run()
