import os
import time
import threading
from log_parser import LogParser


class RealTimeMonitor:
    def __init__(self, log_file):
        self.log_file = log_file
        self.stop_flag = threading.Event()

    def tail_f(self):
        with open(self.log_file, 'r') as file:
            # Move to the end of the file
            file.seek(0, os.SEEK_END)

            while not self.stop_flag.is_set():
                line = file.readline()
                if not line:
                    time.sleep(0.1)  # Wait for new data
                    continue
                self.process_line(line)

    def process_line(self, line):
        parser = LogParser(self.log_file)
        pattern = parser.failed_logins
        print(f"New log entry detected: {line.strip()}")
        if pattern in line:
            print("Detected a suspicious entry.")

    def start_monitoring(self):
        print(f"Starting real-time monitoring of {self.log_file}...")
        self.thread = threading.Thread(target=self.tail_f)
        self.thread.start()

    def stop_monitoring(self):
        print("Stopping real-time monitoring...")
        self.stop_flag.set()
        self.thread.join()


# Example usage
if __name__ == "__main__":
    monitor = RealTimeMonitor("sample_logs/sample.log")
    try:
        monitor.start_monitoring()
        while True:
            time.sleep(1)  # Keep the main thread alive
    except KeyboardInterrupt:
        monitor.stop_monitoring()
