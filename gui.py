import tkinter as tk
from tkinter import filedialog, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import folium
from log_parser import LogParser
from threat_reporter import ThreatReporter
from real_time_monitor import RealTimeMonitor
import threading
import webbrowser

class LogAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Log File Analyzer")
        self.log_file = None

        # Create GUI elements
        self.create_widgets()

    def create_widgets(self):
        # File selection button
        self.select_file_btn = tk.Button(self.root, text="Select Log File", command=self.select_log_file)
        self.select_file_btn.pack(pady=10)

        # Analyze button
        self.analyze_btn = tk.Button(self.root, text="Analyze Log File", command=self.analyze_log_file)
        self.analyze_btn.pack(pady=10)

        # Start Real-Time Monitoring button
        self.monitor_btn = tk.Button(self.root, text="Start Real-Time Monitoring", command=self.start_real_time_monitoring)
        self.monitor_btn.pack(pady=10)

        # Stop Real-Time Monitoring button
        self.stop_monitor_btn = tk.Button(self.root, text="Stop Real-Time Monitoring", command=self.stop_real_time_monitoring)
        self.stop_monitor_btn.pack(pady=10)
        self.stop_monitor_btn.config(state=tk.DISABLED)

        # Show Charts button
        self.show_charts_btn = tk.Button(self.root, text="Show Charts", command=self.show_charts)
        self.show_charts_btn.pack(pady=10)

        # Show Map button
        self.show_map_btn = tk.Button(self.root, text="Show Map", command=self.show_map)
        self.show_map_btn.pack(pady=10)

    def select_log_file(self):
        self.log_file = filedialog.askopenfilename(title="Select Log File", filetypes=(("Log files", "*.log"), ("All files", "*.*")))
        if self.log_file:
            messagebox.showinfo("File Selected", f"Log file selected: {self.log_file}")

    def analyze_log_file(self):
        if not self.log_file:
            messagebox.showerror("Error", "Please select a log file first.")
            return

        parser = LogParser(self.log_file)
        parser.parse_logs()

        failed_logins = parser.get_failed_logins()
        suspicious_ips = parser.get_suspicious_ips()

        reporter = ThreatReporter()
        reporter.generate_csv_report(failed_logins, suspicious_ips)
        reporter.generate_html_report(failed_logins, suspicious_ips)

        messagebox.showinfo("Analysis Complete", "Reports generated successfully.")

    def start_real_time_monitoring(self):
        if not self.log_file:
            messagebox.showerror("Error", "Please select a log file first.")
            return

        self.monitor = RealTimeMonitor(self.log_file)
        self.monitor_thread = threading.Thread(target=self.monitor.start_monitoring)
        self.monitor_thread.start()

        self.monitor_btn.config(state=tk.DISABLED)
        self.stop_monitor_btn.config(state=tk.NORMAL)

        messagebox.showinfo("Monitoring", "Real-time monitoring started.")

    def stop_real_time_monitoring(self):
        if hasattr(self, 'monitor'):
            self.monitor.stop_monitoring()
            self.monitor_btn.config(state=tk.NORMAL)
            self.stop_monitor_btn.config(state=tk.DISABLED)
            messagebox.showinfo("Monitoring", "Real-time monitoring stopped.")

    def show_charts(self):
        parser = LogParser(self.log_file)
        parser.parse_logs()
        failed_logins = parser.get_failed_logins()

        ip_counts = {}
        for login in failed_logins:
            ip = login['ip']
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        fig, ax = plt.subplots()
        ax.bar(ip_counts.keys(), ip_counts.values())
        ax.set_xlabel("IP Address")
        ax.set_ylabel("Failed Login Attempts")
        ax.set_title("Failed Login Attempts by IP")
        plt.xticks(rotation=45, ha="right")

        canvas = FigureCanvasTkAgg(fig, master=self.root)
        canvas.get_tk_widget().pack()
        canvas.draw()

    def show_map(self):
        parser = LogParser(self.log_file)
        parser.parse_logs()
        failed_logins = parser.get_failed_logins()

        m = folium.Map(location=[0, 0], zoom_start=2)

        for login in failed_logins:
            ip_info = ThreatReporter().get_ip_geolocation(login['ip'])
            if 'loc' in ip_info:
                lat, lon = map(float, ip_info['loc'].split(','))
                folium.Marker([lat, lon], popup=f"{login['ip']} ({ip_info.get('city', 'N/A')}, {ip_info.get('country', 'N/A')})").add_to(m)

        map_file = "reports/map.html"
        m.save(map_file)
        webbrowser.open(map_file)

if __name__ == "__main__":
    root = tk.Tk()
    app = LogAnalyzerApp(root)
    root.mainloop()
