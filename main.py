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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from collections import defaultdict

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
        self.log_file = filedialog.askopenfilename(title="Select Log File", filetypes=[("Log files", "*.log"), ("All files", "*.*")])
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
        brute_force_ips = parser.detect_brute_force_attacks()

        reporter = ThreatReporter()
        reporter.generate_csv_report(failed_logins, suspicious_ips)
        reporter.generate_html_report(failed_logins, suspicious_ips)

        # Send email alert if suspicious IPs exceed threshold
        if len(suspicious_ips) > 0 or len(brute_force_ips) > 0:
            self.send_email_alert(suspicious_ips, brute_force_ips)

        messagebox.showinfo("Analysis Complete", "Reports generated successfully.")

    def send_email_alert(self, suspicious_ips, brute_force_ips):
        sender_email = os.getenv("SENDER_EMAIL")
        receiver_email = os.getenv("RECEIVER_EMAIL")
        smtp_server = os.getenv("SMTP_SERVER")
        smtp_password = os.getenv("SMTP_PASSWORD")

        if not sender_email or not receiver_email or not smtp_server or not smtp_password:
            messagebox.showerror("Error", "Missing email configuration in environment variables.")
            return

        subject = "Suspicious Activity Detected"

        # Create the email message
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = subject

        body = "The following suspicious IPs have been detected:\n\n"
        for ip, count in suspicious_ips.items():
            body += f"IP: {ip}, Attempts: {count}\n"

        body += "\nThe following IPs have been flagged for potential brute-force attacks:\n\n"
        for ip, count in brute_force_ips.items():
            body += f"IP: {ip}, Attempts: {count}\n"

        message.attach(MIMEText(body, "plain"))

        try:
            # Connect to the SMTP server and send the email
            with smtplib.SMTP(smtp_server, 587) as server:
                server.starttls()
                server.login(sender_email, smtp_password)
                server.sendmail(sender_email, receiver_email, message.as_string())

            messagebox.showinfo("Email Sent", "Alert email sent to the security team.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send email: {e}")

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
        if not self.log_file:
            messagebox.showerror("Error", "Please select a log file first.")
            return

        parser = LogParser(self.log_file)
        try:
            parser.parse_logs()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse log file: {e}")
            return

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
        if not self.log_file:
            messagebox.showerror("Error", "Please select a log file first.")
            return

        parser = LogParser(self.log_file)
        try:
            parser.parse_logs()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to parse log file: {e}")
            return

        failed_logins = parser.get_failed_logins()

        m = folium.Map(location=[0, 0], zoom_start=2)

        for login in failed_logins:
            ip_info = ThreatReporter().get_ip_geolocation(login['ip'])
            if 'loc' in ip_info:
                try:
                    lat, lon = map(float, ip_info['loc'].split(','))
                    folium.Marker([lat, lon], popup=f"{login['ip']} ({ip_info.get('city', 'N/A')}, {ip_info.get('country', 'N/A')})").add_to(m)
                except ValueError:
                    print(f"Skipping invalid location data for IP {login['ip']}: {ip_info.get('loc')}")
            else:
                print(f"No location data available for IP {login['ip']}")

        map_file = "reports/map.html"
        m.save(map_file)
        webbrowser.open(map_file)

if __name__ == "__main__":
    root = tk.Tk()
    app = LogAnalyzerApp(root)
    root.mainloop()
