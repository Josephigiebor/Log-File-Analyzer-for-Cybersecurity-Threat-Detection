# Log-File-Analyzer-for-Cybersecurity-Threat-Detection
A Python-based tool to detect suspicious activities in server logs, including failed login attempts, brute-force attacks, and unusual IP access patterns. Features include real-time monitoring, geolocation lookup, interactive reports, and email alerts to help cybersecurity teams respond to threats.


# 🔍 Log File Analyzer for Cybersecurity Threat Detection

The **Log File Analyzer** is a Python-based tool that parses server log files to detect **suspicious activities**, such as failed login attempts, brute-force attacks, and unusual IP access patterns. The tool includes a **real-time monitoring feature** and generates **comprehensive reports** in both CSV and HTML formats, including an interactive **map visualization** for geolocation of suspicious IP addresses.

---

## 🚀 **Features**

- 📄 **Log Parsing:** Extracts failed login attempts from server logs using regex.
- 🔐 **Brute-Force Attack Detection:** Detects repeated failed login attempts from the same IP address within a short time window.
- 🌍 **Geolocation Lookup:** Identifies the geographical location of IP addresses using the GeoLite2 database.
- 📊 **Visualization:** Generates interactive reports, including charts and maps for visualizing suspicious activity.
- 📧 **Email Alerts:** Sends email notifications to the security team when suspicious activity is detected.
- 📡 **Real-Time Monitoring:** Monitors log files in real-time using `tail -f` functionality.

---

## 🛠 **Technologies Used**

- **Python**: Core language
- **Tkinter**: GUI for the tool
- **Matplotlib**: For generating charts
- **Folium**: For map visualization
- **GeoIP2**: For geolocation lookup
- **Regex**: For log parsing

---

## 📂 **Project Structure**

```plaintext
├── sample_logs/               # Sample log files
├── reports/                   # Generated reports (CSV, HTML, map)
├── gui.py                     # GUI implementation using Tkinter
├── log_parser.py              # Core log parsing logic
├── main.py                    # Main entry point for the application
├── real_time_monitor.py       # Real-time log file monitoring
├── threat_reporter.py         # Report generation (CSV, HTML)
└── requirements.txt           # Dependencies
