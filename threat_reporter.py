import csv
import os
import requests

class ThreatReporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_csv_report(self, failed_logins, suspicious_ips):
        csv_file = os.path.join(self.output_dir, "threat_report.csv")
        with open(csv_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["User", "IP Address", "City", "Region", "Country", "Organization"])
            for login in failed_logins:
                ip_info = self.get_ip_geolocation(login['ip'])
                writer.writerow([login['user'], login['ip'], ip_info.get("city", "N/A"), ip_info.get("region", "N/A"), ip_info.get("country", "N/A"), ip_info.get("org", "N/A")])

        print(f"CSV report generated: {csv_file}")

    def generate_html_report(self, failed_logins, suspicious_ips):
        html_file = os.path.join(self.output_dir, "threat_report.html")
        with open(html_file, mode='w') as file:
            file.write("<html><head><title>Threat Report</title></head><body>")
            file.write("<h1>Threat Report</h1>")
            file.write("<h2>Failed Logins</h2>")
            file.write("<table border='1'><tr><th>User</th><th>IP Address</th><th>City</th><th>Region</th><th>Country</th><th>Organization</th></tr>")
            for login in failed_logins:
                ip_info = self.get_ip_geolocation(login['ip'])
                file.write(f"<tr><td>{login['user']}</td><td>{login['ip']}</td><td>{ip_info.get('city', 'N/A')}</td><td>{ip_info.get('region', 'N/A')}</td><td>{ip_info.get('country', 'N/A')}</td><td>{ip_info.get('org', 'N/A')}</td></tr>")
            file.write("</table>")

            file.write("<h2>Suspicious IPs</h2>")
            file.write("<table border='1'><tr><th>IP Address</th><th>Attempts</th></tr>")
            for ip, count in suspicious_ips.items():
                file.write(f"<tr><td>{ip}</td><td>{count}</td></tr>")
            file.write("</table>")

            file.write("</body></html>")

        print(f"HTML report generated: {html_file}")



    def get_ip_geolocation(self, ip):
        print(f"Looking up geolocation for IP: {ip}")
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            if response.status_code == 200:
                data = response.json()
                print(f"Geolocation data for {ip}: {data}")
                return data
            else:
                print(f"Failed to fetch geolocation for {ip}. Status code: {response.status_code}")
                return {}
        except requests.RequestException as e:
            print(f"Error fetching geolocation for IP {ip}: {e}")
            return {}


# Example usage
if __name__ == "__main__":
    from log_parser import LogParser

    # Parse sample log
    parser = LogParser("sample_logs/sample.log")
    parser.parse_logs()

    failed_logins = parser.get_failed_logins()
    suspicious_ips = parser.get_suspicious_ips()

    # Generate reports
    reporter = ThreatReporter()
    reporter.generate_csv_report(failed_logins, suspicious_ips)
    reporter.generate_html_report(failed_logins, suspicious_ips)