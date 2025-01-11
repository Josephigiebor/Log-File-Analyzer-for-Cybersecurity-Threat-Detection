import re
from collections import defaultdict
from datetime import datetime, timedelta
import geoip2.database

class LogParser:
    def __init__(self, log_file):
        self.log_file = log_file
        self.failed_logins = []
        self.suspicious_ips = defaultdict(int)
        self.brute_force_ips = defaultdict(list)
        self.suspicious_countries = set(["Russia", "North Korea", "China"])

    def parse_logs(self):
        # Regular expression to match failed login attempts and IP addresses
        pattern = re.compile(r"Failed password for (?:invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+) port")

        with open(self.log_file, 'r') as file:
            for line in file:
                match = pattern.search(line)
                if match:
                    user, ip = match.groups()
                    self.failed_logins.append({"user": user, "ip": ip, "timestamp": self.extract_timestamp(line)})
                    self.suspicious_ips[ip] += 1

    def extract_timestamp(self, log_line):
        # Try multiple date formats to extract the timestamp
        date_formats = ["%b %d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]

        for date_format in date_formats:
            try:
                timestamp_str = log_line[:19]  # Extract the first part of the log line
                timestamp = datetime.strptime(timestamp_str, date_format)
                # Add the current year if it's not already included
                if "%Y" not in date_format:
                    timestamp = timestamp.replace(year=datetime.now().year)
                return timestamp
            except ValueError:
                continue

        # Return None if no format matches
        print(f"Error extracting timestamp: {log_line}")
        return None

    def get_failed_logins(self):
        return self.failed_logins

    def get_suspicious_ips(self, threshold=5):
        return {ip: count for ip, count in self.suspicious_ips.items() if count >= threshold}

    def detect_brute_force_attacks(self, time_window_minutes=5, attempt_threshold=5):
        for login in self.failed_logins:
            ip = login["ip"]
            timestamp = login["timestamp"]
            if timestamp:  # Skip None values
                self.brute_force_ips[ip].append(timestamp)

        brute_force_ips = {}
        for ip, timestamps in self.brute_force_ips.items():
            timestamps.sort()
            for i in range(len(timestamps) - attempt_threshold + 1):
                if timestamps[i + attempt_threshold - 1] - timestamps[i] <= timedelta(minutes=time_window_minutes):
                    brute_force_ips[ip] = len(timestamps)
                    break

        return brute_force_ips

    def detect_suspicious_countries(self):
        reader = geoip2.database.Reader("GeoLite2-Country.mmdb")
        suspicious_countries_ips = {}
        for ip in self.suspicious_ips:
            try:
                response = reader.country(ip)
                country = response.country.name
                if country in self.suspicious_countries:
                    suspicious_countries_ips[ip] = country
            except Exception as e:
                print(f"Error fetching geolocation for IP {ip}: {e}")
        reader.close()
        return suspicious_countries_ips

# Example usage
if __name__ == "__main__":
    parser = LogParser("sample_logs/sample.log")
    parser.parse_logs()

    print("\nFailed Logins:")
    for login in parser.get_failed_logins():
        print(login)

    print("\nSuspicious IPs:")
    for ip, count in parser.get_suspicious_ips().items():
        print(f"{ip}: {count} attempts")

    print("\nBrute Force IPs:")
    for ip, count in parser.detect_brute_force_attacks().items():
        print(f"{ip}: {count} attempts within the time window")

    print("\nSuspicious Countries:")
    for ip, country in parser.detect_suspicious_countries().items():
        print(f"{ip}: {country}")
