import re
import json
import sys
from collections import Counter
from datetime import datetime


# Regex pattern to extract failed SSH login attempts
# Matches: "Month Day Time Hostname sshd[PID]: Failed password for USER from IP port PORT ssh2"
FAILED_LOGIN_PATTERN = re.compile(
    r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)"
)

def parse_log_file(filepath):
    """Parse the log file and extract failed login attempts."""
    events = []

    with open(filepath, "r") as f:
        for line in f:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                events.append({
                    "timestamp": match.group(1),
                    "username": match.group(2),
                    "source_ip": match.group(3),
                })

    return events

def detect_brute_force(events, threshold=5):
    """Detect brute-force attacks based on failed login threshold."""
    # Count attempts per IP
    ip_counts = Counter(event["source_ip"] for event in events)

    alerts = []

    for ip, count in ip_counts.items():
        if count >= threshold:
        # Classify severity based on attempt count
            if count >= 30:
                severity = "CRITICAL"
            elif count >= 15:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

        # Collect which usernames the attacker targeted
            targeted_users = list(set(event["username"] for event in events if event["source_ip"] == ip))

        # Get the time window of the attack
            ip_events = [event for event in events if event["source_ip"] == ip]
            first_seen = ip_events[0]["timestamp"]
            last_seen = ip_events[-1]["timestamp"]

            alerts.append({
            "source_ip": ip,
            "attempt_count": count,
            "severity": severity,
            "targeted_users": targeted_users,
            "first_seen": first_seen,
            "last_seen": last_seen,
        })
    alerts.sort(key=lambda x: x["attempt_count"], reverse=True)

    return alerts

def generate_report(alerts, total_events, log_file):
    """Generate a structured JSON threat report."""
    severity_counts = Counter(alert["severity"] for alert in alerts)

    report = {
        "report_metadata": {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "log_file_analyzed": log_file,
            "total_failed_logins": total_events
        },
        "summary": {
            "total_alerts": len(alerts),
            "critical": severity_counts.get("CRITICAL",0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
        },
        "alerts": alerts,
    }

    return report

""" 
# Quick test
if __name__ == "__main__":
    events = parse_log_file("sample_auth.log")
    print(f"Found {len(events)} failed login attempts")
    alerts = detect_brute_force(events)
    for alert in alerts:
        print(f"[{alert['severity']}] {alert['source_ip']} - {alert['attempt_count']} attempts")
    #print(len(alerts))"""
def main():
    log_file = "sample_auth.log"
    threshold = 5

    # Allow custom threshold from command line
    if len(sys.argv) > 1:
        try:
            threshold = int(sys.argv[1])
        except ValueError:
            print(f"Invaliv threshold: {sys.argv[1]}. Using default: 5")
    print(f"[*] Security Log Analyzer")
    print(f"[*] Analyzing: {log_file}")
    print(f"[*] Detection threshold: {threshold} failed attempts")
    print("-" *50)

    # Step 1: Parse
    events = parse_log_file(log_file)
    print(f"[+] Parsed {len(events)} failed login attempts")

    # Step 2: Detect
    alerts = detect_brute_force(events, threshold)
    print(f"[!] Detected {len(alerts)} suspicious IPs")

    # Step 2: Report
    report = generate_report(alerts, len(events), log_file)

    # Write JSON report
    output_file = "threat_report.json"
    with open(output_file,"w") as f:
        json.dump(report, f, indent=2)

    print("-" * 50)
    print(f"[+] Report saved to: {output_file}")
    print()

    # Print console summary
    for alert in alerts:
        print(f"[{alert['severity']}] {alert['source_ip']} - {alert['attempt_count']} attempts")
        print(f" Targeted users: {','.join(alert['targeted_users'])}")
        print(f" Window: {alert['first_seen']} -> {alert['last_seen']}")
        print()

if __name__ == "__main__":
    main()


"""
import re
import json
import sys
from collections import Counter
from datetime import datetime


# Regex pattern to extract failed SSH login attempts
# Matches: "Month Day Time Hostname sshd[PID]: Failed password for USER from IP port PORT ssh2"
FAILED_LOGIN_PATTERN = re.compile(
    r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+Failed password for\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)"
)

def parse_log_file(filepath):
    # Parse the log file and extract failed login attempts.
    events = []

    with open(filepath, "r") as f:
        for line in f:
            match = FAILED_LOGIN_PATTERN.search(line)
            if match:
                events.append({
                    "timestamp": match.group(1),
                    "username": match.group(2),
                    "source_ip": match.group(3),
                })

    return events

def detect_brute_force(events, threshold=5):
    # Detect brute-force attacks based on failed login threshold.
    # Count attempts per IP
    ip_counts = Counter(event["source_ip"] for event in events)

    alerts = []

    for ip, count in ip_counts.items():
        if count >= threshold:
        # Classify severity based on attempt count
            if count >= 30:
                severity = "CRITICAL"
            elif count >= 15:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

        # Collect which usernames the attacker targeted
            targeted_users = list(set(event["username"] for event in events if event["source_ip"] == ip))

        # Get the time window of the attack
            ip_events = [event for event in events if event["source_ip"] == ip]
            first_seen = ip_events[0]["timestamp"]
            last_seen = ip_events[-1]["timestamp"]

            alerts.append({
            "source_ip": ip,
            "attempt_count": count,
            "severity": severity,
            "targeted_users": targeted_users,
            "first_seen": first_seen,
            "last_seen": last_seen,
        })
    alerts.sort(key=lambda x: x["attempt_count"], reverse=True)

    return alerts

def generate_report(alerts, total_events, log_file):
    # Generate a structured JSON threat report.
    severity_counts = Counter(alert["severity"] for alert in alerts)

    report = {
        "report_metadata": {
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "log_file_analyzed": log_file,
            "total_failed_logins": total_events
        },
        "summary": {
            "total_alerts": len(alerts),
            "critical": severity_counts.get("CRITICAL",0),
            "high": severity_counts.get("HIGH", 0),
            "medium": severity_counts.get("MEDIUM", 0),
        },
        "alerts": alerts,
    }

    return report

# ЗАКОМЕНТИТЬ ЭТОТ КУСОК
# Quick test
if __name__ == "__main__":
    events = parse_log_file("sample_auth.log")
    print(f"Found {len(events)} failed login attempts")
    alerts = detect_brute_force(events)
    for alert in alerts:
        print(f"[{alert['severity']}] {alert['source_ip']} - {alert['attempt_count']} attempts")
    #print(len(alerts))
    
    
def main():
    log_file = "sample_auth.log"
    threshold = 5

    # Allow custom threshold from command line
    if len(sys.argv) > 1:
        try:
            threshold = int(sys.argv[1])
        except ValueError:
            print(f"Invaliv threshold: {sys.argv[1]}. Using default: 5")
    print(f"[*] Security Log Analyzer")
    print(f"[*] Analyzing: {log_file}")
    print(f"[*] Detection threshold: {threshold} failed attempts")
    print("-" *50)

    # Step 1: Parse
    events = parse_log_file(log_file)
    print(f"[+] Parsed {len(events)} failed login attempts")

    # Step 2: Detect
    alerts = detect_brute_force(events, threshold)
    print(f"[!] Detected {len(alerts)} suspicious IPs")

    # Step 2: Report
    report = generate_report(alerts, len(events), log_file)

    # Write JSON report
    output_file = "threat_report.json"
    with open(output_file,"w") as f:
        json.dump(report, f, indent=2)

    print("-" * 50)
    print(f"[+] Report saved to: {output_file}")
    print()

    # Print console summary
    for alert in alerts:
        print(f"[{alert['severity']}] {alert['source_ip']} - {alert['attempt_count']} attempts")
        print(f" Targeted users: {','.join(alert['targeted_users'])}")
        print(f" Window: {alert['first_seen']} -> {alert['last_seen']}")
        print()

if __name__ == "__main__":
    main()

"""