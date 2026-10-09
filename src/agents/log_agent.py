import re
from collections import defaultdict
from .base_agent import BaseAgent

BRUTE_FORCE_THRESHOLD = 5

ATTACK_PATTERNS = {
    "Brute Force / Credential Stuffing": [
        r"Failed password for",
        r"authentication failure",
        r"FAILED LOGIN",
        r"Invalid user",
    ],
    "Privilege Escalation": [
        r"sudo:",
        r"su\[",
        r"PAM: authentication failure.*root",
        r"COMMAND=.*passwd",
    ],
    "Malware / Persistence": [
        r"crontab.*edited",
        r"new user.*added",
        r"useradd",
        r"chmod.*777",
        r"curl.*http",
        r"wget.*http",
    ],
    "Port Scanning / Recon": [
        r"SYN_RECV",
        r"nmap",
        r"connection refused",
        r"SCAN",
    ],
    "Data Exfiltration": [
        r"scp\s",
        r"rsync\s",
        r"ftp\s.*login",
        r"STOR\s",
    ]
}

class LogAgent(BaseAgent):
    def __init__(self):
        super().__init__("LogAgent")

    def analyze(self, log_text: str) -> dict:
        self.logger.info("Starting log analysis...")
        lines = log_text.strip().splitlines()
        total_lines = len(lines)

        # Failed login tracking
        failed_login_pattern = re.compile(
            r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.]+)"
        )
        ip_failures = defaultdict(lambda: {"count": 0, "users": set(), "lines": []})

        for line in lines:
            m = failed_login_pattern.search(line)
            if m:
                ip = m.group("ip")
                user = m.group("user")
                ip_failures[ip]["count"] += 1
                ip_failures[ip]["users"].add(user)
                ip_failures[ip]["lines"].append(line.strip())

        # Brute force IPs (above threshold)
        brute_force_ips = {
            ip: data for ip, data in ip_failures.items()
            if data["count"] >= BRUTE_FORCE_THRESHOLD
        }

        # Serialize sets
        for ip in ip_failures:
            ip_failures[ip]["users"] = list(ip_failures[ip]["users"])

        for ip in brute_force_ips:
            brute_force_ips[ip]["users"] = list(brute_force_ips[ip]["users"])
            brute_force_ips[ip]["lines"] = brute_force_ips[ip]["lines"][:3]  # sample

        # Pattern detection
        pattern_matches = {}
        for pattern_name, regexes in ATTACK_PATTERNS.items():
            matches = []
            for line in lines:
                for rx in regexes:
                    if re.search(rx, line, re.IGNORECASE):
                        matches.append(line.strip())
                        break
            if matches:
                pattern_matches[pattern_name] = matches[:5]  # top 5 samples

        # Extract all IPs from the log
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        all_ips = list(set(ip_pattern.findall(log_text)))

        total_failed = sum(d["count"] for d in ip_failures.values())

        # Risk scoring
        risk_score = 0
        risk_score += min(len(brute_force_ips) * 25, 50)
        risk_score += min(len(pattern_matches) * 15, 50)
        risk_score = min(risk_score, 100)

        severity = "LOW"
        if risk_score >= 70:
            severity = "CRITICAL"
        elif risk_score >= 40:
            severity = "HIGH"
        elif risk_score >= 20:
            severity = "MEDIUM"

        findings = {
            "total_log_lines": total_lines,
            "total_failed_logins": total_failed,
            "brute_force_ips": brute_force_ips,
            "all_ips_found": all_ips,
            "attack_patterns_detected": pattern_matches,
            "suspicious_ip_list": list(brute_force_ips.keys()),
            "risk_score": risk_score,
            "severity": severity
        }

        self.logger.info(f"Log analysis done. {total_failed} failed logins, {len(brute_force_ips)} brute-force IPs. Risk: {risk_score}")
        return findings
