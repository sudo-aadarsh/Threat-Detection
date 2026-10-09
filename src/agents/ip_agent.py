import os
import time
import requests
from .base_agent import BaseAgent

# Known malicious IP samples for demo/offline mode
DEMO_THREAT_DB = {
    "103.45.67.89":  {"score": 95, "category": "SSH Brute Force / Botnet", "country": "CN", "reports": 312},
    "185.220.101.1": {"score": 88, "category": "Tor Exit Node", "country": "DE", "reports": 210},
    "45.142.212.100":{"score": 92, "category": "Port Scanner / DDoS", "country": "RU", "reports": 450},
    "192.241.214.116":{"score": 78, "category": "Spam / Malware C2", "country": "US", "reports": 98},
    "178.62.211.81": {"score": 83, "category": "Credential Stuffing", "country": "NL", "reports": 176},
}

RATE_LIMIT_SLEEP = 0.5  # seconds between API calls (respect free tier)

class IPAgent(BaseAgent):
    def __init__(self):
        super().__init__("IPAgent")
        self.api_key = os.getenv("ABUSEIPDB_API_KEY", "")
        self.use_real_api = bool(self.api_key and self.api_key != "your_abuseipdb_api_key_here")

    def _query_abuseipdb(self, ip: str) -> dict:
        """Real AbuseIPDB API call."""
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Accept": "application/json", "Key": self.api_key}
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            resp = requests.get(url, headers=headers, params=params, timeout=5)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "malicious_score": data.get("abuseConfidenceScore", 0),
                "category": ", ".join(map(str, data.get("usageType", ["Unknown"]))),
                "country": data.get("countryCode", "Unknown"),
                "total_reports": data.get("totalReports", 0),
                "is_whitelisted": data.get("isWhitelisted", False),
                "source": "AbuseIPDB (Live)"
            }
        except Exception as e:
            self.logger.warning(f"AbuseIPDB API failed for {ip}: {e}. Falling back to demo DB.")
            return self._demo_lookup(ip)

    def _demo_lookup(self, ip: str) -> dict:
        """Demo/offline mode using local threat intelligence DB."""
        if ip in DEMO_THREAT_DB:
            info = DEMO_THREAT_DB[ip]
            return {
                "malicious_score": info["score"],
                "category": info["category"],
                "country": info["country"],
                "total_reports": info["reports"],
                "is_whitelisted": False,
                "source": "Demo Threat DB (Offline)"
            }
        # Unknown IPs get low-risk score
        return {
            "malicious_score": 0,
            "category": "No threats reported",
            "country": "Unknown",
            "total_reports": 0,
            "is_whitelisted": False,
            "source": "Demo Threat DB (Offline)"
        }

    def analyze(self, ip_addresses: list) -> dict:
        if not ip_addresses:
            return {}

        self.logger.info(f"IP analysis for {len(ip_addresses)} addresses. API={'Live' if self.use_real_api else 'Demo'}")
        results = {}

        for ip in ip_addresses:
            # Skip private/loopback IPs
            if ip.startswith("127.") or ip.startswith("192.168.") or ip.startswith("10.") or ip == "0.0.0.0":
                continue

            if self.use_real_api:
                results[ip] = self._query_abuseipdb(ip)
                time.sleep(RATE_LIMIT_SLEEP)
            else:
                results[ip] = self._demo_lookup(ip)

            score = results[ip]["malicious_score"]
            if score >= 75:
                results[ip]["severity"] = "CRITICAL"
            elif score >= 50:
                results[ip]["severity"] = "HIGH"
            elif score >= 25:
                results[ip]["severity"] = "MEDIUM"
            else:
                results[ip]["severity"] = "LOW"

        self.logger.info("IP analysis complete.")
        return results
