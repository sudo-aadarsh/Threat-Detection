import re
from .base_agent import BaseAgent

# Known phishing/disposable domains for detection
SUSPICIOUS_DOMAINS = [
    "paypa1.com", "amazon-security.net", "secure-login.xyz", "verify-account.info",
    "apple-id-verify.com", "account-suspended.net", "update-required.biz",
    "trk.click", "bit.ly", "tinyurl.com", "goo.gl", "ow.ly"
]

PHISHING_KEYWORDS = [
    "verify your account", "confirm your identity", "suspended", "urgent action required",
    "click here immediately", "your account has been", "unusual sign-in", "limited time",
    "update your payment", "prize", "won", "lottery", "inheritance", "wire transfer",
    "password expired", "security alert", "click below to restore"
]

class EmailAgent(BaseAgent):
    def __init__(self):
        super().__init__("EmailAgent")

    def analyze(self, email_text: str) -> dict:
        self.logger.info("Starting email analysis...")

        # Extract URLs
        url_pattern = r'https?://[^\s<>"\'\\]+'
        urls = list(set(re.findall(url_pattern, email_text, re.IGNORECASE)))

        # Extract email addresses
        email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
        emails = list(set(re.findall(email_pattern, email_text)))

        # Extract IPs embedded in email headers
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = list(set(re.findall(ip_pattern, email_text)))

        # Check for suspicious domains in URLs
        suspicious_urls = []
        for url in urls:
            for domain in SUSPICIOUS_DOMAINS:
                if domain in url.lower():
                    suspicious_urls.append(url)

        # Check for phishing keywords
        found_keywords = []
        email_lower = email_text.lower()
        for kw in PHISHING_KEYWORDS:
            if kw in email_lower:
                found_keywords.append(kw)

        # Detect sender spoofing (e.g. "PayPal" in display name but different domain)
        spoofing_indicators = []
        if re.search(r'paypal', email_lower) and not any('paypal.com' in e for e in emails):
            spoofing_indicators.append("Claims to be PayPal but sender domain is not paypal.com")
        if re.search(r'amazon', email_lower) and not any('amazon.com' in e for e in emails):
            spoofing_indicators.append("Claims to be Amazon but sender domain is not amazon.com")
        if re.search(r'google', email_lower) and not any('google.com' in e for e in emails):
            spoofing_indicators.append("Claims to be Google but sender domain is not google.com")
        if re.search(r'microsoft|outlook', email_lower) and not any('microsoft.com' in e or 'outlook.com' in e for e in emails):
            spoofing_indicators.append("Claims to be Microsoft but sender domain is not microsoft.com")

        # Calculate risk score
        risk_score = 0
        risk_score += min(len(found_keywords) * 15, 40)
        risk_score += min(len(suspicious_urls) * 20, 30)
        risk_score += min(len(spoofing_indicators) * 20, 30)
        risk_score = min(risk_score, 100)

        severity = "LOW"
        if risk_score >= 70:
            severity = "CRITICAL"
        elif risk_score >= 40:
            severity = "HIGH"
        elif risk_score >= 20:
            severity = "MEDIUM"

        findings = {
            "extracted_urls": urls,
            "extracted_emails": emails,
            "extracted_ips": ips,
            "suspicious_urls": suspicious_urls,
            "phishing_keywords_found": found_keywords,
            "spoofing_indicators": spoofing_indicators,
            "total_ioc_count": len(urls) + len(emails) + len(ips),
            "risk_score": risk_score,
            "severity": severity,
            "verdict": "SUSPICIOUS" if risk_score > 0 else "CLEAN"
        }

        self.logger.info(f"Email analysis done. Risk: {risk_score}/100, Severity: {severity}")
        return findings
