import os
import google.generativeai as genai
from .base_agent import BaseAgent

PROMPT_TEMPLATE = """
You are a Senior Cybersecurity Incident Response Analyst. You have received the following automated findings from three specialized analysis agents.

---
## EMAIL AGENT FINDINGS
{email_findings}

---
## IP/NETWORK AGENT FINDINGS
{ip_findings}

---
## LOG ANALYSIS AGENT FINDINGS
{log_findings}

---

## YOUR TASK:
Using ONLY the evidence above (do not invent or assume any data not present), produce a professional security incident report with the following sections:

### 1. Executive Summary
A 3-sentence overview of what happened, suitable for a non-technical manager.

### 2. Threat Correlation Analysis
Identify all connections between the three agent findings (e.g., same IP appearing in logs and email headers, matching domains, timing patterns). List each correlation as a bullet point.

### 3. Attack Vector & Kill Chain Mapping
Based on the evidence, describe the likely attack sequence step-by-step (e.g., Reconnaissance → Initial Access → Execution → Persistence).

### 4. Severity Assessment
- Overall Incident Severity: [CRITICAL / HIGH / MEDIUM / LOW]
- Confidence Level: [HIGH / MEDIUM / LOW]
- Estimated Risk Score: [0-100]
- Justification: (1-2 sentences)

### 5. Recommended Immediate Actions
Provide exactly 5 specific, actionable remediation steps ordered by priority. Each step must reference the specific evidence that motivated it.

### 6. Indicators of Compromise (IOCs)
List all IOCs extracted from the findings in a structured format:
- Malicious IPs: ...
- Suspicious Domains/URLs: ...
- Targeted Usernames: ...
- Attack Techniques: ...

Keep the tone professional. Do not use filler phrases like "It is important to note that".
"""

class CorrelationAgent(BaseAgent):
    def __init__(self, api_key: str = None):
        super().__init__("CorrelationAgent")
        key = api_key or os.getenv("GEMINI_API_KEY", "")
        self.is_configured = bool(key and key != "your_google_gemini_api_key_here")
        if self.is_configured:
            genai.configure(api_key=key)
            self.model = genai.GenerativeModel('gemini-2.5-flash')

    def analyze(self, email_findings: dict, ip_findings: dict, log_findings: dict) -> dict:
        self.logger.info("Starting LLM correlation...")

        if not self.is_configured:
            return {
                "report": "⚠️ Gemini API key not configured. Please enter your API key in the Settings page.",
                "severity": "UNKNOWN",
                "risk_score": 0,
                "ioc_count": 0
            }

        prompt = PROMPT_TEMPLATE.format(
            email_findings=email_findings,
            ip_findings=ip_findings,
            log_findings=log_findings
        )

        try:
            response = self.model.generate_content(prompt)
            report_text = response.text

            # Parse severity from the report
            severity = "MEDIUM"
            for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                if level in report_text:
                    severity = level
                    break

            # Count IOCs
            ioc_count = (
                len(email_findings.get("extracted_urls", [])) +
                len(email_findings.get("extracted_emails", [])) +
                len([ip for ip, d in ip_findings.items() if d.get("malicious_score", 0) > 25]) +
                len(log_findings.get("suspicious_ip_list", []))
            )

            # Compute combined risk score
            email_risk = email_findings.get("risk_score", 0)
            log_risk = log_findings.get("risk_score", 0)
            ip_risk = max((d.get("malicious_score", 0) for d in ip_findings.values()), default=0) if ip_findings else 0
            combined_risk = round((email_risk * 0.3 + log_risk * 0.4 + ip_risk * 0.3), 1)

            self.logger.info(f"Correlation complete. Severity={severity}, Risk={combined_risk}")
            return {
                "report": report_text,
                "severity": severity,
                "risk_score": combined_risk,
                "ioc_count": ioc_count
            }

        except Exception as e:
            self.logger.error(f"LLM call failed: {e}")
            return {
                "report": f"Error connecting to Gemini API: {str(e)}",
                "severity": "UNKNOWN",
                "risk_score": 0,
                "ioc_count": 0
            }
