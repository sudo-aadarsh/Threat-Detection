# 🛡️ CyberSentinel AI: Multi-Agent SIEM

![UI Preview](https://img.shields.io/badge/UI-Streamlit-FF4B4B?style=flat&logo=streamlit)
![LLM Engine](https://img.shields.io/badge/AI-Google_Gemini_2.5-4285F4?style=flat&logo=google)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=flat&logo=python)
![Status](https://img.shields.io/badge/Status-Active-success)

**CyberSentinel AI** is a professional, multi-agent Security Information and Event Management (SIEM) pipeline built with pure Python. It uses highly specialized agents to analyze emails for phishing, parse security logs for brute-force attacks, query external threat intelligence databases (AbuseIPDB), and dynamically correlate the findings into actionable incident reports using Google's Gemini 2.5 Flash Large Language Model.

## 🚀 Features

*   **📧 Email Agent**: Parses headers and bodies to detect spoofing, phishing links, and social engineering keywords.
*   **📜 Log Agent**: Employs regex-driven analysis to identify failed SSH/auth logins and track brute-force patterns across thousands of events.
*   **🌐 IP Agent**: Queries real-time global threat intelligence databases (AbuseIPDB) to score malicious IP addresses.
*   **🧠 Correlation Agent (LLM)**: Takes output from all other agents and uses Gemini to synthesize the data, calculate risk scores, and propose mitigation strategies.
*   **📊 Enterprise Dashboard**: A beautiful, minimalist Streamlit frontend featuring Plotly charts, incident trend analysis, and live interactive running of the agent pipeline.

## 🛠️ Architecture

The backend pipeline leverages a modular multi-agent system, avoiding heavy frameworks (like Langchain or CrewAI) to ensure lightning-fast execution and easy deployability. All persistent incident reporting is managed cleanly via a local SQLite database and SQLAlchemy.

## ⚙️ Setup & Installation

**1. Clone the repository**
```bash
git clone https://github.com/yourusername/CyberSentinel-MultiAgent-SIEM.git
cd CyberSentinel-MultiAgent-SIEM
```

**2. Create and activate a Virtual Environment**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Set up Environment Variables**
Copy the example environment file and add your keys:
```bash
cp .env.example .env
```
*Note: You will need a free Google Gemini API key. An AbuseIPDB API key is optional but recommended for live IP threat lookups.*

**5. Run the Application**
```bash
streamlit run src/app.py
```
The application will launch on `http://localhost:8501`.

## 📁 Directory Structure
```text
.
├── src/
│   ├── app.py                     # Main Streamlit Frontend
│   ├── agents/
│   │   ├── email_agent.py         # Phishing/Spoof detection
│   │   ├── log_agent.py           # Log parsing & pattern matching
│   │   ├── ip_agent.py            # Threat Intel (AbuseIPDB)
│   │   ├── correlation_agent.py   # LLM Incident Report Generation
│   │   └── base_agent.py          # Abstract Agent class
│   ├── database/
│   │   └── db_setup.py            # SQLAlchemy schema and setup
│   └── utils/
│       └── sample_data.py         # Demo data for testing
├── .env.example                   # Environment variable template
├── requirements.txt               # Python dependencies
└── README.md                      # Project documentation
```

## 🤝 Academic Acknowledgment
This project was developed by Group 4 (Dhruv Malhotra, Aadarsh Jha, Tuhin Mech, Sujal Kumar Kanu) at the BMS Institute of Technology and Management, under the guidance of Dr. Chandrashekhar K. T., for the academic year 2026-27.

---
*Built with ❤️ for better, AI-driven cybersecurity.*
