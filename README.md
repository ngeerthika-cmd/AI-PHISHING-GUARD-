# 🛡️ AI Phishing Guard — Enterprise SOC Security Dashboard

**AI Phishing Guard** is a full-featured, multi-layer Explainable-AI Security Dashboard designed for Security Operations Centers (SOC). Built using **Python FastAPI** and an interactive dark-themed UI, it detects, analyzes, and educates on phishing, smishing, and social engineering threats in real time.

---

## ✨ Key Features

* 🚀 **Interactive Scan Center:** Analyzes URLs, domains, and SMS payloads dynamically across heuristic risk engines with live color-coded status badges (Safe / Suspicious / High Risk).
* ⚔️ **Attack Kill-Chain Visualization:** Dynamic 5-stage cyber threat flow visualizer that updates states automatically based on target inspection.
* 🤖 **Digital Twin Sandbox Simulation:** Safe, animated AI replica analysis predicting credential theft probabilities without interacting with live target servers.
* 🛰️ **Global Threat Intelligence Integration:** Cross-references active indicators against URLHaus, VirusTotal, and AbusePDB status structures.
* 🕵️ **Hidden HTML / Zero-Font Detector:** Scans raw HTML email source for zero-size fonts (`font-size:0px`), `display:none` evasion, and off-screen text positioning tricks.
* 🎓 **Defensive Training Generator:** Automatically constructs customized awareness training email templates and red-flag explanations based on scanned targets.
* 💬 **AI SOC Security Assistant:** Intelligent interactive chat assistant providing real-time security context, explanation, and threat mitigation advice.

---

## 🛠️ Tech Stack

* **Backend:** Python 3.10+, FastAPI, Uvicorn
* **Frontend:** HTML5, CSS3 (Dark Mode SOC Design System), JavaScript (ES6+ Fetch API, Single-Page App architecture)
* **Detection Engine:** Heuristic Rule Parsing, Regular Expressions (Regex), Real-time Threat Scoring Model

---

## 🚦 Getting Started

### Prerequisites

Ensure Python is installed on your machine:
```bash
python --version
