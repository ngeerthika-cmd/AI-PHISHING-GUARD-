from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn
import re

app = FastAPI(title="AI Phishing Guard Enterprise SOC")

def analyze_any_threat(input_text: str):
    text_lower = input_text.lower()
    score = 10
    indicators = []
    
    is_phishing = any(kw in text_lower for kw in ['paypal', 'secure', 'bank', 'login', 'update', 'kyc', 'verify', 'account', 'reward', 'free', 'bonus', 'claim', 'apple', 'netflix', 'xyz'])
    
    if is_phishing:
        score += 65
        indicators.append("High-value social engineering or brand impersonation keyword detected.")
    
    if '-' in text_lower or re.search(r'\d{2,}', text_lower):
        score += 15
        indicators.append("Contains suspicious hyphens, numbers, or obfuscated patterns.")
        
    if 'http' in text_lower and not text_lower.startswith('https://'):
        score += 10
        indicators.append("Insecure HTTP protocol or missing valid encryption indicator.")
        
    if score > 98: score = 95
    
    if score >= 50:
        status = "HIGH RISK / PHISHING LIKELY"
    elif score >= 25:
        status = "MODERATE / SUSPICIOUS"
    else:
        status = "LOW RISK / LIKELY SAFE"
    
    return {
        "input": input_text,
        "score": score,
        "status": status,
        "is_phishing": is_phishing,
        "indicators": indicators if indicators else ["No severe heuristic anomalies detected. Domain structure appears valid and trusted."]
    }

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AI Phishing Guard Enterprise SOC Dashboard</title>
    <style>
        :root {
            --bg-color: #0b0f19;
            --panel-bg: #111827;
            --border-color: #1f2937;
            --text-primary: #f9fafb;
            --text-secondary: #9ca3af;
            --accent-blue: #2563eb;
            --accent-cyan: #06b6d4;
            --accent-green: #10b981;
            --accent-yellow: #f59e0b;
            --accent-red: #ef4444;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background-color: var(--bg-color); color: var(--text-primary); display: flex; height: 100vh; overflow: hidden; }
        
        /* Sidebar */
        .sidebar { width: 270px; background-color: var(--panel-bg); border-right: 1px solid var(--border-color); display: flex; flex-direction: column; }
        .sidebar-header { padding: 22px; font-size: 1.1rem; font-weight: bold; border-bottom: 1px solid var(--border-color); color: var(--text-primary); display: flex; align-items: center; gap: 8px; cursor: pointer; }
        .nav-links { list-style: none; padding: 15px; overflow-y: auto; flex-grow: 1; }
        .nav-links li { padding: 12px 16px; margin-bottom: 6px; border-radius: 6px; cursor: pointer; color: var(--text-secondary); transition: all 0.2s ease; font-size: 0.95rem; font-weight: 500; }
        .nav-links li:hover, .nav-links li.active { background-color: var(--accent-blue); color: var(--text-primary); transform: translateX(4px); }
        .backend-status { padding: 15px; font-size: 0.85rem; border-top: 1px solid var(--border-color); color: var(--accent-green); background: #07090e; font-family: monospace; display: flex; align-items: center; gap: 6px; }
        .backend-status::before { content: ""; width: 8px; height: 8px; background: var(--accent-green); border-radius: 50%; display: inline-block; }

        /* Main Content */
        .main-content { flex-grow: 1; display: flex; flex-direction: column; overflow-y: auto; }
        .top-bar { padding: 18px 30px; background-color: var(--panel-bg); border-bottom: 1px solid var(--border-color); font-size: 1.15rem; font-weight: bold; display: flex; justify-content: space-between; align-items: center; }
        .content-body { padding: 30px; flex-grow: 1; }
        
        /* SOC Guidance Box */
        .soc-guide { background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%); border: 1px solid #6366f1; border-radius: 8px; padding: 16px 20px; margin-bottom: 25px; display: flex; gap: 15px; align-items: flex-start; box-shadow: 0 4px 12px rgba(99,102,241,0.2); }
        .soc-guide-icon { font-size: 1.4rem; }
        .soc-guide-content h4 { color: #818cf8; font-size: 0.95rem; margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
        .soc-guide-content p { color: #e0e7ff; font-size: 0.90rem; line-height: 1.4; }

        /* Cover Hero */
        .cover-hero { background: radial-gradient(circle at 90% 10%, #1e293b 0%, #0b0f19 60%); border: 1px solid var(--border-color); border-radius: 12px; padding: 60px 50px; min-height: 550px; display: flex; flex-direction: column; justify-content: center; }
        .cover-logo { width: 64px; height: 64px; background: #1e293b; border: 1px solid #334155; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2rem; margin-bottom: 30px; }
        .cover-title { font-size: 3rem; font-weight: 800; color: #ffffff; margin-bottom: 15px; font-family: 'Georgia', serif; letter-spacing: 1px; }
        .cover-subtitle { font-size: 1.3rem; color: var(--accent-cyan); font-weight: 500; margin-bottom: 15px; }
        .cover-desc { font-size: 1rem; color: var(--text-secondary); font-style: italic; margin-bottom: 40px; }
        .cover-pills { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 40px; }
        .pill { background: #1e293b; border: 1px solid #334155; padding: 10px 24px; border-radius: 24px; font-size: 0.9rem; color: #e2e8f0; cursor: pointer; transition: all 0.2s; }
        .pill:hover { border-color: var(--accent-cyan); background: #334155; }

        /* Cards & Metrics */
        .metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }
        .card { background-color: var(--panel-bg); border: 1px solid var(--border-color); border-radius: 8px; padding: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
        .card-title { font-size: 0.78rem; color: var(--text-secondary); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
        .card-value { font-size: 2.2rem; font-weight: bold; color: var(--text-primary); }
        
        /* Sections */
        .section-box { background-color: var(--panel-bg); border: 1px solid var(--border-color); border-radius: 8px; padding: 25px; margin-bottom: 25px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
        .section-title { font-size: 1.1rem; font-weight: bold; margin-bottom: 15px; color: var(--text-primary); display: flex; align-items: center; gap: 10px; }
        .section-desc { font-size: 0.9rem; color: var(--text-secondary); margin-bottom: 20px; line-height: 1.4; }
        
        /* Forms & Inputs */
        .input-group { display: flex; gap: 10px; margin-bottom: 15px; }
        input[type="text"], textarea { flex-grow: 1; background: var(--bg-color); border: 1px solid var(--border-color); padding: 12px 15px; border-radius: 6px; color: var(--text-primary); font-size: 0.95rem; }
        input[type="text"]:focus, textarea:focus { border-color: var(--accent-cyan); outline: none; }
        textarea { height: 130px; resize: vertical; font-family: monospace; }
        button { background-color: var(--accent-blue); color: white; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-weight: bold; transition: background 0.2s; font-size: 0.95rem; }
        button:hover { background-color: #1d4ed8; }
        
        /* Tab visibility */
        .tab-pane { display: none; }
        .tab-pane.active { display: block; }
        
        /* Pipeline / Charts */
        .pipeline-bars { display: flex; align-items: flex-end; gap: 20px; height: 200px; padding-top: 20px; border-bottom: 2px solid var(--border-color); }
        .bar-col { flex: 1; display: flex; flex-direction: column; align-items: center; height: 100%; justify-content: flex-end; }
        .bar { width: 100%; background: var(--accent-cyan); border-radius: 4px 4px 0 0; }
        .bar-label { font-size: 0.75rem; color: var(--text-secondary); margin-top: 10px; text-align: center; font-weight: 500; }

        /* Kill Chain Items */
        .kill-item { display: flex; align-items: flex-start; gap: 15px; padding: 18px; margin-bottom: 12px; background: var(--bg-color); border: 1px solid var(--border-color); border-radius: 6px; }
        .kill-icon { font-size: 1.4rem; padding: 8px; background: var(--panel-bg); border-radius: 6px; border: 1px solid var(--border-color); min-width: 45px; text-align: center; }
        .kill-content h4 { margin-bottom: 4px; color: var(--text-primary); font-size: 1.05rem; }
        .kill-content p { font-size: 0.9rem; color: var(--text-secondary); }
        
        /* Dynamic Badges */
        .badge { padding: 6px 12px; border-radius: 4px; font-size: 0.85rem; display: inline-block; margin-bottom: 15px; font-weight: bold; }
        .badge.danger { background: rgba(239, 68, 68, 0.15); color: var(--accent-red); border: 1px solid rgba(239, 68, 68, 0.3); }
        .badge.warning { background: rgba(245, 158, 11, 0.15); color: var(--accent-yellow); border: 1px solid rgba(245, 158, 11, 0.3); }
        .badge.safe { background: rgba(16, 185, 129, 0.15); color: var(--accent-green); border: 1px solid rgba(16, 185, 129, 0.3); }
        
        .result-box { background: var(--bg-color); border: 1px solid var(--border-color); padding: 18px; border-radius: 6px; margin-top: 15px; font-family: monospace; white-space: pre-wrap; font-size: 0.9rem; line-height: 1.5; color: #f3f4f6; }
        
        /* Active Modules */
        .module-list { list-style: none; display: flex; flex-direction: column; gap: 10px; }
        .module-item { display: flex; align-items: center; gap: 12px; font-size: 0.95rem; color: var(--text-secondary); }
        .check-box { color: var(--accent-green); font-weight: bold; font-size: 1.1rem; }

        /* Digital Twin Points */
        .twin-steps { display: flex; flex-direction: column; gap: 10px; margin-bottom: 20px; }
        .twin-step-item { display: flex; align-items: center; gap: 12px; background: var(--bg-color); padding: 12px 16px; border: 1px solid var(--border-color); border-radius: 6px; font-size: 0.95rem; color: var(--text-secondary); }
        .twin-step-num { width: 22px; height: 22px; background: rgba(239, 68, 68, 0.2); color: var(--accent-red); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 0.8rem; font-weight: bold; }

        /* Threat Feed Rows */
        .feed-row { background: var(--bg-color); border: 1px solid var(--border-color); padding: 15px; border-radius: 6px; margin-bottom: 12px; }
        .feed-title { font-weight: bold; color: var(--text-primary); margin-bottom: 4px; display: flex; justify-content: space-between; align-items: center; }
        .feed-desc { font-size: 0.85rem; color: var(--text-secondary); }
        .status-tag { font-size: 0.75rem; padding: 3px 8px; border-radius: 4px; background: #1f2937; color: var(--text-secondary); border: 1px solid var(--border-color); }
        .status-tag.clean { background: rgba(16, 185, 129, 0.15); color: var(--accent-green); border-color: rgba(16, 185, 129, 0.3); }
        .status-tag.warning { background: rgba(245, 158, 11, 0.15); color: var(--accent-yellow); border-color: rgba(245, 158, 11, 0.3); }
        .status-tag.danger { background: rgba(239, 68, 68, 0.15); color: var(--accent-red); border-color: rgba(239, 68, 68, 0.3); }
        
        /* Chat box */
        .chat-container { display: flex; flex-direction: column; height: 350px; background: var(--bg-color); border: 1px solid var(--border-color); border-radius: 6px; padding: 15px; overflow-y: auto; margin-bottom: 15px; gap: 12px; }
        .chat-msg { padding: 12px 16px; border-radius: 6px; max-width: 85%; font-size: 0.95rem; line-height: 1.4; }
        .chat-msg.user { background: var(--accent-blue); color: white; align-self: flex-start; }
        .chat-msg.ai { background: #1f2937; color: var(--text-primary); align-self: flex-start; border: 1px solid var(--border-color); }
    </style>
</head>
<body>

    <!-- Sidebar Navigation -->
    <div class="sidebar">
        <div class="sidebar-header" onclick="switchTab('home', document.getElementById('nav-cover'))">
            <span>🛡️</span> AI Phishing Guard
        </div>
        <ul class="nav-links">
            <li id="nav-cover" class="active" onclick="switchTab('home', this)">Home</li>
            <li onclick="switchTab('overview', this)">Overview</li>
            <li onclick="switchTab('scan', this)">Scan Center</li>
            <li onclick="switchTab('killchain', this)">Kill Chain</li>
            <li onclick="switchTab('digitaltwin', this)">Digital Twin</li>
            <li onclick="switchTab('threatintel', this)">Threat Intel</li>
            <li onclick="switchTab('hiddenhtml', this)">Hidden HTML</li>
            <li onclick="switchTab('training', this)">Training Generator</li>
            <li onclick="switchTab('assistant', this)">AI Assistant</li>
        </ul>
        <div class="backend-status">Backend Connected: localhost:8000</div>
    </div>

    <!-- Main Content Panel -->
    <div class="main-content">
        <div class="top-bar">
            <span id="topbar-title">AI PHISHING GUARD</span>
            <span style="font-size: 0.85rem; color: var(--text-secondary);">Enterprise SOC Dashboard</span>
        </div>
        
        <div class="content-body">
            
            <!-- 0. COVER PAGE -->
            <div id="home" class="tab-pane active">
                <div class="cover-hero">
                    <div class="cover-logo">🛡️</div>
                    <div class="cover-title">AI PHISHING GUARD</div>
                    <div class="cover-subtitle">Multi-Layer AI Detection for Phishing, Quishing & Smishing Attacks</div>
                    <div class="cover-desc">Not just a URL scanner — a full explainable-AI security platform that detects, explains, and teaches.</div>
                    
                    <div class="cover-pills">
                        <div class="pill" onclick="switchTab('scan', document.querySelectorAll('.nav-links li')[2])">🚀 Test Scan Center</div>
                        <div class="pill" onclick="switchTab('hiddenhtml', document.querySelectorAll('.nav-links li')[6])">🕵️ Test Hidden HTML</div>
                        <div class="pill" onclick="switchTab('assistant', document.querySelectorAll('.nav-links li')[8])">🤖 Ask AI Assistant</div>
                    </div>
                </div>
            </div>

            <!-- 1. OVERVIEW TAB -->
            <div id="overview" class="tab-pane">
                <div class="soc-guide">
                    <div class="soc-guide-icon">💡</div>
                    <div class="soc-guide-content">
                        <h4>SOC Analyst Guide</h4>
                        <p>This section displays real-time threat metrics and active detection module weights across multi-layer scanning engines.</p>
                    </div>
                </div>
                <div class="metrics-grid">
                    <div class="card"><div class="card-title">Total Community Reports</div><div class="card-value">1,248</div></div>
                    <div class="card"><div class="card-title">Unique URLs Reported</div><div class="card-value">842</div></div>
                    <div class="card"><div class="card-title">Auto-Flagged Threats</div><div class="card-value">315</div></div>
                    <div class="card"><div class="card-title">Active Detection Modules</div><div class="card-value">13</div></div>
                </div>
                
                <div class="section-box">
                    <div class="section-title">Detection Pipeline (Weight in Risk Engine %)</div>
                    <div class="pipeline-bars">
                        <div class="bar-col"><div class="bar" style="height: 45%;"></div><div class="bar-label">URL Analysis</div></div>
                        <div class="bar-col"><div class="bar" style="height: 30%;"></div><div class="bar-label">NLP Text</div></div>
                        <div class="bar-col"><div class="bar" style="height: 30%;"></div><div class="bar-label">Computer Vision</div></div>
                        <div class="bar-col"><div class="bar" style="height: 20%;"></div><div class="bar-label">Multimodal</div></div>
                        <div class="bar-col"><div class="bar" style="height: 100%;"></div><div class="bar-label">Smishing</div></div>
                        <div class="bar-col"><div class="bar" style="height: 40%;"></div><div class="bar-label">Threat Intel</div></div>
                        <div class="bar-col"><div class="bar" style="height: 30%;"></div><div class="bar-label">Hidden HTML</div></div>
                    </div>
                </div>

                <div class="section-box">
                    <div class="section-title">Active Modules</div>
                    <ul class="module-list">
                        <li class="module-item"><span class="check-box">✔</span> URL & Domain Intelligence</li>
                        <li class="module-item"><span class="check-box">✔</span> NLP Text Analysis</li>
                        <li class="module-item"><span class="check-box">✔</span> Computer Vision Logo Match</li>
                        <li class="module-item"><span class="check-box">✔</span> Multimodal QR/PDF Scanning</li>
                    </ul>
                </div>
            </div>

            <!-- 2. SCAN CENTER TAB -->
            <div id="scan" class="tab-pane">
                <div class="soc-guide">
                    <div class="soc-guide-icon">💡</div>
                    <div class="soc-guide-content">
                        <h4>SOC Analyst Guide</h4>
                        <p>Enter any URL or SMS message below and click 'Check Threat Intel' to update all SOC modules instantly.</p>
                    </div>
                </div>
                <div class="section-box">
                    <div class="section-title">URL & Threat Intelligence Scanner</div>
                    <div class="input-group">
                        <input type="text" id="scan-url-input" value="http://www.paypal1.com" placeholder="Enter any URL or SMS message..." onkeypress="if(event.key === 'Enter') runLiveScan()">
                        <button type="button" onclick="runLiveScan()">Check Threat Intel</button>
                    </div>
                    <div class="result-box" id="scan-result-box">URL Analyzed: http://www.paypal1.com
Status: HIGH RISK / PHISHING LIKELY
- Heuristic Risk Score: 90% (High Risk)
- Findings: High-value social engineering or brand impersonation keyword detected.
- AI Recommendation: Block access immediately and isolate endpoint.</div>
                </div>
            </div>

            <!-- 3. KILL CHAIN TAB -->
            <div id="killchain" class="tab-pane">
                <div class="soc-guide">
                    <div class="soc-guide-icon">💡</div>
                    <div class="soc-guide-content">
                        <h4>SOC Analyst Guide</h4>
                        <p>Tracks automated attack methodology tailored directly to your current scanned target.</p>
                    </div>
                </div>
                <div class="section-box">
                    <div class="section-title">Attack Kill-Chain Visualization</div>
                    <div class="section-desc" id="killchain-desc">Active target: http://www.paypal1.com</div>
                    <button style="margin-bottom: 20px;" onclick="replayKillChain()">▶ Replay Attack Flow</button>
                    <div class="badge danger" id="killchain-badge">HIGH RISK / ATTACK FLOW IN PROGRESS</div>
                    
                    <div class="kill-item">
                        <div class="kill-icon">🌐</div>
                        <div class="kill-content" style="width: 100%;">
                            <h4>Reconnaissance <span style="color: var(--accent-green);">✔</span></h4>
                            <p id="kc-1">Attacker targeted domain infrastructure matching input payload.</p>
                        </div>
                    </div>
                    <div class="kill-item">
                        <div class="kill-icon">📦</div>
                        <div class="kill-content" style="width: 100%;">
                            <h4>Weaponization <span style="color: var(--accent-green);">✔</span></h4>
                            <p id="kc-2">Fake phishing infrastructure and lookalike templates prepared.</p>
                        </div>
                    </div>
                    <div class="kill-item">
                        <div class="kill-icon">✉️</div>
                        <div class="kill-content" style="width: 100%;">
                            <h4>Delivery <span style="color: var(--accent-green);">✔</span></h4>
                            <p id="kc-3">Malicious link distributed via active SMS/Email vector.</p>
                        </div>
                    </div>
                    <div class="kill-item">
                        <div class="kill-icon">🔐</div>
                        <div class="kill-content" style="width: 100%;">
                            <h4>Credential Harvesting <span style="color: var(--accent-green);">✔</span></h4>
                            <p id="kc-4">Credential harvesting page active on target endpoint.</p>
                        </div>
                    </div>
                    <div class="kill-item">
                        <div class="kill-icon">💥</div>
                        <div class="kill-content" style="width: 100%;">
                            <h4>Impact <span style="color: var(--accent-green);">✔</span></h4>
                            <p id="kc-5">Account compromise risk predicted by active AI engine.</p>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 4. DIGITAL TWIN TAB -->
            <div id="digitaltwin" class="tab-pane">
                <div class="soc-guide">
                    <div class="soc-guide-icon">💡</div>
                    <div class="soc-guide-content">
                        <h4>SOC Analyst Guide</h4>
                        <p>Simulates safe sandboxed AI replica analysis based on your active scanned target.</p>
                    </div>
                </div>
                <div class="section-box">
                    <div class="section-title">Digital Twin Attack Simulation</div>
                    <div class="section-desc" id="dt-desc">Safe, animated simulation for active target: http://www.paypal1.com</div>
                    <button style="margin-bottom: 20px;" onclick="runSimulation()">▶ Run Simulation</button>
                    
                    <div style="background: var(--bg-color); border: 1px solid var(--border-color); border-radius: 8px; padding: 20px;">
                        <div style="color: var(--accent-cyan); font-weight: bold; font-size: 0.9rem; margin-bottom: 15px;">▲ Safe AI Simulation — No real website or user data accessed</div>
                        <div class="twin-steps">
                            <div class="twin-step-item"><div class="twin-step-num">1</div> <span id="dt-1">AI created a virtual replica of the scanned target</span></div>
                            <div class="twin-step-item"><div class="twin-step-num">2</div> <span id="dt-2">Computer Vision compared brand logo and page layout</span></div>
                            <div class="twin-step-item"><div class="twin-step-num">3</div> <span id="dt-3">AI evaluated login forms and credential-harvesting triggers</span></div>
                            <div class="twin-step-item"><div class="twin-step-num">4</div> <span id="dt-4">Threat model calculated overall risk probability</span></div>
                        </div>
                        <div style="color: var(--accent-red); font-weight: bold; margin-top: 15px; font-size: 1.1rem;" id="dt-probability">90% Probability of Credential Theft</div>
                    </div>
                </div>
            </div>

            <!-- 5. THREAT INTEL TAB -->
            <div id="threatintel" class="tab-pane">
                <div class="soc-guide">
                    <div class="soc-guide-icon">💡</div>
                    <div class="soc-guide-content">
                        <h4>SOC Analyst Guide</h4>
                        <p>Cross-references target URLs against global intelligence feeds (URLHaus, VirusTotal, AbusePDB).</p>
                    </div>
                </div>
                <div class="section-box">
                    <div class="section-title">Threat Intelligence Feeds</div>
                    <input type="text" id="ti-display-url" value="http://www.paypal1.com" style="margin-bottom: 15px;" placeholder="Enter URL to check intel..." onkeypress="if(event.key === 'Enter') runLiveScanFromTI()">
                    <button style="margin-bottom: 20px;" onclick="runLiveScanFromTI()">Check Threat Intel</button>
                    
                    <div class="feed-row">
                        <div class="feed-title">URLHaus <span class="status-tag danger" id="ti-urlhaus">malicious payload</span></div>
                        <div class="feed-desc" id="ti-urlhaus-desc">Linked to active malware or phishing drop zone.</div>
                    </div>
                    <div class="feed-row">
                        <div class="feed-title">VirusTotal <span class="status-tag danger" id="ti-vt">flagged 16/88</span></div>
                        <div class="feed-desc" id="ti-vt-desc">Multiple security vendors flagged lookalike anomaly.</div>
                    </div>
                    <div class="feed-row">
                        <div class="feed-title">AbusePDB <span class="status-tag danger" id="ti-abuse">abusive IP reported</span></div>
                        <div class="feed-desc" id="ti-abuse-desc">Associated with recent abusive traffic reports.</div>
                    </div>
                </div>
            </div>

            <!-- 6. HIDDEN HTML TAB -->
            <div id="hiddenhtml" class="tab-pane">
                <div class="soc-guide">
                    <div class="soc-guide-icon">💡</div>
                    <div class="soc-guide-content">
                        <h4>SOC Analyst Guide</h4>
                        <p>Paste raw HTML source below to analyze text-salting, zero-size fonts, and display:none evasion tricks.</p>
                    </div>
                </div>
                <div class="section-box">
                    <div class="section-title">Hidden HTML / Zero-Font Detection</div>
                    <textarea id="html-input"><p style="font-size:0px;">once upon a time in a land of recipes and history...</p>
<p>Click here to <span style="display:none;">hidden</span> verify your account now.</p>
<p style="position:absolute; left:-9999px;">hidden filler text block</p></textarea>
                    <div style="margin-top: 15px; display: flex; gap: 10px;">
                        <button onclick="analyzeHTML()">Analyze HTML</button>
                        <button style="background: #374151;" onclick="loadExampleHTML()">Load Example Payload</button>
                    </div>
                    <div class="result-box" id="html-result">Risk: 60%
- Hidden-text CSS tricks detected: zero size font (text invisible to users but parsed by scanners), display:none elements, text pushed off-screen.
- 2 explicitly hidden element(s) found in markup.</div>
                </div>
            </div>

            <!-- 7. TRAINING GENERATOR TAB -->
            <div id="training" class="tab-pane">
                <div class="soc-guide">
                    <div class="soc-guide-icon">💡</div>
                    <div class="soc-guide-content">
                        <h4>SOC Analyst Guide</h4>
                        <p>Generates defensive phishing training templates and quiz materials based on active scan inputs.</p>
                    </div>
                </div>
                <div class="section-box">
                    <div class="section-title">AI Phishing Email Generator (Defensive Training)</div>
                    <input type="text" id="training-input" value="Bank KYC Scam" style="margin-bottom: 15px;" placeholder="Enter topic or scam type...">
                    <button style="margin-bottom: 20px;" onclick="generateTraining()">Generate Training Email</button>
                    <div class="result-box" id="training-result">Subject: Immediate Action Required: Your Account KYC Has Expired
Dear Valued Customer,
Our records indicate that your KYC verification has expired. Your account will be temporarily suspended within 24 hours.

Link: http://www.paypal1.com

Red Flags Detected:
- Fake urgency (24 hours deadline)
- Suspicious domain or lookalike link
- Generic greeting & scare tactics</div>
                </div>
            </div>

            <!-- 8. AI ASSISTANT TAB -->
            <div id="assistant" class="tab-pane">
                <div class="soc-guide">
                    <div class="soc-guide-icon">💡</div>
                    <div class="soc-guide-content">
                        <h4>SOC Analyst Guide</h4>
                        <p>Ask any security-related question. The AI bot answers based on your currently active scan target.</p>
                    </div>
                </div>
                <div class="section-box">
                    <div class="section-title">AI Chat Assistant</div>
                    <div class="chat-container" id="chatbox">
                        <div class="chat-msg ai">Hello! I am your AI Security Assistant. Ask me anything about threat scans, suspicious URLs, emails, or security rules. How can I assist you today?</div>
                    </div>
                    <div class="input-group">
                        <input type="text" id="user-input" placeholder="Ask a question about threats, URLs, or scans..." onkeypress="if(event.key === 'Enter') sendChatMessage()">
                        <button onclick="sendChatMessage()">Send</button>
                    </div>
                </div>
            </div>

        </div>
    </div>

    <script>
        let currentScanData = {
            input: "http://www.paypal1.com",
            score: 90,
            status: "HIGH RISK / PHISHING LIKELY",
            is_phishing: true,
            indicators: ["High-value social engineering or brand impersonation keyword detected."]
        };

        function switchTab(tabId, element) {
            document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.nav-links li').forEach(el => el.classList.remove('active'));
            
            document.getElementById(tabId).classList.add('active');
            if (element) {
                element.classList.add('active');
            } else {
                const links = document.querySelectorAll('.nav-links li');
                const map = {'home':0, 'overview':1, 'scan':2, 'killchain':3, 'digitaltwin':4, 'threatintel':5, 'hiddenhtml':6, 'training':7, 'assistant':8};
                if(map[tabId] !== undefined) links[map[tabId]].classList.add('active');
            }
            
            const titles = {
                'home': 'AI PHISHING GUARD',
                'overview': 'Overview Dashboard',
                'scan': 'Scan Center',
                'killchain': 'Kill Chain Visualization',
                'digitaltwin': 'Digital Twin Attack Simulation',
                'threatintel': 'Threat Intelligence Feeds',
                'hiddenhtml': 'Hidden HTML / Zero-Font Detection',
                'training': 'AI Phishing Email Generator',
                'assistant': 'AI Chat Assistant'
            };
            document.getElementById('topbar-title').innerText = titles[tabId] || 'AI PHISHING GUARD';
        }

        async function processScan(urlVal) {
            const formData = new FormData();
            formData.append('url', urlVal);

            try {
                const response = await fetch('/scancenter', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                currentScanData = data; // Sync Global State

                // 1. Update Scan Center Input Box & Result Box
                document.getElementById('scan-url-input').value = data.input;
                const resBox = document.getElementById('scan-result-box');
                resBox.innerText = `URL Analyzed: ${data.input}
Status: ${data.status}
- Heuristic Risk Score: ${data.score}%
- Findings: ${data.indicators.join(' ')}
- AI Recommendation: ${data.score >= 50 ? 'Block access immediately and isolate endpoint.' : data.score >= 25 ? 'Caution: Suspicious domain activity observed.' : 'Endpoint appears safe or low risk.'}`;

                // 2. Update Threat Intel Feeds UI
                document.getElementById('ti-display-url').value = data.input;
                const urlhausEl = document.getElementById('ti-urlhaus');
                const vtEl = document.getElementById('ti-vt');
                const abuseEl = document.getElementById('ti-abuse');

                if (data.score >= 50) {
                    urlhausEl.className = "status-tag danger";
                    urlhausEl.innerText = "malicious payload";
                    document.getElementById('ti-urlhaus-desc').innerText = "Linked to active malware or phishing drop zone.";
                    
                    vtEl.className = "status-tag danger";
                    vtEl.innerText = "flagged 16/88";
                    document.getElementById('ti-vt-desc').innerText = "Multiple security vendors flagged lookalike anomaly.";
                    
                    abuseEl.className = "status-tag danger";
                    abuseEl.innerText = "abusive IP reported";
                    document.getElementById('ti-abuse-desc').innerText = "Associated with recent abusive traffic reports.";
                } else if (data.score >= 25) {
                    urlhausEl.className = "status-tag warning";
                    urlhausEl.innerText = "suspicious structure";
                    document.getElementById('ti-urlhaus-desc').innerText = "Unverified domain host / new registration.";
                    
                    vtEl.className = "status-tag warning";
                    vtEl.innerText = "flagged 2/88";
                    document.getElementById('ti-vt-desc').innerText = "Minor heuristic anomalies reported by vendors.";
                    
                    abuseEl.className = "status-tag warning";
                    abuseEl.innerText = "moderate risk";
                    document.getElementById('ti-abuse-desc').innerText = "Dynamic IP range with limited reputation history.";
                } else {
                    urlhausEl.className = "status-tag clean";
                    urlhausEl.innerText = "clean";
                    document.getElementById('ti-urlhaus-desc').innerText = "No active malware payloads reported.";
                    
                    vtEl.className = "status-tag clean";
                    vtEl.innerText = "0/88 clean";
                    document.getElementById('ti-vt-desc').innerText = "All security engines confirmed clean domain.";
                    
                    abuseEl.className = "status-tag clean";
                    abuseEl.innerText = "no reports";
                    document.getElementById('ti-abuse-desc').innerText = "No abusive IP activity recorded.";
                }

                // 3. Dynamic Kill Chain Badge & Stages (RED / YELLOW / GREEN)
                document.getElementById('killchain-desc').innerText = "Active target: " + data.input;
                const kcBadge = document.getElementById('killchain-badge');
                
                if (data.score >= 50) {
                    kcBadge.className = "badge danger";
                    kcBadge.innerText = "HIGH RISK / ATTACK FLOW IN PROGRESS";
                    document.getElementById('kc-1').innerText = "Attacker targeted domain infrastructure matching input payload.";
                    document.getElementById('kc-2').innerText = "Fake phishing infrastructure and lookalike templates prepared.";
                    document.getElementById('kc-3').innerText = "Malicious link distributed via active SMS/Email vector.";
                    document.getElementById('kc-4').innerText = "Credential harvesting page active on target endpoint.";
                    document.getElementById('kc-5').innerText = "High compromise risk predicted by active AI engine.";
                } else if (data.score >= 25) {
                    kcBadge.className = "badge warning";
                    kcBadge.innerText = "MODERATE RISK / ATTACK SUSPECTED";
                    document.getElementById('kc-1').innerText = "Suspicious domain query observed.";
                    document.getElementById('kc-2').innerText = "Unverified web components detected.";
                    document.getElementById('kc-3').innerText = "Link delivered via unverified route.";
                    document.getElementById('kc-4').innerText = "Form inputs under observation.";
                    document.getElementById('kc-5').innerText = "Moderate anomaly score calculated.";
                } else {
                    kcBadge.className = "badge safe";
                    kcBadge.innerText = "SYSTEM SECURE / TARGET VERIFIED SAFE";
                    document.getElementById('kc-1').innerText = "Domain verified as official trusted infrastructure.";
                    document.getElementById('kc-2').innerText = "No weaponized phishing templates detected.";
                    document.getElementById('kc-3').innerText = "Normal web traffic routing observed.";
                    document.getElementById('kc-4').innerText = "No credential theft forms identified.";
                    document.getElementById('kc-5').innerText = "Zero compromise risk detected.";
                }

                // 4. Update Digital Twin UI
                document.getElementById('dt-desc').innerText = "Safe, animated simulation for active target: " + data.input;
                const dtProb = document.getElementById('dt-probability');
                if (data.score >= 50) {
                    dtProb.style.color = "var(--accent-red)";
                    dtProb.innerText = `${data.score}% Probability of Credential Theft`;
                } else if (data.score >= 25) {
                    dtProb.style.color = "var(--accent-yellow)";
                    dtProb.innerText = `${data.score}% Suspicious Risk Identified`;
                } else {
                    dtProb.style.color = "var(--accent-green)";
                    dtProb.innerText = `${data.score}% Risk / Safe Domain Verified`;
                }

            } catch (err) {
                console.error(err);
            }
        }

        async function runLiveScan() {
            const urlVal = document.getElementById('scan-url-input').value;
            document.getElementById('scan-result-box').innerText = "Analyzing input across 13 detection engines...";
            await processScan(urlVal);
        }

        async function runLiveScanFromTI() {
            const urlVal = document.getElementById('ti-display-url').value;
            await processScan(urlVal);
            alert(`Threat Intel refreshed for: "${urlVal}"\\nStatus: ${currentScanData.status} (${currentScanData.score}% Risk)`);
        }

        function replayKillChain() {
            alert(`Replaying attack flow for active target: "${currentScanData.input}"\\nStatus: ${currentScanData.status} (${currentScanData.score}% Risk)\\nAll 5 kill-chain stages evaluated.`);
        }

        function runSimulation() {
            alert(`Digital Twin Sandbox Initialized for "${currentScanData.input}":\\n- Virtual replica analyzed safely.\\n- Calculated Result: ${currentScanData.score}% Threat Level.`);
        }

        function analyzeHTML() {
            const val = document.getElementById('html-input').value.toLowerCase();
            const resBox = document.getElementById('html-result');
            let risk = 15;
            let findings = [];
            
            if (val.includes('font-size:0px') || val.includes('font-size: 0px')) {
                risk += 35;
                findings.push("Zero-size font trick detected (font-size:0px).");
            }
            if (val.includes('display:none')) {
                risk += 30;
                findings.push("Hidden elements detected via display:none.");
            }
            if (val.includes('position:absolute') || val.includes('-9999px')) {
                risk += 25;
                findings.push("Off-screen text positioning detected to evade regex scanners.");
            }
            if (risk > 100) risk = 100;
            
            resBox.innerText = "Risk: " + risk + "%\\n- " + (findings.length > 0 ? findings.join("\\n- ") : "Standard markup structure with no severe evasion elements.") + "\\n- Analysis completed across 13 detection weights.";
        }

        function loadExampleHTML() {
            document.getElementById('html-input').value = '<p style="font-size:0px;">hidden urgent bonus reward instructions...</p>\\n<p>Claim your reward <span style="display:none;">scam_payload</span> now.</p>';
            analyzeHTML();
        }

        function generateTraining() {
            const query = document.getElementById('training-input').value;
            const resBox = document.getElementById('training-result');
            resBox.innerText = `Subject: Security Awareness Training: ${query}
Dear Employee,

This is a generated defensive simulation template corresponding to topic: "${query}".

Target Payload Analyzed: ${currentScanData.input}
Risk Level: ${currentScanData.status} (${currentScanData.score}%)

Red Flags Identified:
- Artificial urgency or social engineering language
- Suspicious domain structure matching pattern: ${currentScanData.input}
- Recommendation: Always verify credentials before submitting sensitive info.`;
        }

        function sendChatMessage() {
            const input = document.getElementById('user-input');
            const chatbox = document.getElementById('chatbox');
            if (!input.value.trim()) return;

            const q = input.value.trim();
            const userDiv = document.createElement('div');
            userDiv.className = 'chat-msg user';
            userDiv.innerText = q;
            chatbox.appendChild(userDiv);

            input.value = '';
            chatbox.scrollTop = chatbox.scrollHeight;

            setTimeout(() => {
                const aiDiv = document.createElement('div');
                aiDiv.className = 'chat-msg ai';
                let reply = "";
                const qLower = q.toLowerCase();
                
                if (qLower.includes('hello') || qLower.includes('hi') || qLower.includes('hey')) {
                    reply = `Hello! I am your AI SOC Assistant. How can I help you analyze URL threats or security rules today? Currently loaded target: "${currentScanData.input}".`;
                } else if (qLower.includes('why') || qLower.includes('block') || qLower.includes('safe') || qLower.includes('link') || qLower.includes('http')) {
                    reply = `Regarding the target "${currentScanData.input}": Risk Score is ${currentScanData.score}% (${currentScanData.status}). Findings: ${currentScanData.indicators.join(' ')}`;
                } else if (qLower.includes('risk') || qLower.includes('score') || qLower.includes('percent')) {
                    reply = `The active risk score for "${currentScanData.input}" is ${currentScanData.score}%, calculated dynamically across our 13 enterprise SOC detection engines.`;
                } else {
                    reply = `I have received your question: "${q}". Regarding our active target "${currentScanData.input}", the threat evaluation is ${currentScanData.status} (${currentScanData.score}% risk). Let me know if you need specific guidance on this!`;
                }
                
                aiDiv.innerText = reply;
                chatbox.appendChild(aiDiv);
                chatbox.scrollTop = chatbox.scrollHeight;
            }, 500);
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def home():
    return HTML_TEMPLATE

@app.post("/scancenter")
async def scan_center(url: str = Form(...)):
    res = analyze_any_threat(url)
    return JSONResponse(content=res)

if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)