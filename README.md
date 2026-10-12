# 🛡️ AegisGuard - Autonomous Bug-Bounty Security Assessment Platform

**AegisGuard** is a defensive, scope-enforced, rate-limited web security assessment platform engineered specifically for **authorized bug-bounty programs (HackerOne, Bugcrowd, Intigriti)**, sanctioned penetration testing, and defensive auditing in **Kali Linux** virtual machines and environments.

AegisGuard combines **Kali Linux security tools**, non-destructive HTTP/TLS audit probes, **Machine Learning classification & deduplication** (Scikit-Learn + PyTorch), and **Local AI Reasoning** (powered by `qwen3:latest` via Ollama) into an autonomous security agent with a cybersecurity web interface.

---

## 🏛️ End-to-End Architecture

```text
                     ┌───────────────────────────────────────────┐
                     │         Bug Bounty Scope Engine           │
                     │  config/scope.json & config/policies.json │
                     └─────────────────────┬─────────────────────┘
                                           ↓
                     ┌───────────────────────────────────────────┐
                     │        Target & SSRF Guardrails           │
                     │  Wildcard Matcher & Out-of-Scope Dropper  │
                     └─────────────────────┬─────────────────────┘
                                           ↓
                     ┌───────────────────────────────────────────┐
                     │        Centralized Rate Limiter           │
                     │   Token-Bucket (RPS & Host Cap Guard)     │
                     └─────────────────────┬─────────────────────┘
                                           ↓
                     ┌───────────────────────────────────────────┐
                     │       Autonomous Agent Orchestrator       │
                     │                 agent.py                  │
                     └───────┬───────────────────────────┬───────┘
                             ↓                           ↓
        ┌────────────────────────────┐   ┌────────────────────────────┐
        │   Kali Linux Tool Suite    │   │   Defensive Core Probes    │
        │          tools.py          │   │          core.py           │
        │ • Nmap (Service Banners)   │   │ • OWASP Security Headers   │
        │ • WhatWeb (Tech Stack)     │   │ • Cookie Security Flags    │
        │ • SSLScan (TLS & Ciphers)  │   │ • CORS & HTTP Methods      │
        │ • Nikto (Misconfigurations)│   │ • Info Disclosure / Errors │
        │ • Dig/DNS (SPF / Records)  │   │ • Scope Redirect Blocker   │
        └─────────────┬──────────────┘   └─────────────┬──────────────┘
                      └─────────────────┬──────────────┘
                                        ↓
                     ┌───────────────────────────────────────────┐
                     │         Machine Learning Layer            │
                     │                  ML.py                    │
                     │  • Multi-factor Deduplication Engine      │
                     │  • Scikit-Learn RandomForest Baseline     │
                     │  • PyTorch Deep Neural Classifier (MLP)   │
                     │  • False-Positive Scoring & Prioritization│
                     └──────────────────┬────────────────────────┘
                                        ↓
                     ┌───────────────────────────────────────────┐
                     │          Local AI Reasoning Core          │
                     │          Qwen3 (qwen3:latest)             │
                     │  • Threat Modeling & Business Impact      │
                     │  • Bug Bounty Submission Draft Generation │
                     │  • Prioritized Remediation Roadmap        │
                     └──────────────────┬────────────────────────┘
                                        ↓
                     ┌───────────────────────────────────────────┐
                     │         Reporting & Export Suite          │
                     │   report_generator.py & downloader.py     │
                     │  • Markdown (.md) - HackerOne Template    │
                     │  • Executive Cyber HTML (.html)           │
                     │  • Structured Machine JSON (.json)        │
                     └──────────────────┬────────────────────────┘
                                        ↓
                     ┌───────────────────────────────────────────┐
                     │     FastAPI + Cyber Dashboard (UI)        │
                     │          main.py & frontend.html          │
                     └───────────────────────────────────────────┘
```

---

## 📁 Project Directory Structure

```text
webscanner/
│
├── agent.py             # Autonomous bug-bounty agent connecting ML, AI Core & Kali tools
├── tools.py             # Kali Linux tool suite wrappers (Nmap, WhatWeb, SSLScan, Nikto, Dig)
├── main.py              # FastAPI backend server, REST endpoints & report downloaders
├── core.py              # Scope-aware scanning engine, rate controls & Qwen3 client
├── scope_manager.py     # Bug-bounty scope validator, wildcards & redirect safety
├── rate_limiter.py      # Centralized request scheduler & telemetry tracker
├── report_generator.py  # HackerOne Markdown, HTML, and JSON report generator
├── downloader.py        # Multi-format report export & streaming controller
├── ML.py                # Dual Scikit-Learn + PyTorch ML prioritization & deduplication
├── train.py             # Supervised training & evaluation metrics pipeline
├── tuner.py             # Hyperparameter grid tuning & checkpointing
├── lora.py              # Modular LoRA adapter management (Native + PEFT)
│
├── frontend.html        # Dark-theme cybersecurity dashboard
├── style.css            # Custom responsive CSS design system
├── run.sh               # One-click execution script for Kali Linux / macOS
├── run.bat              # One-click execution script for Windows
│
├── config/
│   ├── scope.json       # Program targets, exclusions, schemes & rate limits
│   ├── scanner.json     # Concurrency, timeouts, host caps & redaction flags
│   └── policies.json    # Policy profiles (Safe Passive, BB Standard, Local Lab)
│
├── logs/
│   ├── scanner.log      # Operational events, start/stop, status codes
│   ├── scope.log        # Scope audit decisions & blocked redirects
│   └── findings.log     # Observed findings & CWE audit trail
│
├── datasets/
│   ├── vulnerabilities.csv  # Standardized vulnerability catalog
│   ├── headers.csv          # Security headers definitions
│   ├── findings.csv         # False-positive calibration records
│   └── training.csv         # Tabular dataset for model training
│
├── models/
│   ├── baseline_rf.joblib   # Trained Random Forest classifier
│   ├── neural_mlp.pth       # Trained PyTorch neural network
│   ├── preprocessor.joblib  # Feature vector standardizer
│   └── metrics.json         # Accuracy, precision, recall & F1 scores
│
├── reports/                 # Generated JSON, Markdown, and HTML reports
├── requirements.txt         # Python dependencies
└── README.md                # Documentation & Kali Linux execution guide
```

---

## 🐧 Kali Linux VM Execution Guide (Step-by-Step)

Follow these exact steps to deploy and run AegisGuard inside your Kali Linux virtual machine:

### Step 1: Update Kali Linux & Install System Packages

Open a Kali terminal and install the native security tools and Python build dependencies:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y \
  python3 \
  python3-pip \
  python3-venv \
  git \
  curl \
  nmap \
  whatweb \
  sslscan \
  testssl.sh \
  nikto \
  dnsrecon \
  dnsutils
```

### Step 2: Set Up Python Virtual Environment

Navigate to the project root and create an isolated virtual environment:

```bash
cd /path/to/webscanner

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip and install all Python dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Install & Start Ollama with Qwen3 in Kali Linux

AegisGuard uses the local **`qwen3:latest`** model running on Ollama for autonomous reasoning and report generation:

1. **Install Ollama** in Kali:
   ```bash
   curl -fsSL https://ollama.com/install.sh | sh
   ```

2. **Start the Ollama daemon**:
   ```bash
   # Run in background or separate terminal:
   ollama serve
   ```

3. **Pull and test `qwen3:latest`**:
   ```bash
   ollama pull qwen3:latest
   ```

4. **Verify Ollama is responding**:
   ```bash
   curl http://localhost:11434/api/tags
   ```
   *(You should see `qwen3:latest` listed in the JSON response).*

### Step 4: Verify Kali Tool Integration & Capabilities

Run the tool capability audit to ensure all CLI utilities and fallbacks are ready:

```bash
python agent.py --check-tools
```

Output:
```text
🔍 Checking Kali Linux Tool Suite Status...
  • nmap       : ✅ AVAILABLE (Binary: nmap)
  • whatweb    : ✅ AVAILABLE (Binary: whatweb)
  • sslscan    : ✅ AVAILABLE (Binary: sslscan)
  • testssl    : ✅ AVAILABLE (Binary: testssl.sh)
  • nikto      : ✅ AVAILABLE (Binary: nikto)
  • dig        : ✅ AVAILABLE (Binary: dig)
```

> **Note:** If any tool binary is not installed, AegisGuard's `tools.py` will automatically switch to an equivalent pure-Python fallback (using native Python `socket`, `ssl`, and `requests` modules), preventing any crashes.

### Step 5: Train / Verify Machine Learning Models

Verify or retrain the vulnerability classifier models:

```bash
python train.py --epochs 40 --batch-size 16 --lr 0.005
```

This trains both the Scikit-Learn Random Forest and PyTorch Multi-Layer Perceptron (MLP) on the enriched dataset, outputting model artifacts to `models/` with **93%+ classification accuracy**.

---

## 🤖 Running the Autonomous Security Agent (`agent.py`)

The autonomous agent (`agent.py`) performs complete bug-bounty assessments autonomously without requiring browser interaction:

### Basic Scan:
```bash
python agent.py --url https://api.example.com
```

### Stealth Bug-Bounty Scan with Custom Rate Limit:
```bash
python agent.py --url https://api.example.com --profile "Bug Bounty Stealth" --rps 1.0
```

### Testing on Local Vulnerable Lab:
```bash
# In one terminal:
python3 -m http.server 8080

# In another terminal:
python agent.py --url http://127.0.0.1:8080 --profile "Local Lab"
```

### Agent Command-Line Flags:

| Flag | Description | Default |
| :--- | :--- | :--- |
| `--url <URL>` | Target website URL to assess (must be in scope) | *Required* |
| `--profile <NAME>` | Policy profile (`Bug Bounty Standard`, `Safe Passive`, `Local Lab`) | `Bug Bounty Standard` |
| `--rps <FLOAT>` | Maximum allowed requests per second | `2.0` |
| `--no-ml` | Disable ML prioritization and deduplication | `False` |
| `--no-ai` | Disable Qwen3 AI LLM reasoning synthesis | `False` |
| `--no-kali` | Disable Kali Linux CLI tools | `False` |
| `--check-tools` | Audit and display Kali tool availability | `False` |

---

## 🌐 Launching the Cybersecurity Web Dashboard (`main.py`)

Launch the web application using the provided shell script:

```bash
chmod +x run.sh
./run.sh
```

Or start directly with Python / Uvicorn:

```bash
python main.py
```

Then open your browser inside Kali Linux:
```text
http://127.0.0.1:8000
```

### Dashboard Features:
1. **Target Intake & Scope Strip**: Dynamically checks whether the target is in scope against `config/scope.json`.
2. **Authorization Gate**: Requires explicit acknowledgment of program testing boundaries before the assessment button unlocks.
3. **Engine Toggles**:
   - **Kali Agent Mode (`tools.py`)**: Executes the Kali tool suite alongside core probes.
   - **ML Prioritization**: Activates Scikit-Learn & PyTorch deduplication and scoring.
   - **Qwen3 Analysis**: Engages local Ollama Qwen3 reasoning for executive synthesis.
4. **Interactive Manual Verification Badges**: Highlights findings needing human review with benign reproduction steps.
5. **Multi-Format Export Menu**: Instant one-click download for Markdown (`.md`), HTML (`.html`), and JSON (`.json`).
6. **Live Compliance Logs**: Dedicated modal streaming `scanner.log`, `scope.log`, and `findings.log`.

---

## 🛡️ Bug-Bounty Scope Configuration (`config/scope.json`)

To configure targets for your specific bug-bounty program, edit `config/scope.json`:

```json
{
  "program": "Authorized Bug Bounty Assessment",
  "authorized": true,
  "targets": [
    "*.example.com",
    "api.example.com",
    "testphp.vulnweb.com",
    "localhost",
    "127.0.0.1"
  ],
  "excluded_targets": [
    "admin.example.com",
    "payment.example.com"
  ],
  "allowed_schemes": [
    "https",
    "http"
  ],
  "max_requests_per_second": 2.0,
  "automated_scanning_allowed": true,
  "program_rules_acknowledged": true
}
```

### Safeguards Enforced:
- **Wildcard Subdomain Matching**: `*.example.com` permits `api.example.com` and `web.example.com`.
- **Exclusion Precedence**: Excluded targets (e.g. `admin.example.com`) are dropped immediately before any network traffic is sent.
- **Out-of-Scope Redirect Interception**: If an in-scope site redirects to a third party (e.g., `https://accounts.google.com`), the redirect is aborted and logged as `[OUT-OF-SCOPE REDIRECT BLOCKED]`.
- **Credential & Secret Redaction**: All captured headers, session cookies, and authentication tokens are automatically redacted as `[REDACTED]`.

---

## 🔧 Kali Linux Tools Suite Reference (`tools.py`)

AegisGuard incorporates native Kali Linux command-line utilities configured strictly with **safe, non-destructive, non-DoS** parameters:

| Tool | CLI Command Used | Defensive Purpose | Fallback / Integration Behavior |
| :--- | :--- | :--- | :--- |
| **Nmap** | `nmap -sV -Pn --version-light -p 80,443,8080,8443` | Identifies web ports and service version banners without intrusive scripts | Pure-Python socket TCP connection & HTTP banner grab |
| **WhatWeb** | `whatweb --colour=never --no-errors -a 1` | Stealthy passive fingerprinting of CMS, frameworks, and web stacks | Inspects `Server`, `X-Powered-By`, and HTML meta tags |
| **SSLScan** | `sslscan --no-colour --tlsall` | Audits SSL/TLS protocols for deprecated versions (SSLv3, TLS 1.0, 1.1) | Python `ssl` library handshake & cipher inspection |
| **Nikto** | `nikto -h <URL> -Tuning 1,2,b -nointeractive` | Checks for server info leakage, missing headers, and obsolete files | Probes `/robots.txt` and `/.well-known/security.txt` |
| **Dig / DNS**| `dig +noall +answer <host> ANY` | Validates DNS records and audits email security (missing SPF/DMARC) | Python `socket.gethostbyname_ex` resolution |
| **Metasploit** | `msfconsole -q` (Manual Launch Only) | Interactive terminal workspace for the authorized researcher | Scope guard enforced; NEVER automated; no exploit execution |
| **Burp Suite** | `burpsuite` (Manual Interception) | Local HTTP proxy & traffic analysis tool for the researcher | Scope export (`/api/tools/burp/scope`); proxy routing (`127.0.0.1:8080`) |

### ⚡ Manual Security Tool Integrations (Metasploit & Burp Suite)

1. **Metasploit Framework (`msfconsole`)**:
   - **Manual-Only Invocation**: Kept strictly separate from the automated scanner and autonomous agent.
   - **Target Scope Guard**: Before launching, verifies the target is in `config/scope.json`. Out-of-scope targets are blocked.
   - **Safe Target Context**: Sets only the global target variable (`setg RHOSTS <host>`) in an interactive terminal session for the researcher; **never** automatically selects or executes exploits, payloads, credential attacks, or persistence.
   - **Audit Trail**: Every launch is timestamped and logged in `logs/scanner.log`.

2. **Burp Suite (`burpsuite`)**:
   - **Local Launch**: Spawns Burp Suite directly from the web dashboard for authorized traffic interception.
   - **Target Scope Export**: Click **Export Burp Scope JSON** in the dashboard to generate a Burp-compatible `burp_target_scope.json` rule file matching your authorized program scope and exclusions.
   - **Proxy Routing**: Click **Route via Proxy (127.0.0.1:8080)** to route AegisGuard scanner requests through Burp Suite's local interception proxy.
   - **Findings Ingestion**: Exported Burp Suite findings can be ingested via `/api/tools/burp/import` into AegisGuard's normalized reports.

## 📄 Platform-Ready Report Formats

Generated reports are saved in `reports/` and exportable in three formats:

1. **Markdown (`.md`)**:
   - Styled directly for submission to **HackerOne** and **Bugcrowd**.
   - Includes: Affected Asset, CWE, CVSS Base Score, Verification Status, Technical Description, Redacted Evidence, Non-Destructive Reproduction Steps, and Remediation.
2. **HTML (`.html`)**:
   - Executive presentation report featuring the dark cybersecurity design system, severity breakdown cards, and visual code evidence blocks.
3. **JSON (`.json`)**:
   - Standardized audit payload for integration into SIEMs, defect trackers, or automated DevSecOps pipelines.

---

## ❓ Troubleshooting in Kali Linux

### 1. `Ollama connection refused (http://localhost:11434)`
Ensure the Ollama service is running in your Kali VM:
```bash
ollama serve &
# Test with:
curl http://localhost:11434/api/tags
```

### 2. `Nmap requires root or raw socket access`
AegisGuard runs non-privileged TCP connect scans (`-sV -Pn`), which run smoothly without `sudo`. If required:
```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

### 3. `LibreSSL / urllib3 Warning`
If Kali outputs a LibreSSL notice from `urllib3`:
```bash
pip install "urllib3<2.0.0"
```

---

## ⚖️ Legal & Ethical Use

AegisGuard is intended **strictly for authorized bug-bounty engagements, contracted security assessments, and academic research on systems you own or have explicit written permission to evaluate**. Unauthorized scanning without prior authorization violates computer misuse laws and bug-bounty program terms of service.
