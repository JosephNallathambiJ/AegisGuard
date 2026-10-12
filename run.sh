#!/usr/bin/env bash
# ==============================================================================
# run.sh - AegisGuard One-Click Launcher for Kali Linux / macOS
# ==============================================================================

set -e

echo "====================================================================="
echo "   AegisGuard - Bug Bounty Web Security Assessment Platform"
echo "   Non-Destructive Reconnaissance & Rate-Limited Vulnerability Audit"
echo "====================================================================="
echo ""

# 1. Check Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is required. Run: sudo apt install python3 python3-venv"
    exit 1
fi

echo "[*] Python version: $(python3 --version)"

# 2. Virtual Environment
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment in ./venv ..."
    python3 -m venv venv
fi

echo "[*] Activating virtual environment..."
source venv/bin/activate

# 3. Dependencies
echo "[*] Checking dependencies..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

# 4. Check ML Models
if [ ! -f "models/baseline_model.joblib" ]; then
    echo "[*] Initializing ML classification baseline models..."
    python train.py --epochs 25 --batch-size 16
    echo "[✓] Initial models created in ./models/"
fi

# 5. Check Ollama / Qwen3
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "[✓] Local Ollama service detected. Qwen3 analysis assistant online."
else
    echo "[!] Note: Ollama service is not currently running on port 11434."
    echo "    Scanner will use built-in deterministic heuristic analysis."
    echo "    To enable Qwen3, open another terminal and run: ollama run qwen3:latest"
fi

# 6. Launch Server
echo ""
echo "====================================================================="
echo " [+] Launching AegisGuard Dashboard on: http://127.0.0.1:8000"
echo " [+] Press CTRL+C to stop the server."
echo "====================================================================="
echo ""

python main.py
