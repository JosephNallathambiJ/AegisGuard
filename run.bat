@echo off
setlocal enabledelayedexpansion

title AegisGuard - Bug Bounty Security Assessment Platform
color 0B

echo =====================================================================
echo    AegisGuard - Bug Bounty Web Security Assessment Platform
echo    Non-Destructive Reconnaissance & Rate-Limited Vulnerability Audit
echo =====================================================================
echo.

:: 1. Verify Python Installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo [ERROR] Python 3 is not found in your system PATH.
    echo Please install Python 3.9+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo [*] Python detected:
python --version

:: 2. Setup Virtual Environment
if not exist "venv\" (
    echo [*] Creating Python virtual environment in .\venv ...
    python -m venv venv
    if %errorlevel% neq 0 (
        color 0C
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
)

echo [*] Activating virtual environment...
call venv\Scripts\activate.bat

:: 3. Install / Verify Dependencies
echo [*] Checking dependencies...
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
if %errorlevel% neq 0 (
    echo [!] Warning: Some dependencies could not be installed automatically.
    echo Continuing to launch server with available components...
)

:: 4. Check ML Models (Train if missing)
if not exist "models\baseline_model.joblib" (
    echo [*] Training initial ML classification baseline models...
    python train.py --epochs 25 --batch-size 16
    echo [✓] Initial models created in .\models\
)

:: 5. Check Local Ollama / Qwen3 Status
curl -s http://localhost:11434/api/tags >nul 2>&1
if %errorlevel% equ 0 (
    echo [✓] Local Ollama service detected. Qwen3 analysis assistant online.
) else (
    echo [!] Note: Ollama service is not currently running on port 11434.
    echo     Scanner will use built-in deterministic heuristic analysis.
    echo     To enable Qwen3, open another terminal and run: ollama run qwen3:latest
)

:: 6. Launch Browser and Server
echo.
echo =====================================================================
echo  [+] Launching AegisGuard Dashboard on: http://127.0.0.1:8000
echo  [+] Press CTRL+C to stop the scanner server.
echo =====================================================================
echo.

:: Automatically open browser after 2 seconds in background
start "" cmd /c "timeout /t 2 >nul & start http://127.0.0.1:8000"

:: Start FastAPI application
python main.py

if %errorlevel% neq 0 (
    color 0C
    echo.
    echo [ERROR] AegisGuard server terminated unexpectedly.
    pause
)
