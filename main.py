"""
main.py - AegisGuard Bug-Bounty Security Assessment Server
FastAPI application enforcing program scope boundaries, rate limits,
SSRF defenses, ML prioritization, and professional multi-format reporting.
"""

import os
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from scope_manager import ScopeManager
from rate_limiter import RateLimiter
from core import execute_security_scan, QwenAnalysisEngine, log_audit_event
from ML import VulnerabilityMLPipeline
from downloader import ReportDownloader

app = FastAPI(
    title="AegisGuard Bug Bounty Security Assessment Platform",
    description="Authorized, scope-aware, and rate-limited non-destructive web security assessment engine.",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Core engine singletons
scope_mgr = ScopeManager()
rate_limiter = RateLimiter(requests_per_second=2.0)
ml_pipeline = VulnerabilityMLPipeline(models_dir="models")
qwen_engine = QwenAnalysisEngine()
downloader = ReportDownloader(reports_dir="reports")

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


class ScanRequest(BaseModel):
    url: str = Field(..., description="Target URL")
    program_rules_acknowledged: bool = Field(..., description="Explicit acknowledgement of program rules and authorization")
    policy_profile: str = Field("Bug Bounty Standard", description="Selectable policy profile")
    enable_ml: bool = Field(True, description="Enable ML prioritization and false-positive filtering")
    enable_llm: bool = Field(True, description="Enable local Qwen3 finding analysis assistant")
    custom_rps: Optional[float] = Field(None, description="Optional custom rate limit")


class ScopeUpdateRequest(BaseModel):
    program: str
    authorized: bool
    targets: List[str]
    excluded_targets: List[str]
    allowed_schemes: List[str] = ["https", "http"]
    max_requests_per_second: float = 2.0
    automated_scanning_allowed: bool = True
    program_rules_acknowledged: bool = True


# ==============================================================================
# UI Routes
# ==============================================================================

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serves the dashboard HTML."""
    if not os.path.exists("frontend.html"):
        raise HTTPException(status_code=404, detail="frontend.html not found.")
    with open("frontend.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/style.css")
async def serve_style():
    """Serves styling CSS."""
    if not os.path.exists("style.css"):
        raise HTTPException(status_code=404, detail="style.css not found.")
    return FileResponse("style.css", media_type="text/css")


# ==============================================================================
# Scope & Policy APIs
# ==============================================================================

@app.get("/api/scope")
async def get_scope():
    """Returns current active bug bounty program scope configuration."""
    return scope_mgr.get_scope_config()


@app.post("/api/scope")
async def update_scope(req: ScopeUpdateRequest):
    """Updates bug bounty scope targets and restrictions."""
    updated = scope_mgr.update_scope_config(req.model_dump())
    if not updated:
        raise HTTPException(status_code=500, detail="Failed to save scope configuration.")
    return {"status": "success", "scope": scope_mgr.get_scope_config()}


@app.get("/api/policies")
async def get_policies():
    """Returns available assessment policy profiles."""
    return {
        "profiles": scope_mgr.get_policies(),
        "default": "Bug Bounty Standard"
    }


@app.get("/api/status")
async def get_system_status():
    """Returns scanner health, active scope, and ML/LLM model readiness."""
    return {
        "status": "ready",
        "program": scope_mgr.get_scope_config().get("program", "Authorized Assessment"),
        "ml_models_loaded": ml_pipeline.is_trained(),
        "baseline_model_available": ml_pipeline.baseline_model is not None,
        "neural_model_available": ml_pipeline.neural_model is not None,
        "qwen_llm_available": qwen_engine.is_available(),
        "qwen_model_name": qwen_engine.model_name,
        "rate_limit_rps": rate_limiter.requests_per_second
    }


# ==============================================================================
# Scan Execution Pipeline
# ==============================================================================

@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    """
    Executes the comprehensive bug-bounty assessment pipeline:
    1. Scope & exclusion validation
    2. Program rule acknowledgment
    3. Hostname normalization & SSRF protection
    4. Rate-limited non-destructive scanning
    5. ML prioritization & false-positive scoring
    6. Qwen3 remediation assistant synthesis
    7. Professional audit report generation
    """
    if not req.program_rules_acknowledged:
        raise HTTPException(
            status_code=400,
            detail="Program rules and authorization must be explicitly acknowledged."
        )

    # Set rate limit if specified
    if req.custom_rps is not None:
        rate_limiter.requests_per_second = max(0.1, float(req.custom_rps))
        rate_limiter.min_interval = 1.0 / rate_limiter.requests_per_second

    # Execute scope-aware, rate-limited scan
    scan_result = execute_security_scan(
        target_url=req.url,
        policy_profile=req.policy_profile,
        scope_manager=scope_mgr,
        rate_limiter=rate_limiter
    )

    if not scan_result.get("success"):
        raise HTTPException(status_code=400, detail=scan_result.get("error", "Scan execution halted."))

    raw_findings = scan_result.get("findings", [])

    # Apply ML layer (Prioritization, Deduplication, False-Positive scoring)
    if req.enable_ml:
        enriched_findings = ml_pipeline.enrich_findings(raw_findings)
    else:
        enriched_findings = raw_findings

    # Severity distribution
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in enriched_findings:
        sev = f.get("severity", "Informational")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Qwen3 Assistant Synthesis
    llm_synthesis = None
    if req.enable_llm:
        llm_synthesis = qwen_engine.generate_findings_analysis(scan_result["target_url"], enriched_findings)

    # Build report
    scan_id = f"bb-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
    report = {
        "scan_id": scan_id,
        "target_url": scan_result["target_url"],
        "policy_profile": req.policy_profile,
        "timestamp": scan_result["scan_timestamp"],
        "duration_seconds": scan_result["scan_duration_seconds"],
        "status_code": scan_result["status_code"],
        "blocked_redirects_count": scan_result.get("blocked_redirects_count", 0),
        "scheduler_telemetry": scan_result.get("scheduler_telemetry", {}),
        "metadata": scan_result["metadata"],
        "severity_summary": severity_counts,
        "total_findings": len(enriched_findings),
        "ml_enhanced": req.enable_ml,
        "llm_analysis": llm_synthesis,
        "findings": enriched_findings
    }

    # Sanitize data for JSON (convert numpy types & non-str keys)
    from report_generator import sanitize_for_json
    report = sanitize_for_json(report)

    # Persist report JSON
    report_file_path = os.path.join(REPORTS_DIR, f"{scan_id}.json")
    with open(report_file_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    return report


# ==============================================================================
# Autonomous Security Agent Endpoints (tools.py & agent.py)
# ==============================================================================

@app.get("/api/agent/tools")
async def get_agent_tools_status():
    """Returns availability and version info for Kali Linux tools."""
    from tools import KaliToolRegistry
    return {"tools": KaliToolRegistry.check_capabilities()}


@app.post("/api/agent/scan")
async def trigger_agent_scan(req: ScanRequest):
    """Executes a full autonomous security assessment via AegisSecurityAgent."""
    if not req.program_rules_acknowledged:
        raise HTTPException(
            status_code=400,
            detail="Program rules and authorization must be explicitly acknowledged."
        )
    from agent import AegisSecurityAgent
    agent = AegisSecurityAgent(reports_dir=REPORTS_DIR, models_dir="models")
    result = agent.run_autonomous_assessment(
        target_url=req.url,
        policy_profile=req.policy_profile,
        enable_ml=req.enable_ml,
        enable_ai=req.enable_llm,
        enable_kali_tools=True,
        custom_rps=req.custom_rps,
        verbose=False
    )
    if not result.get("success", True):
        raise HTTPException(status_code=400, detail=result.get("error", "Agent assessment halted."))
    return result


# ==============================================================================
# Metasploit & Burp Suite Manual Testing Integrations (tools.py)
# ==============================================================================

class MetasploitLaunchRequest(BaseModel):
    url: Optional[str] = Field(None, description="Optional explicitly selected in-scope target URL")


class ProxyConfigRequest(BaseModel):
    host: str = Field("127.0.0.1", description="Local proxy IP")
    port: int = Field(8080, description="Local proxy port")
    enabled: bool = Field(True, description="Enable local proxy routing")


@app.post("/api/tools/metasploit/launch")
async def launch_metasploit_endpoint(req: MetasploitLaunchRequest):
    """
    Launches msfconsole in an interactive terminal window for the authorized researcher.
    Strictly verifies that any passed target is within program scope.
    Never executes automated exploits or payloads.
    """
    from tools import KaliToolRunner
    runner = KaliToolRunner(scope_manager=scope_mgr)
    result = runner.launch_metasploit_console(target_url=req.url)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Could not launch Metasploit console."))
    return result


@app.post("/api/tools/burp/launch")
async def launch_burp_endpoint():
    """
    Launches Burp Suite locally for the authorized researcher to perform manual interception.
    """
    from tools import KaliToolRunner
    runner = KaliToolRunner(scope_manager=scope_mgr)
    result = runner.launch_burp_suite()
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Could not launch Burp Suite."))
    return result


@app.get("/api/tools/burp/scope")
async def get_burp_scope_endpoint():
    """
    Generates a Burp Suite-compatible Target Scope JSON configuration based on config/scope.json.
    """
    from tools import KaliToolRunner
    runner = KaliToolRunner(scope_manager=scope_mgr)
    return runner.get_burp_suite_scope_config()


@app.post("/api/tools/proxy/configure")
async def configure_proxy_endpoint(req: ProxyConfigRequest):
    """
    Configures local proxy settings (such as Burp Suite on 127.0.0.1:8080).
    """
    from tools import KaliToolRunner
    runner = KaliToolRunner(scope_manager=scope_mgr)
    result = runner.configure_proxy(proxy_host=req.host, proxy_port=req.port, enabled=req.enabled)
    return result


@app.post("/api/tools/burp/import")
async def import_burp_findings_endpoint(issues: List[Dict[str, Any]]):
    """
    Imports and normalizes findings exported from Burp Suite.
    """
    from tools import KaliToolRunner
    runner = KaliToolRunner(scope_manager=scope_mgr)
    normalized = runner.import_burp_findings(issues)
    return {"imported_count": len(normalized), "findings": normalized}


# ==============================================================================
# Reporting & Multi-Format Downloader Endpoints
# ==============================================================================

@app.get("/api/reports/{scan_id}")
async def get_report(scan_id: str):
    """Retrieves an existing audit report by ID."""
    report_path = os.path.join(REPORTS_DIR, f"{scan_id}.json")
    if not os.path.exists(report_path):
        raise HTTPException(status_code=404, detail="Report not found.")
    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)


@app.get("/api/reports/{scan_id}/download")
async def download_report_endpoint(
    scan_id: str,
    format: str = Query("json", pattern="^(json|markdown|md|html)$", description="Report format: json, markdown, html")
):
    """
    Downloads the audit report in JSON, Markdown (bug-bounty template), or HTML format.
    Powered by report_generator.py and downloader.py.
    """
    file_path, media_type, filename = downloader.export_report(scan_id, export_format=format)
    if not file_path or not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Could not generate export for specified report ID.")

    return FileResponse(
        file_path,
        media_type=media_type,
        filename=filename
    )


@app.get("/api/logs/{log_type}")
async def get_logs(log_type: str):
    """Streams the tail of audit and scope verification logs."""
    log_map = {
        "scanner": "logs/scanner.log",
        "scope": "logs/scope.log",
        "findings": "logs/findings.log"
    }
    path = log_map.get(log_type)
    if not path or not os.path.exists(path):
        return {"lines": ["Log file empty or not initialized."]}

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    return {"lines": [l.strip() for l in lines[-40:]]}


@app.get("/api/history")
async def get_scan_history():
    """Lists recent bug-bounty scan reports."""
    history = []
    if os.path.exists(REPORTS_DIR):
        files = sorted(os.listdir(REPORTS_DIR), reverse=True)
        for fname in files:
            if fname.endswith(".json") and fname.startswith("bb-") or fname.startswith("audit-"):
                fpath = os.path.join(REPORTS_DIR, fname)
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        history.append({
                            "scan_id": data.get("scan_id"),
                            "target_url": data.get("target_url"),
                            "policy_profile": data.get("policy_profile", "Standard"),
                            "timestamp": data.get("timestamp"),
                            "total_findings": data.get("total_findings", 0),
                            "severity_summary": data.get("severity_summary", {})
                        })
                except Exception:
                    pass
    return {"scans": history[:25]}


if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*65)
    print("🛡️  AegisGuard Bug Bounty Security Assessment Platform")
    print("🌐  Dashboard running at: http://127.0.0.1:8000")
    print("="*65 + "\n")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
