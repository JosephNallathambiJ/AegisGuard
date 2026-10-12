"""
agent.py - Autonomous Bug-Bounty Security Assessment Agent for AegisGuard
Connects Machine Learning classification (ML.py), Local AI Reasoning (Qwen3 on Ollama via core.py),
and Kali Linux reconnaissance capabilities (tools.py) into an autonomous, non-destructive agent.
"""

import os
import sys
import json
import uuid
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from scope_manager import ScopeManager
from rate_limiter import RateLimiter
from core import execute_security_scan, QwenAnalysisEngine, log_audit_event
from ML import VulnerabilityMLPipeline
from tools import KaliToolRunner, KaliToolRegistry
from report_generator import BugBountyReportGenerator, sanitize_for_json
from downloader import ReportDownloader


class AegisSecurityAgent:
    """
    Autonomous Defensive Security Agent.
    Orchestrates target scope verification, AI-driven scan planning,
    Kali Linux tool execution, ML prioritization, and Qwen3 report synthesis.
    """

    def __init__(self, reports_dir: str = "reports", models_dir: str = "models"):
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)
        
        self.scope_mgr = ScopeManager()
        self.rate_limiter = RateLimiter(requests_per_second=2.0)
        self.ml_pipeline = VulnerabilityMLPipeline(models_dir=models_dir)
        self.qwen_engine = QwenAnalysisEngine()
        self.tool_runner = KaliToolRunner(scope_manager=self.scope_mgr)
        self.downloader = ReportDownloader(reports_dir=reports_dir)

    def plan_assessment(self, target_url: str, policy_profile: str) -> Dict[str, Any]:
        """
        Agentic Planning Step:
        Analyzes target structure and generates an optimal non-destructive execution plan.
        """
        parsed_target = target_url.lower()
        is_https = parsed_target.startswith("https://")
        
        selected_tools = ["core_http_probes"]
        selected_tools.append("whatweb")
        selected_tools.append("dns_recon")
        selected_tools.append("nmap_services")
        if is_https:
            selected_tools.append("ssl_cipher_audit")
        selected_tools.append("nikto_misconfig")

        rationale = [
            f"Target scheme: {'HTTPS (TLS audit required)' if is_https else 'HTTP (Unencrypted transport)'}",
            "Scope check verified via ScopeManager policies.",
            "Enforcing non-destructive banner, header, and configuration audits only."
        ]

        return {
            "target_url": target_url,
            "policy_profile": policy_profile,
            "planned_tools": selected_tools,
            "planning_rationale": rationale,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def run_autonomous_assessment(
        self,
        target_url: str,
        policy_profile: str = "Bug Bounty Standard",
        enable_ml: bool = True,
        enable_ai: bool = True,
        enable_kali_tools: bool = True,
        custom_rps: Optional[float] = None,
        verbose: bool = True
    ) -> Dict[str, Any]:
        """
        Executes the end-to-end agentic workflow:
        1. Scope & Authorization Validation
        2. Agentic Scan Planning
        3. Core Probes + Kali Linux Reconnaissance
        4. ML Deduplication & Priority Scoring
        5. Qwen3 Reasoning & Bug-Bounty Synthesis
        6. Multiformat Artifact Generation
        """
        scan_id = f"bb-agent-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        start_time = datetime.now(timezone.utc)

        if verbose:
            print("\n" + "="*68)
            print(f"🤖 [AegisGuard Agent] Launching Autonomous Assessment: {target_url}")
            print(f"🆔 Scan ID: {scan_id} | Profile: {policy_profile}")
            print("="*68)

        # ----------------------------------------------------------------------
        # Step 1: Pre-flight Scope Verification
        # ----------------------------------------------------------------------
        if verbose:
            print("\n[Step 1/6] 🛡️  Verifying Target Scope & Boundaries...")

        if not self.scope_mgr.is_in_scope(target_url):
            err_msg = f"Target URL '{target_url}' is OUT OF SCOPE according to config/scope.json policies."
            log_audit_event("agent_scope_blocked", {"url": target_url, "reason": err_msg})
            if verbose:
                print(f"❌ ABORTED: {err_msg}")
            return {
                "scan_id": scan_id,
                "target_url": target_url,
                "success": False,
                "error": err_msg
            }

        # Configure rate limiter
        if custom_rps is not None:
            self.rate_limiter.requests_per_second = max(0.1, float(custom_rps))
            self.rate_limiter.min_interval = 1.0 / self.rate_limiter.requests_per_second

        # ----------------------------------------------------------------------
        # Step 2: Agentic Planning
        # ----------------------------------------------------------------------
        if verbose:
            print("[Step 2/6] 📋 Formulating Autonomous Security Plan...")
        plan = self.plan_assessment(target_url, policy_profile)
        if verbose:
            print(f"  • Tools Planned: {', '.join(plan['planned_tools'])}")

        # ----------------------------------------------------------------------
        # Step 3: Core Probing + Kali Linux Tool Execution
        # ----------------------------------------------------------------------
        if verbose:
            print("[Step 3/6] ⚙️  Executing Probes & Kali Linux Reconnaissance Tools...")

        # 3a. Core HTTP / TLS / OWASP Probes
        if verbose:
            print("  • Dispatching safe OWASP HTTP security probes (Headers, Cookies, CORS, Methods)...")
        core_result = execute_security_scan(
            target_url=target_url,
            policy_profile=policy_profile,
            scope_manager=self.scope_mgr,
            rate_limiter=self.rate_limiter
        )

        all_findings: List[Dict[str, Any]] = list(core_result.get("findings", []))
        tool_execution_details: Dict[str, Any] = {}

        # 3b. Kali Linux Tools
        if enable_kali_tools:
            if verbose:
                print("  • Deploying Kali Linux tools (Nmap, WhatWeb, SSLScan, Nikto, DNS)...")
            kali_results = self.tool_runner.run_all_tools(target_url)
            tool_findings = kali_results.get("findings", [])
            tool_execution_details = kali_results.get("tool_details", {})
            all_findings.extend(tool_findings)
            if verbose:
                print(f"  • Kali Tool Suite completed ({len(tool_findings)} findings identified).")

        # ----------------------------------------------------------------------
        # Step 4: Machine Learning Deduplication & Prioritization (ML.py)
        # ----------------------------------------------------------------------
        if verbose:
            print("[Step 4/6] 🧠 Applying ML Layer (Deduplication, CVSS adjustments & Triage Scoring)...")

        if enable_ml and self.ml_pipeline.is_trained():
            enriched_findings = self.ml_pipeline.enrich_findings(all_findings)
        else:
            enriched_findings = self.ml_pipeline.detect_duplicates(all_findings)

        # Compute summary counts
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in enriched_findings:
            sev = f.get("severity", "Informational")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        if verbose:
            print(f"  • Findings Breakdown: Critical={severity_counts['Critical']} | "
                  f"High={severity_counts['High']} | Medium={severity_counts['Medium']} | "
                  f"Low={severity_counts['Low']} | Info={severity_counts['Informational']}")

        # ----------------------------------------------------------------------
        # Step 5: Qwen3 AI Reasoning Core Synthesis
        # ----------------------------------------------------------------------
        ai_synthesis = None
        if enable_ai:
            if verbose:
                print("[Step 5/6] 🤖 Consulting Qwen3 AI Reasoning Core (Ollama local inference)...")
            ai_synthesis = self.qwen_engine.generate_findings_analysis(target_url, enriched_findings)
            if verbose:
                eng = ai_synthesis.get("llm_engine_used", "AI Core")
                print(f"  • AI Synthesis generated via: {eng}")

        # ----------------------------------------------------------------------
        # Step 6: Artifact Creation & Multi-Format Reporting
        # ----------------------------------------------------------------------
        if verbose:
            print("[Step 6/6] 📄 Generating HackerOne Bug-Bounty Artifacts & Reports...")

        duration = round((datetime.now(timezone.utc) - start_time).total_seconds(), 2)

        report_payload = {
            "scan_id": scan_id,
            "target_url": target_url,
            "policy_profile": policy_profile,
            "timestamp": start_time.isoformat(),
            "duration_seconds": duration,
            "status_code": core_result.get("status_code", 200),
            "blocked_redirects_count": core_result.get("blocked_redirects_count", 0),
            "scheduler_telemetry": core_result.get("scheduler_telemetry", {}),
            "metadata": core_result.get("metadata", {}),
            "severity_summary": severity_counts,
            "total_findings": len(enriched_findings),
            "ml_enhanced": enable_ml,
            "agent_plan": plan,
            "kali_tools_telemetry": tool_execution_details,
            "llm_analysis": ai_synthesis,
            "findings": enriched_findings
        }

        # Sanitize any numpy scalars and save JSON
        report_payload = sanitize_for_json(report_payload)
        json_file_path = os.path.join(self.reports_dir, f"{scan_id}.json")
        with open(json_file_path, "w", encoding="utf-8") as f:
            json.dump(report_payload, f, indent=2)

        # Export Markdown & HTML
        gen = BugBountyReportGenerator(report_payload)
        md_content = gen.to_markdown()
        md_file_path = os.path.join(self.reports_dir, f"{scan_id}.md")
        with open(md_file_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        html_content = gen.to_html()
        html_file_path = os.path.join(self.reports_dir, f"{scan_id}.html")
        with open(html_file_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        if verbose:
            print("\n" + "="*68)
            print("✅ ASSESSMENT COMPLETE!")
            print(f"📊 Total Findings: {len(enriched_findings)}")
            print(f"📁 JSON Report : {json_file_path}")
            print(f"📝 Markdown    : {md_file_path}")
            print(f"🌐 HTML Report : {html_file_path}")
            print("="*68 + "\n")

        return report_payload


# ==============================================================================
# CLI Entrypoint
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(
        description="AegisGuard Autonomous Bug-Bounty Security Assessment Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py --url https://example.com
  python agent.py --url https://example.com --profile "Bug Bounty Stealth" --rps 1.0
  python agent.py --check-tools
        """
    )
    parser.add_argument("--url", type=str, help="Authorized target website URL to assess")
    parser.add_argument("--profile", type=str, default="Bug Bounty Standard", help="Security policy profile")
    parser.add_argument("--rps", type=float, default=2.0, help="Custom rate limit (requests per second)")
    parser.add_argument("--no-ml", action="store_true", help="Disable ML prioritization and deduplication")
    parser.add_argument("--no-ai", action="store_true", help="Disable Qwen3 AI LLM reasoning")
    parser.add_argument("--no-kali", action="store_true", help="Disable Kali Linux CLI tools")
    parser.add_argument("--check-tools", action="store_true", help="Check status of Kali Linux reconnaissance tools")

    args = parser.parse_args()

    if args.check_tools:
        print("\n🔍 Checking Kali Linux Tool Suite Status...")
        caps = KaliToolRegistry.check_capabilities()
        for tool, info in caps.items():
            status = "✅ AVAILABLE" if info["available"] else "⚠️ MISSING (Pure-Python Fallback Active)"
            print(f"  • {tool:10s} : {status} (Binary: {info['binary']})")
        print()
        sys.exit(0)

    if not args.url:
        parser.print_help()
        print("\n❌ Error: Please provide a target URL using --url <URL>")
        sys.exit(1)

    agent = AegisSecurityAgent()
    agent.run_autonomous_assessment(
        target_url=args.url,
        policy_profile=args.profile,
        enable_ml=not args.no_ml,
        enable_ai=not args.no_ai,
        enable_kali_tools=not args.no_kali,
        custom_rps=args.rps,
        verbose=True
    )


if __name__ == "__main__":
    main()
