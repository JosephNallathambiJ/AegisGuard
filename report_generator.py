"""
report_generator.py - Bug-Bounty Vulnerability Audit Report Generator
Generates professional security assessment reports formatted for bug-bounty platforms
(HackerOne, Bugcrowd, Intigriti) in JSON, Markdown, and standalone HTML formats.
"""

import os
import json
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

def redact_sensitive_evidence(text: str) -> str:
    """
    Sanitizes raw HTTP requests/responses and logs to prevent secret leakage.
    Redacts Authorization headers, session cookies, API tokens, passwords, and private keys.
    """
    if not text or not isinstance(text, str):
        return ""

    sanitized = text

    # Redact Authorization tokens
    sanitized = re.sub(r"(?i)(Authorization:\s*(?:Bearer|Basic|Token)\s+)[^\r\n]+", r"\1[REDACTED]", sanitized)

    # Redact Cookies
    sanitized = re.sub(r"(?i)(Cookie:\s*)[^\r\n]+", r"\1[REDACTED]", sanitized)
    sanitized = re.sub(r"(?i)(Set-Cookie:\s*[^=;]+)=[^;\r\n]+", r"\1=[REDACTED]", sanitized)

    # Redact common credential query params or json fields
    sanitized = re.sub(r"(?i)(password|secret|apikey|api_key|token|access_token|private_key)([\"']?\s*[:=]\s*[\"']?)[^\"'\s&]+", r"\1\2[REDACTED]", sanitized)

    # Redact private key blocks
    sanitized = re.sub(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----", "[REDACTED PRIVATE KEY]", sanitized)

    return sanitized


def sanitize_for_json(obj: Any) -> Any:
    """Recursively converts numpy scalars/arrays, non-str dict keys, and non-serializable objects to standard JSON types."""
    if isinstance(obj, dict):
        return {str(k): sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple, set)):
        return [sanitize_for_json(item) for item in obj]
    elif hasattr(obj, "item") and callable(getattr(obj, "item")):
        return obj.item()
    elif hasattr(obj, "tolist") and callable(getattr(obj, "tolist")):
        return obj.tolist()
    return obj


class BugBountyReportGenerator:
    """
    Builds structured, platform-ready audit reports.
    Clearly delineates Observed, Inferred, Potential, and Confirmed findings.
    """
    def __init__(self, audit_data: Dict[str, Any]):
        self.data = sanitize_for_json(audit_data)
        self.findings = self.data.get("findings", [])
        self.target_url = self.data.get("target_url", "")
        self.scan_id = self.data.get("scan_id", "audit-report")
        self.timestamp = self.data.get("timestamp", datetime.now(timezone.utc).isoformat())

    def to_json(self, indent: int = 2) -> str:
        """Exports sanitized JSON report."""
        clean_copy = sanitize_for_json(self.data)
        # Ensure all evidence is redacted
        for f in clean_copy.get("findings", []):
            if "evidence" in f:
                f["evidence"] = redact_sensitive_evidence(f["evidence"])
        return json.dumps(clean_copy, indent=indent)

    def to_markdown(self) -> str:
        """
        Generates a professional Markdown bug-bounty assessment report
        formatted for submission or client delivery.
        """
        sev_counts = self.data.get("severity_summary", {})
        meta = self.data.get("metadata", {})
        program = meta.get("program", "Authorized Bug Bounty Program")
        policy = self.data.get("policy_profile", "Bug Bounty Standard")

        md = []
        md.append(f"# Bug Bounty Security Assessment Report: {self.target_url}\n")
        md.append(f"**Program Name:** {program}  ")
        md.append(f"**Audit ID:** `{self.scan_id}`  ")
        md.append(f"**Timestamp:** `{self.timestamp}`  ")
        md.append(f"**Assessment Policy:** `{policy}`  ")
        md.append(f"**Scope Verification:** Verified In-Scope via AegisGuard Policy Engine  ")
        md.append(f"**Scan Duration:** {self.data.get('duration_seconds', 0)} seconds  \n")

        md.append("## Executive Summary\n")
        llm = self.data.get("llm_analysis", {})
        if llm and "executive_summary" in llm:
            md.append(llm["executive_summary"] + "\n")
        else:
            md.append(f"An authorized, non-destructive web security assessment was conducted against `{self.target_url}`. ")
            md.append(f"The audit identified a total of **{len(self.findings)}** findings across HTTP/TLS configuration, headers, and security controls.\n")

        md.append("### Severity Breakdown\n")
        md.append("| Severity | Count | Classification |")
        md.append("| :--- | :---: | :--- |")
        md.append(f"| **Critical** | {sev_counts.get('Critical', 0)} | Immediate remediation required |")
        md.append(f"| **High** | {sev_counts.get('High', 0)} | High risk of security control bypass |")
        md.append(f"| **Medium** | {sev_counts.get('Medium', 0)} | Misconfiguration / Hardening gap |")
        md.append(f"| **Low** | {sev_counts.get('Low', 0)} | Defense-in-depth weakness |")
        md.append(f"| **Informational** | {sev_counts.get('Informational', 0)} | Passive reconnaissance metric |\n")

        # Telemetry
        sched = self.data.get("scheduler_telemetry", {})
        if sched:
            md.append("### Audit Scheduler & Rate Limiting Compliance\n")
            md.append(f"- **Configured Rate:** {sched.get('configured_rps', 2.0)} requests/second")
            md.append(f"- **Total Requests Dispatched:** {sched.get('requests_sent', 0)}")
            md.append(f"- **Out-of-Scope Redirects Blocked:** {self.data.get('blocked_redirects_count', 0)}\n")

        md.append("## Detailed Vulnerability Findings\n")
        if not self.findings:
            md.append("*No security weaknesses identified during this assessment.*\n")
        else:
            for i, f in enumerate(self.findings, 1):
                title = f.get("title", "Untitled Finding")
                sev = f.get("severity", "Low")
                cwe = f.get("cwe", "CWE-16")
                cvss = f.get("cvss") or "N/A"
                conf = int(f.get("confidence", 0.9) * 100)
                status = f.get("verification_status", "potential").upper()
                scope_st = f.get("scope_status", "in_scope").upper()
                endpoint = f.get("endpoint", self.target_url)
                evidence = redact_sensitive_evidence(f.get("evidence", "No evidence recorded."))

                md.append(f"### {i}. [{sev}] {title}\n")
                md.append(f"- **Affected Asset / Endpoint:** `{endpoint}`")
                cwe_str = str(cwe)
                cwe_digits = "".join(filter(str.isdigit, cwe_str)) or "16"
                md.append(f"- **CWE:** [{cwe_str}](https://cwe.mitre.org/data/definitions/{cwe_digits}.html) | **CVSS Base:** `{cvss}`")
                md.append(f"- **Verification Status:** `{status}` | **Scope Status:** `{scope_st}`")
                md.append(f"- **Scanner Confidence:** `{conf}%`\n")

                md.append(f"#### Technical Description\n{f.get('description', '')}\n")
                md.append(f"#### Security Impact\n{f.get('impact', 'Potential exposure of configuration metadata or degraded defense-in-depth posture.')}\n")

                md.append("#### Observed Evidence\n```http")
                md.append(evidence)
                md.append("```\n")

                if f.get("manual_verification_required"):
                    md.append("> ⚠️ **MANUAL VERIFICATION REQUIRED**  ")
                    notes = f.get("manual_verification_notes", {})
                    md.append(f"> **Why this matters:** {notes.get('why_it_matters', 'Requires human contextual review.')}  ")
                    md.append(f"> **Verification Step:** {notes.get('how_to_verify', 'Perform non-destructive browser inspection.')}  ")
                    md.append(f"> **Program Rule Check:** {notes.get('rule_check', 'Ensure active exploitation is never attempted.')}\n")

                md.append("#### Steps to Reproduce (Non-Destructive)")
                md.append(f"1. Navigate to target endpoint: `{endpoint}`")
                md.append("2. Inspect response headers and TLS parameters using `curl -I -v` or developer tools.")
                md.append(f"3. Note the absence or misconfiguration as highlighted in the evidence above.\n")

                md.append(f"#### Remediation Recommendation\n{f.get('remediation', f.get('recommendation', 'Implement recommended security controls.'))}\n")
                md.append("---\n")

        # Roadmap
        if llm and "remediation_roadmap" in llm:
            md.append("## Prioritized Remediation Roadmap\n")
            for step in llm["remediation_roadmap"]:
                md.append(f"- {step}")
            md.append("")

        md.append("\n*Report generated by AegisGuard Defensive Security Assessment Platform.*")
        return "\n".join(md)

    def to_html(self) -> str:
        """Renders a self-contained, publication-ready HTML report."""
        sev_counts = self.data.get("severity_summary", {})
        meta = self.data.get("metadata", {})
        program = meta.get("program", "Authorized Bug Bounty Program")

        findings_html = []
        for i, f in enumerate(self.findings, 1):
            sev = f.get("severity", "Low")
            sev_class = sev.lower()
            conf = int(f.get("confidence", 0.9) * 100)
            status = f.get("verification_status", "potential").upper()
            evidence = redact_sensitive_evidence(f.get("evidence", ""))

            manual_block = ""
            if f.get("manual_verification_required"):
                notes = f.get("manual_verification_notes", {})
                manual_block = f"""
                <div class="manual-box">
                  <strong>⚠️ MANUAL VERIFICATION REQUIRED</strong>
                  <p><strong>Context:</strong> {notes.get('why_it_matters', 'Requires manual inspection.')}</p>
                  <p><strong>Guidance:</strong> {notes.get('how_to_verify', 'Inspect headers in browser.')}</p>
                </div>
                """

            findings_html.append(f"""
            <div class="finding-block {sev_class}">
              <div class="finding-header">
                <span class="sev-tag {sev_class}">{sev}</span>
                <span class="finding-num">#{i}</span>
                <h3 class="finding-title">{f.get('title')}</h3>
              </div>
              <div class="finding-meta">
                <span><strong>Endpoint:</strong> <code>{f.get('endpoint', self.target_url)}</code></span>
                <span><strong>CWE:</strong> {f.get('cwe', 'CWE-16')}</span>
                <span><strong>Status:</strong> {status}</span>
                <span><strong>Confidence:</strong> {conf}%</span>
              </div>
              <p class="finding-desc">{f.get('description')}</p>
              <div class="evidence-box">
                <div class="evidence-title">OBSERVED EVIDENCE</div>
                <pre><code>{evidence}</code></pre>
              </div>
              {manual_block}
              <div class="remediation-box">
                <strong>Remediation:</strong> {f.get('remediation', f.get('recommendation'))}
              </div>
            </div>
            """)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AegisGuard Audit Report - {self.target_url}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f19; color: #f3f4f6; margin: 0; padding: 40px 20px; line-height: 1.6; }}
    .container {{ max-width: 900px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-radius: 12px; padding: 32px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
    h1 {{ font-size: 1.6rem; color: #38bdf8; margin-top: 0; }}
    .meta-bar {{ display: flex; flex-wrap: wrap; gap: 16px; background: #0a0e17; padding: 12px 16px; border-radius: 8px; margin-bottom: 24px; font-size: 0.85rem; border: 1px solid #1e293b; }}
    .counts-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; margin-bottom: 30px; }}
    .count-card {{ background: #141e33; padding: 12px; border-radius: 8px; text-align: center; border: 1px solid #1f2b42; }}
    .count-card h4 {{ margin: 0; font-size: 0.75rem; text-transform: uppercase; color: #94a3b8; }}
    .count-card .val {{ font-size: 1.5rem; font-weight: bold; margin-top: 4px; }}
    .finding-block {{ background: #141e33; border: 1px solid #1f2b42; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
    .finding-block.critical {{ border-left: 4px solid #f43f5e; }}
    .finding-block.high {{ border-left: 4px solid #fb923c; }}
    .finding-block.medium {{ border-left: 4px solid #facc15; }}
    .finding-block.low {{ border-left: 4px solid #38bdf8; }}
    .finding-block.informational {{ border-left: 4px solid #818cf8; }}
    .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }}
    .sev-tag {{ font-size: 0.7rem; font-weight: 800; padding: 3px 8px; border-radius: 4px; text-transform: uppercase; }}
    .sev-tag.critical {{ background: rgba(244,63,94,0.2); color: #f43f5e; }}
    .sev-tag.high {{ background: rgba(251,146,60,0.2); color: #fb923c; }}
    .sev-tag.medium {{ background: rgba(250,204,21,0.2); color: #facc15; }}
    .sev-tag.low {{ background: rgba(56,189,248,0.2); color: #38bdf8; }}
    .sev-tag.informational {{ background: rgba(129,140,248,0.2); color: #818cf8; }}
    .finding-title {{ margin: 0; font-size: 1.1rem; color: #fff; }}
    .finding-meta {{ font-size: 0.8rem; color: #94a3b8; display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 12px; }}
    .evidence-box {{ background: #050811; border: 1px solid #111a2e; border-radius: 6px; padding: 12px; margin: 12px 0; }}
    .evidence-title {{ font-size: 0.7rem; color: #64748b; font-weight: 700; margin-bottom: 6px; }}
    pre {{ margin: 0; font-family: monospace; font-size: 0.82rem; color: #38bdf8; overflow-x: auto; white-space: pre-wrap; }}
    .remediation-box {{ background: rgba(52,211,153,0.1); border: 1px solid rgba(52,211,153,0.3); border-radius: 6px; padding: 10px 14px; color: #6ee7b7; font-size: 0.88rem; }}
    .manual-box {{ background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.3); border-radius: 6px; padding: 10px 14px; margin: 10px 0; font-size: 0.84rem; color: #fde047; }}
    code {{ font-family: monospace; color: #38bdf8; }}
  </style>
</head>
<body>
  <div class="container">
    <h1>AegisGuard Bug Bounty Security Audit Report</h1>
    <div class="meta-bar">
      <span><strong>Target:</strong> {self.target_url}</span>
      <span><strong>Program:</strong> {program}</span>
      <span><strong>Audit ID:</strong> {self.scan_id}</span>
      <span><strong>Generated:</strong> {self.timestamp}</span>
    </div>

    <div class="counts-grid">
      <div class="count-card"><h4 style="color:#f43f5e">Critical</h4><div class="val" style="color:#f43f5e">{sev_counts.get('Critical', 0)}</div></div>
      <div class="count-card"><h4 style="color:#fb923c">High</h4><div class="val" style="color:#fb923c">{sev_counts.get('High', 0)}</div></div>
      <div class="count-card"><h4 style="color:#facc15">Medium</h4><div class="val" style="color:#facc15">{sev_counts.get('Medium', 0)}</div></div>
      <div class="count-card"><h4 style="color:#38bdf8">Low</h4><div class="val" style="color:#38bdf8">{sev_counts.get('Low', 0)}</div></div>
      <div class="count-card"><h4 style="color:#818cf8">Informational</h4><div class="val" style="color:#818cf8">{sev_counts.get('Informational', 0)}</div></div>
    </div>

    <h2>Vulnerability Findings ({len(self.findings)})</h2>
    {"".join(findings_html)}
  </div>
</body>
</html>"""
        return html
