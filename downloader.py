"""
downloader.py - Report Download & Export Controller
Manages report retrieval, multi-format transformation (JSON, Markdown, HTML),
and secure export packaging for bug-bounty researchers and clients.
"""

import os
import json
from typing import Tuple, Dict, Any, Optional
from report_generator import BugBountyReportGenerator

REPORTS_DIR = "reports"

class ReportDownloader:
    """
    Handles report retrieval and formatting for download endpoints.
    """
    def __init__(self, reports_dir: str = REPORTS_DIR):
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)

    def get_report_json_path(self, scan_id: str) -> Optional[str]:
        """Validates and returns path to raw report JSON."""
        # Sanitize scan_id against path traversal
        clean_id = os.path.basename(scan_id).replace("..", "")
        file_path = os.path.join(self.reports_dir, f"{clean_id}.json")
        if os.path.exists(file_path):
            return file_path
        return None

    def export_report(self, scan_id: str, export_format: str = "json") -> Tuple[Optional[str], str, str]:
        """
        Transforms and generates requested report export.
        Returns: (file_path_on_disk, media_type, suggested_filename)
        """
        json_path = self.get_report_json_path(scan_id)
        if not json_path:
            return None, "", ""

        with open(json_path, "r", encoding="utf-8") as f:
            audit_data = json.load(f)

        generator = BugBountyReportGenerator(audit_data)
        fmt = export_format.lower().strip()

        if fmt == "markdown" or fmt == "md":
            content = generator.to_markdown()
            out_filename = f"AegisGuard_BugBounty_Report_{scan_id}.md"
            out_path = os.path.join(self.reports_dir, out_filename)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(content)
            return out_path, "text/markdown", out_filename

        elif fmt == "html":
            content = generator.to_html()
            out_filename = f"AegisGuard_BugBounty_Report_{scan_id}.html"
            out_path = os.path.join(self.reports_dir, out_filename)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(content)
            return out_path, "text/html", out_filename

        else: # Default JSON
            content = generator.to_json()
            out_filename = f"AegisGuard_BugBounty_Report_{scan_id}.json"
            out_path = os.path.join(self.reports_dir, out_filename)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(content)
            return out_path, "application/json", out_filename
