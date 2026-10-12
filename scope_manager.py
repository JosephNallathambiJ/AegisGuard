"""
scope_manager.py - Bug-Bounty Scope & Program Policy Manager
Enforces strict in-scope target verification, exclusion lists, scheme validation,
and scope-aware redirect interception for authorized bug-bounty audits.
"""

import os
import json
import fnmatch
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Any, Tuple, Optional

CONFIG_DIR = "config"
LOGS_DIR = "logs"
SCOPE_FILE = os.path.join(CONFIG_DIR, "scope.json")
POLICIES_FILE = os.path.join(CONFIG_DIR, "policies.json")
SCOPE_LOG_FILE = os.path.join(LOGS_DIR, "scope.log")


class ScopeManager:
    """
    Evaluates and enforces bug-bounty program scopes and rules.
    """
    def __init__(self, scope_path: str = SCOPE_FILE, policies_path: str = POLICIES_FILE):
        self.scope_path = scope_path
        self.policies_path = policies_path
        self.scope_data: Dict[str, Any] = {}
        self.policies_data: Dict[str, Any] = {}
        self.load_configurations()

    def load_configurations(self):
        """Loads scope and policy profiles from disk."""
        if os.path.exists(self.scope_path):
            try:
                with open(self.scope_path, "r", encoding="utf-8") as f:
                    self.scope_data = json.load(f)
            except Exception as e:
                print(f"[!] Error reading {self.scope_path}: {e}")
                self.scope_data = {}
        else:
            self.scope_data = {
                "program": "Default Authorized Assessment",
                "authorized": True,
                "targets": ["localhost", "127.0.0.1"],
                "excluded_targets": [],
                "allowed_schemes": ["https", "http"],
                "max_requests_per_second": 2.0,
                "automated_scanning_allowed": True,
                "program_rules_acknowledged": True
            }

        if os.path.exists(self.policies_path):
            try:
                with open(self.policies_path, "r", encoding="utf-8") as f:
                    self.policies_data = json.load(f)
            except Exception as e:
                print(f"[!] Error reading {self.policies_path}: {e}")
                self.policies_data = {}

    def get_scope_config(self) -> Dict[str, Any]:
        return self.scope_data

    def get_policies(self) -> Dict[str, Any]:
        return self.policies_data.get("profiles", {})

    def update_scope_config(self, new_scope: Dict[str, Any]) -> bool:
        """Persists updated scope configuration."""
        self.scope_data = new_scope
        os.makedirs(CONFIG_DIR, exist_ok=True)
        try:
            with open(self.scope_path, "w", encoding="utf-8") as f:
                json.dump(self.scope_data, f, indent=2)
            self._log_scope_event("SCOPE_UPDATED", "Config", True, f"Program: {new_scope.get('program')}")
            return True
        except Exception as e:
            print(f"[!] Error saving scope config: {e}")
            return False

    def _log_scope_event(self, action: str, target: str, allowed: bool, reason: str):
        """Appends an event to logs/scope.log for compliance audits."""
        os.makedirs(LOGS_DIR, exist_ok=True)
        timestamp = datetime.now(timezone.utc).isoformat()
        decision = "PERMITTED" if allowed else "BLOCKED"
        entry = f"[{timestamp}] [{action}] [{decision}] Target: {target} | Reason: {reason}\n"
        try:
            with open(SCOPE_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(entry)
        except Exception:
            pass

    def _matches_pattern(self, hostname: str, pattern: str) -> bool:
        """Matches a hostname against a pattern supporting wildcards (e.g. *.example.com)."""
        hostname = hostname.lower().strip()
        pattern = pattern.lower().strip()

        if hostname == pattern:
            return True

        if pattern.startswith("*."):
            base_domain = pattern[2:]
            # Matches sub.example.com or direct example.com
            if hostname == base_domain or hostname.endswith("." + base_domain):
                return True

        return fnmatch.fnmatch(hostname, pattern)

    def is_hostname_in_scope(self, hostname: str) -> Tuple[bool, str]:
        """Verifies if a hostname is explicitly allowed and not excluded."""
        if not hostname:
            return False, "Empty hostname provided."

        clean_host = hostname.lower().split(":")[0].strip()

        # 1. Check exclusions first
        excluded = self.scope_data.get("excluded_targets", [])
        for exc in excluded:
            if self._matches_pattern(clean_host, exc):
                reason = f"Target '{clean_host}' matches excluded target '{exc}' in program scope rules."
                self._log_scope_event("EXCLUSION_CHECK", clean_host, False, reason)
                return False, reason

        # 2. Check in-scope targets
        targets = self.scope_data.get("targets", [])
        if not targets:
            reason = "No target domains configured in program scope."
            self._log_scope_event("SCOPE_CHECK", clean_host, False, reason)
            return False, reason

        for tgt in targets:
            if self._matches_pattern(clean_host, tgt):
                reason = f"Matches authorized scope pattern '{tgt}'."
                self._log_scope_event("SCOPE_CHECK", clean_host, True, reason)
                return True, reason

        reason = f"Hostname '{clean_host}' is outside configured program scope targets: {targets}"
        self._log_scope_event("SCOPE_CHECK", clean_host, False, reason)
        return False, reason

    def validate_target_url(self, raw_url: str, policy_profile: str = "Bug Bounty Standard") -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates target URL against scheme constraints, program rules, and scope.
        """
        if not raw_url or not isinstance(raw_url, str):
            return False, "Target URL must be a non-empty string.", {}

        # Check program rules flags
        if not self.scope_data.get("program_rules_acknowledged", False):
            return False, "Program rules must be explicitly acknowledged prior to assessment.", {}

        if not self.scope_data.get("automated_scanning_allowed", True):
            reason = "Bug-bounty program explicitly disallows automated scanning."
            self._log_scope_event("POLICY_CHECK", raw_url, False, reason)
            return False, reason, {}

        # Normalize URL scheme
        url_stripped = raw_url.strip()
        if not (url_stripped.startswith("http://") or url_stripped.startswith("https://")):
            url_stripped = "https://" + url_stripped

        parsed = urllib.parse.urlsplit(url_stripped)
        scheme = parsed.scheme.lower()

        allowed_schemes = self.scope_data.get("allowed_schemes", ["https", "http"])
        if scheme not in allowed_schemes:
            reason = f"URI scheme '{scheme}' is not allowed by program scope (permitted: {allowed_schemes})."
            self._log_scope_event("SCHEME_CHECK", raw_url, False, reason)
            return False, reason, {}

        hostname = parsed.hostname
        if not hostname:
            return False, "Could not extract valid hostname from URL.", {}

        # Verify policy profile requirements
        profile = self.get_policies().get(policy_profile, {})
        allow_local_lab = profile.get("allow_local_lab", False)

        # Hostname scope check
        in_scope, scope_reason = self.is_hostname_in_scope(hostname)
        if not in_scope:
            return False, scope_reason, {}

        # Clean normalized URL
        normalized_url = urllib.parse.urlunsplit((scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))

        meta = {
            "program": self.scope_data.get("program", "Authorized Assessment"),
            "hostname": hostname,
            "scheme": scheme,
            "port": parsed.port or (443 if scheme == "https" else 80),
            "policy_profile": policy_profile,
            "allow_local_lab": allow_local_lab,
            "max_rps": float(self.scope_data.get("max_requests_per_second", 2.0)),
            "path": parsed.path or "/"
        }

        return True, normalized_url, meta

    def is_redirect_in_scope(self, current_url: str, redirect_url: str) -> Tuple[bool, str]:
        """
        Checks if an HTTP redirect lands on an authorized in-scope host.
        If out of scope, blocks the redirect and logs OUT-OF-SCOPE REDIRECT BLOCKED.
        """
        # Resolve relative redirects
        abs_redirect = urllib.parse.urljoin(current_url, redirect_url)
        parsed = urllib.parse.urlsplit(abs_redirect)
        dest_host = parsed.hostname

        if not dest_host:
            reason = "Malformed redirect destination."
            self._log_scope_event("REDIRECT_BLOCKED", redirect_url, False, reason)
            return False, reason

        in_scope, reason = self.is_hostname_in_scope(dest_host)
        if not in_scope:
            log_reason = f"OUT-OF-SCOPE REDIRECT BLOCKED: Navigating from '{current_url}' to out-of-scope host '{dest_host}' is prohibited."
            self._log_scope_event("REDIRECT_BLOCKED", abs_redirect, False, log_reason)
            return False, log_reason

        return True, abs_redirect

    def is_in_scope(self, url_or_host: str) -> bool:
        """Convenience method checking whether a given URL or hostname is within scope."""
        if not url_or_host:
            return False
        clean = url_or_host.strip()
        if "://" in clean:
            parsed = urllib.parse.urlsplit(clean)
            host = parsed.hostname or clean
        else:
            host = clean.split("/")[0].split(":")[0]
        in_scope, _ = self.is_hostname_in_scope(host)
        return in_scope
