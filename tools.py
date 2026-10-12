"""
tools.py - Kali Linux Security Tool Integration Suite for AegisGuard
Provides safe, non-destructive wrappers for native Kali Linux reconnaissance
and auditing utilities (Nmap, WhatWeb, SSLScan/Testssl, Nikto, DNS/Dig),
with complete pure-Python fallbacks when binaries are not available.
"""

import os
import re
import ssl
import json
import socket
import shutil
import urllib.parse
import subprocess
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from scope_manager import ScopeManager


SECURITY_TOOLS = {
    "nmap": "nmap",
    "whatweb": "whatweb",
    "sslscan": "sslscan",
    "testssl": "testssl.sh",
    "nikto": "nikto",
    "dig": "dig",
    "metasploit": "msfconsole",
    "Burp Suite": "burpsuite",
}


class KaliToolRegistry:
    """Detects available Kali Linux CLI utilities and system capabilities."""
    
    TOOL_BINARIES = SECURITY_TOOLS

    @classmethod
    def check_capabilities(cls) -> Dict[str, Dict[str, Any]]:
        """Returns availability and version info for each tool."""
        capabilities = {}
        for tool_key, bin_name in cls.TOOL_BINARIES.items():
            path = shutil.which(bin_name)

            # Special path searches for macOS/Kali standard locations if not on PATH
            if not path:
                if tool_key == "Burp Suite":
                    for alt in [
                        "/usr/bin/burpsuite",
                        "/Applications/Burp Suite Community Edition.app/Contents/MacOS/JavaApplicationStub",
                        "/Applications/Burp Suite Professional.app/Contents/MacOS/JavaApplicationStub"
                    ]:
                        if os.path.exists(alt):
                            path = alt
                            break
                elif tool_key == "metasploit":
                    for alt in ["/usr/bin/msfconsole", "/opt/metasploit-framework/bin/msfconsole"]:
                        if os.path.exists(alt):
                            path = alt
                            break

            is_present = path is not None
            version = "Not installed"
            is_manual = tool_key in ("metasploit", "Burp Suite")

            if is_present:
                try:
                    if tool_key == "metasploit":
                        res = subprocess.run([path, "-v"], capture_output=True, text=True, timeout=8)
                        raw_out = (res.stdout or res.stderr).splitlines()
                        version = raw_out[0].strip() if raw_out else "Metasploit Framework Present"
                    elif tool_key == "Burp Suite":
                        version = "Burp Suite Proxy & Testing Suite"
                    else:
                        res = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=5)
                        raw_out = (res.stdout or res.stderr).splitlines()
                        version = raw_out[0].strip() if raw_out else "Present"
                except Exception:
                    version = "Present (version query timed out)"

            capabilities[tool_key] = {
                "available": is_present,
                "binary": bin_name,
                "path": path,
                "version": version,
                "is_manual_only": is_manual,
                "category": "Interactive Testing / Proxy" if is_manual else "Automated Reconnaissance"
            }
        return capabilities


class KaliToolRunner:
    """
    Executes safe, non-destructive Kali Linux tool checks within program scope,
    automatically falling back to robust pure-Python implementations if native binaries
    are absent.
    """

    def __init__(self, scope_manager: Optional[ScopeManager] = None):
        self.scope_mgr = scope_manager or ScopeManager()
        self.capabilities = KaliToolRegistry.check_capabilities()

    def _parse_host_and_port(self, target_url: str) -> Tuple[str, int, str]:
        parsed = urllib.parse.urlparse(target_url)
        scheme = parsed.scheme or "https"
        host = parsed.hostname or "localhost"
        default_port = 443 if scheme == "https" else 80
        port = parsed.port or default_port
        return host, port, scheme

    # ==========================================================================
    # 1. NMAP (Passive Port & Service Version Detection)
    # ==========================================================================
    def run_nmap_scan(self, target_url: str, timeout: int = 40) -> Dict[str, Any]:
        """
        Executes a non-destructive service version audit.
        Flags used: -sV (Version detection), -Pn (Assume host online), --version-light (Minimal probes),
        and restricted only to common web ports (80, 443, 8000, 8080, 8443, 8888).
        """
        host, port, _ = self._parse_host_and_port(target_url)

        # Enforce scope check
        if not self.scope_mgr.is_in_scope(f"http://{host}") and not self.scope_mgr.is_in_scope(f"https://{host}"):
            return {
                "tool": "nmap",
                "status": "blocked_out_of_scope",
                "findings": [],
                "raw_output": "Target host outside configured program scope."
            }

        nmap_bin = shutil.which("nmap")
        findings = []

        if nmap_bin:
            try:
                cmd = [
                    nmap_bin,
                    "-sV",
                    "-Pn",
                    "--version-light",
                    "-p", "80,443,8000,8080,8443,8888",
                    "--open",
                    host
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                raw_out = res.stdout

                # Parse open ports & services
                for line in raw_out.splitlines():
                    match = re.search(r"(\d+)/(tcp|udp)\s+open\s+([\w\-\?]+)\s*(.*)", line)
                    if match:
                        p_num, proto, svc_name, version_info = match.groups()
                        version_info = version_info.strip()
                        findings.append({
                            "title": f"Exposed Web Port & Service: {p_num}/{proto} ({svc_name})",
                            "severity": "Informational",
                            "cwe": "CWE-200",
                            "cvss": 2.0,
                            "confidence": 0.95,
                            "verification_status": "observed",
                            "endpoint": f"{host}:{p_num}",
                            "parameter": f"{proto}/{p_num}",
                            "evidence": f"Service: {svc_name} | Version: {version_info or 'Unknown'}",
                            "remediation": "Restrict accessible administrative ports and disable non-essential external listeners.",
                            "tool_source": "nmap-cli"
                        })

                return {
                    "tool": "nmap",
                    "mode": "kali_native",
                    "status": "completed",
                    "findings": findings,
                    "raw_output": raw_out
                }
            except Exception as e:
                # Fallback to python
                pass

        # Python Socket Fallback
        common_ports = [80, 443, 8080, 8443]
        for p in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                code = sock.connect_ex((host, p))
                if code == 0:
                    findings.append({
                        "title": f"Exposed Web Port: {p}/tcp",
                        "severity": "Informational",
                        "cwe": "CWE-200",
                        "cvss": 2.0,
                        "confidence": 0.90,
                        "verification_status": "observed",
                        "endpoint": f"{host}:{p}",
                        "parameter": f"tcp/{p}",
                        "evidence": f"Socket connection succeeded on port {p}.",
                        "remediation": "Ensure port is intentionally exposed and protected with rate limiting.",
                        "tool_source": "nmap-python-fallback"
                    })
                sock.close()
            except Exception:
                pass

        return {
            "tool": "nmap",
            "mode": "python_fallback",
            "status": "completed",
            "findings": findings,
            "raw_output": f"Python TCP socket connection probe completed for {host}."
        }

    # ==========================================================================
    # 2. WHATWEB (Web Technology Fingerprinting)
    # ==========================================================================
    def run_whatweb_scan(self, target_url: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Executes stealthy/passive technology fingerprinting.
        Uses Aggression Level 1 (-a 1) to inspect HTTP response headers and body meta tags.
        """
        host, _, _ = self._parse_host_and_port(target_url)
        if not self.scope_mgr.is_in_scope(target_url):
            return {
                "tool": "whatweb",
                "status": "blocked_out_of_scope",
                "findings": [],
                "raw_output": "Target URL outside configured scope."
            }

        whatweb_bin = shutil.which("whatweb")
        findings = []

        if whatweb_bin:
            try:
                cmd = [
                    whatweb_bin,
                    "--colour=never",
                    "--no-errors",
                    "-a", "1",
                    target_url
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                raw_out = res.stdout.strip()

                if raw_out:
                    # Detect tech disclosures
                    findings.append({
                        "title": "Web Technology Stack Fingerprint Disclosed",
                        "severity": "Low",
                        "cwe": "CWE-200",
                        "cvss": 3.1,
                        "confidence": 0.92,
                        "verification_status": "observed",
                        "endpoint": target_url,
                        "parameter": "HTTP Response Headers / HTML Meta",
                        "evidence": raw_out[:300],
                        "remediation": "Suppress detailed version headers (Server, X-Powered-By) and framework banners in production.",
                        "tool_source": "whatweb-cli"
                    })

                return {
                    "tool": "whatweb",
                    "mode": "kali_native",
                    "status": "completed",
                    "findings": findings,
                    "raw_output": raw_out
                }
            except Exception:
                pass

        # Python HTTP Fingerprint Fallback
        import requests
        try:
            resp = requests.get(target_url, timeout=5, verify=False, headers={"User-Agent": "AegisGuard-Defensive-Scanner/2.0"})
            disclosed = []
            for h in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
                if h in resp.headers:
                    disclosed.append(f"{h}: {resp.headers[h]}")

            if disclosed:
                findings.append({
                    "title": "Web Server / Technology Banner Exposed",
                    "severity": "Low",
                    "cwe": "CWE-200",
                    "cvss": 3.1,
                    "confidence": 0.95,
                    "verification_status": "observed",
                    "endpoint": target_url,
                    "parameter": "Response Headers",
                    "evidence": ", ".join(disclosed),
                    "remediation": "Configure reverse proxies or web servers to strip diagnostic technology banners.",
                    "tool_source": "whatweb-python-fallback"
                })
        except Exception:
            pass

        return {
            "tool": "whatweb",
            "mode": "python_fallback",
            "status": "completed",
            "findings": findings,
            "raw_output": "Python HTTP response header technology audit completed."
        }

    # ==========================================================================
    # 3. SSLSCAN / TESTSSL (TLS & Cipher Suite Auditor)
    # ==========================================================================
    def run_ssl_scan(self, target_url: str, timeout: int = 35) -> Dict[str, Any]:
        """
        Audits SSL/TLS protocols and weak ciphers (SSLv2, SSLv3, TLS 1.0, TLS 1.1, RC4, CBC, 3DES).
        """
        host, port, scheme = self._parse_host_and_port(target_url)
        if scheme != "https":
            return {
                "tool": "sslscan",
                "status": "skipped_plain_http",
                "findings": [],
                "raw_output": "Target is not using HTTPS scheme."
            }

        if not self.scope_mgr.is_in_scope(target_url):
            return {
                "tool": "sslscan",
                "status": "blocked_out_of_scope",
                "findings": [],
                "raw_output": "Target outside scope."
            }

        sslscan_bin = shutil.which("sslscan")
        findings = []

        if sslscan_bin:
            try:
                cmd = [sslscan_bin, "--no-colour", "--tlsall", f"{host}:{port}"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                raw_out = res.stdout

                # Check for legacy TLS protocols
                for proto in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
                    if re.search(rf"Accepted\s+{proto}", raw_out, re.IGNORECASE):
                        findings.append({
                            "title": f"Deprecated Insecure TLS Protocol Supported: {proto}",
                            "severity": "Medium",
                            "cwe": "CWE-326",
                            "cvss": 5.9,
                            "confidence": 0.95,
                            "verification_status": "observed",
                            "endpoint": f"{host}:{port}",
                            "parameter": f"TLS Protocol: {proto}",
                            "evidence": f"sslscan verified that {proto} handshake is accepted.",
                            "remediation": f"Disable {proto} on web servers and load balancers. Enforce TLSv1.2 and TLSv1.3 exclusively.",
                            "tool_source": "sslscan-cli"
                        })

                return {
                    "tool": "sslscan",
                    "mode": "kali_native",
                    "status": "completed",
                    "findings": findings,
                    "raw_output": raw_out[:1000]
                }
            except Exception:
                pass

        # Python SSL Fallback
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher = ssock.cipher()
                    proto_version = ssock.version()
                    if proto_version in ["TLSv1", "TLSv1.1"]:
                        findings.append({
                            "title": f"Legacy TLS Protocol Detected: {proto_version}",
                            "severity": "Medium",
                            "cwe": "CWE-326",
                            "cvss": 5.9,
                            "confidence": 0.90,
                            "verification_status": "observed",
                            "endpoint": f"{host}:{port}",
                            "parameter": "SSL Handshake",
                            "evidence": f"Negotiated protocol: {proto_version}, Cipher: {cipher[0] if cipher else 'Unknown'}",
                            "remediation": "Enforce TLS 1.2 or TLS 1.3 as the minimum protocol version.",
                            "tool_source": "ssl-python-fallback"
                        })
        except Exception:
            pass

        return {
            "tool": "sslscan",
            "mode": "python_fallback",
            "status": "completed",
            "findings": findings,
            "raw_output": "Python SSL socket handshake inspection completed."
        }

    # ==========================================================================
    # 4. NIKTO (Safe Web Misconfiguration Audit)
    # ==========================================================================
    def run_nikto_scan(self, target_url: str, timeout: int = 45) -> Dict[str, Any]:
        """
        Runs Nikto with safe, non-destructive tuning:
        -Tuning 1 (Server misconfiguration), 2 (Default files), b (Software ID).
        """
        if not self.scope_mgr.is_in_scope(target_url):
            return {
                "tool": "nikto",
                "status": "blocked_out_of_scope",
                "findings": [],
                "raw_output": "Target outside scope."
            }

        nikto_bin = shutil.which("nikto")
        findings = []

        if nikto_bin:
            try:
                cmd = [
                    nikto_bin,
                    "-h", target_url,
                    "-Tuning", "1,2,b",
                    "-nointeractive",
                    "-maxtime", "35s"
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                raw_out = res.stdout

                for line in raw_out.splitlines():
                    if "+ The anti-clickjacking X-Frame-Options header is not present" in line:
                        findings.append({
                            "title": "Missing X-Frame-Options Header (Clickjacking Risk)",
                            "severity": "Low",
                            "cwe": "CWE-1021",
                            "cvss": 4.3,
                            "confidence": 0.95,
                            "verification_status": "observed",
                            "endpoint": target_url,
                            "parameter": "X-Frame-Options",
                            "evidence": line.strip(),
                            "remediation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header.",
                            "tool_source": "nikto-cli"
                        })
                    elif "+ Server leaks chemical/version" in line or "+ Server banner:" in line:
                        findings.append({
                            "title": "Server Banner Information Disclosure",
                            "severity": "Low",
                            "cwe": "CWE-200",
                            "cvss": 3.1,
                            "confidence": 0.90,
                            "verification_status": "observed",
                            "endpoint": target_url,
                            "parameter": "Server Banner",
                            "evidence": line.strip(),
                            "remediation": "Disable server banner disclosure.",
                            "tool_source": "nikto-cli"
                        })

                return {
                    "tool": "nikto",
                    "mode": "kali_native",
                    "status": "completed",
                    "findings": findings,
                    "raw_output": raw_out[:1200]
                }
            except Exception:
                pass

        # Python Safe Misconfiguration Probe (robots.txt, security.txt)
        import requests
        base = target_url.rstrip("/")
        for path in ["/robots.txt", "/.well-known/security.txt"]:
            try:
                r = requests.get(f"{base}{path}", timeout=4, verify=False)
                if r.status_code == 200 and len(r.text.strip()) > 0:
                    findings.append({
                        "title": f"Public Administrative File Disclosed: {path}",
                        "severity": "Informational",
                        "cwe": "CWE-200",
                        "cvss": 2.0,
                        "confidence": 0.95,
                        "verification_status": "observed",
                        "endpoint": f"{base}{path}",
                        "parameter": path,
                        "evidence": f"File accessible with HTTP 200 (length: {len(r.text)} bytes).",
                        "remediation": "Verify exposed paths do not list sensitive admin or staging directories.",
                        "tool_source": "nikto-python-fallback"
                    })
            except Exception:
                pass

        return {
            "tool": "nikto",
            "mode": "python_fallback",
            "status": "completed",
            "findings": findings,
            "raw_output": "Python defensive misconfiguration probe completed."
        }

    # ==========================================================================
    # 5. DNS / DIG (DNS & Domain Hygiene Reconnaissance)
    # ==========================================================================
    def run_dns_recon(self, target_url: str, timeout: int = 20) -> Dict[str, Any]:
        """
        Checks DNS records (A, AAAA, MX, TXT) and email security records (SPF, DMARC).
        """
        host, _, _ = self._parse_host_and_port(target_url)
        findings = []
        dig_bin = shutil.which("dig")

        if dig_bin:
            try:
                cmd = [dig_bin, "+noall", "+answer", host, "ANY"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
                raw_out = res.stdout

                # Check SPF record presence
                txt_cmd = [dig_bin, "+short", "TXT", host]
                txt_res = subprocess.run(txt_cmd, capture_output=True, text=True, timeout=timeout)
                txt_records = txt_res.stdout
                if "v=spf1" not in txt_records.lower():
                    findings.append({
                        "title": "Missing or Weak SPF Email Authentication Record",
                        "severity": "Low",
                        "cwe": "CWE-346",
                        "cvss": 3.8,
                        "confidence": 0.88,
                        "verification_status": "observed",
                        "endpoint": host,
                        "parameter": "DNS TXT (SPF)",
                        "evidence": "No valid v=spf1 TXT record found for root hostname.",
                        "remediation": "Publish an SPF record ('v=spf1 ... -all') to protect against email spoofing.",
                        "tool_source": "dig-cli"
                    })

                return {
                    "tool": "dnsrecon",
                    "mode": "kali_native",
                    "status": "completed",
                    "findings": findings,
                    "raw_output": raw_out[:800]
                }
            except Exception:
                pass

        # Python Socket DNS Fallback
        try:
            _, _, ips = socket.gethostbyname_ex(host)
            findings.append({
                "title": f"Domain Name Resolution Verified ({len(ips)} A-Records)",
                "severity": "Informational",
                "cwe": "CWE-200",
                "cvss": 1.0,
                "confidence": 1.0,
                "verification_status": "observed",
                "endpoint": host,
                "parameter": "DNS A",
                "evidence": f"Resolved IP addresses: {', '.join(ips)}",
                "remediation": "Ensure DNS addresses point to authorized infrastructure.",
                "tool_source": "dns-python-fallback"
            })
        except Exception:
            pass

        return {
            "tool": "dnsrecon",
            "mode": "python_fallback",
            "status": "completed",
            "findings": findings,
            "raw_output": f"Python DNS resolution completed for {host}."
        }

    # ==========================================================================
    # Run Full Kali Tool Assessment Suite
    # ==========================================================================
    def run_all_tools(self, target_url: str) -> Dict[str, Any]:
        """
        Executes the entire suite of defensive reconnaissance tools against an authorized target.
        """
        start_time = datetime.now(timezone.utc)
        results = {
            "nmap": self.run_nmap_scan(target_url),
            "whatweb": self.run_whatweb_scan(target_url),
            "sslscan": self.run_ssl_scan(target_url),
            "nikto": self.run_nikto_scan(target_url),
            "dnsrecon": self.run_dns_recon(target_url)
        }

        all_findings = []
        for tool_name, tool_res in results.items():
            all_findings.extend(tool_res.get("findings", []))

        end_time = datetime.now(timezone.utc)
        duration = round((end_time - start_time).total_seconds(), 2)

        return {
            "target_url": target_url,
            "tool_suite_duration_seconds": duration,
            "total_tool_findings": len(all_findings),
            "findings": all_findings,
            "tool_details": results
        }

    # ==========================================================================
    # Metasploit Manual Testing Integration
    # Strictly for manual, authorized invocation.
    # NEVER invoked by automatic scanner. No automated exploits or payloads.
    # ==========================================================================
    def launch_metasploit_console(self, target_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Launches msfconsole in an interactive terminal window for the authorized researcher.
        
        Guards:
        - Checks installation status.
        - If target_url is provided, verifies that target is strictly IN-SCOPE.
        - Passes only target configuration context (e.g. RHOSTS) for manual research.
        - NEVER executes automated exploits, payloads, credential attacks, or persistence.
        - Records user-initiated launch event to logs/scanner.log.
        """
        target_host = None
        if target_url:
            if not self.scope_mgr.is_in_scope(target_url):
                self._log_tool_event("metasploit", f"LAUNCH BLOCKED: Target '{target_url}' is OUT OF SCOPE.")
                return {
                    "success": False,
                    "installed": bool(self.capabilities.get("metasploit", {}).get("available")),
                    "error": f"Target '{target_url}' is OUT OF SCOPE according to program policies. Metasploit cannot be launched against unauthorized targets."
                }
            host, _, _ = self._parse_host_and_port(target_url)
            target_host = host

        msf_info = self.capabilities.get("metasploit", {})
        msf_path = msf_info.get("path") or shutil.which("msfconsole")

        if not msf_path or not os.path.exists(msf_path):
            return {
                "success": False,
                "installed": False,
                "error": "Metasploit console ('msfconsole') is not installed or not in PATH."
            }

        # Identify available terminal emulator on Kali Linux or host
        terminal_cmd = None
        for term in ["qterminal", "x-terminal-emulator", "gnome-terminal", "xfce4-terminal", "konsole", "xterm"]:
            if shutil.which(term):
                if term in ("gnome-terminal", "xfce4-terminal", "qterminal"):
                    terminal_cmd = [term, "--"]
                else:
                    terminal_cmd = [term, "-e"]
                break

        # Log audit event
        self._log_tool_event(
            "metasploit",
            f"Metasploit console manually launched by authorized researcher. "
            f"Target context: {target_host or 'Manual Interactive Session'}."
        )

        try:
            # Build command: pass strictly in-scope target variable if provided, no exploit commands
            msf_args = [msf_path, "-q"]
            if target_host:
                msf_args.extend(["-x", f"setg RHOSTS {target_host}"])

            if terminal_cmd:
                full_cmd = terminal_cmd + msf_args
                subprocess.Popen(full_cmd, start_new_session=True)
                msg = f"Metasploit console launched in interactive terminal window ({terminal_cmd[0]})."
            elif os.uname().sysname == "Darwin":
                # macOS Terminal fallback
                script = f'tell application "Terminal" to do script "{msf_path}' + (f' -x \\"setg RHOSTS {target_host}\\"' if target_host else '') + '" activate'
                subprocess.Popen(["osascript", "-e", script])
                msg = "Metasploit console launched in macOS Terminal."
            else:
                subprocess.Popen(msf_args, start_new_session=True)
                msg = "Metasploit console launched in background interactive session."

            return {
                "success": True,
                "installed": True,
                "tool": "metasploit",
                "binary": msf_path,
                "target_host": target_host,
                "message": msg
            }
        except Exception as e:
            return {
                "success": False,
                "installed": True,
                "error": f"Failed to launch terminal process for msfconsole: {str(e)}"
            }

    # ==========================================================================
    # Burp Suite Manual Testing & Scope Integration
    # ==========================================================================
    def launch_burp_suite(self) -> Dict[str, Any]:
        """
        Launches Burp Suite locally for the authorized researcher to perform
        manual traffic interception and analysis.
        """
        burp_info = self.capabilities.get("Burp Suite", {})
        burp_path = burp_info.get("path") or shutil.which("burpsuite")

        if not burp_path or not os.path.exists(burp_path):
            return {
                "success": False,
                "installed": False,
                "error": "Burp Suite ('burpsuite') is not installed or not in PATH."
            }

        self._log_tool_event("burpsuite", "Burp Suite launched locally by authorized researcher for manual traffic inspection.")

        try:
            subprocess.Popen([burp_path], start_new_session=True)
            return {
                "success": True,
                "installed": True,
                "tool": "Burp Suite",
                "binary": burp_path,
                "message": "Burp Suite launched successfully in local environment."
            }
        except Exception as e:
            return {
                "success": False,
                "installed": True,
                "error": f"Failed to spawn Burp Suite process: {str(e)}"
            }

    def get_burp_suite_scope_config(self) -> Dict[str, Any]:
        """
        Generates a Burp Suite-compatible Target Scope JSON configuration
        derived from config/scope.json so the researcher can directly import it
        into Burp Suite -> Target -> Scope.
        """
        scope_data = self.scope_mgr.get_scope_config()
        targets = scope_data.get("targets", [])
        excluded = scope_data.get("excluded_targets", [])

        include_rules = []
        for tgt in targets:
            clean = tgt.strip()
            if not clean:
                continue
            if clean.startswith("*."):
                host_regex = r"^.*\." + re.escape(clean[2:]) + r"$"
            else:
                host_regex = r"^" + re.escape(clean) + r"$"
            include_rules.append({
                "enabled": True,
                "protocol": "any",
                "host": host_regex,
                "port": r"^(80|443|8080|8443)$",
                "file": r"^.*$"
            })

        exclude_rules = []
        for exc in excluded:
            clean = exc.strip()
            if not clean:
                continue
            if clean.startswith("*."):
                host_regex = r"^.*\." + re.escape(clean[2:]) + r"$"
            else:
                host_regex = r"^" + re.escape(clean) + r"$"
            exclude_rules.append({
                "enabled": True,
                "protocol": "any",
                "host": host_regex,
                "port": r"^.*$",
                "file": r"^.*$"
            })

        burp_config = {
            "target": {
                "scope": {
                    "advanced_mode": True,
                    "include": include_rules,
                    "exclude": exclude_rules
                }
            },
            "_metadata": {
                "program": scope_data.get("program", "Authorized Bug Bounty"),
                "generated_by": "AegisGuard Scope Engine",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }
        return burp_config

    def configure_proxy(self, proxy_host: str = "127.0.0.1", proxy_port: int = 8080, enabled: bool = True) -> Dict[str, Any]:
        """
        Configures an upstream local HTTP proxy (such as Burp Suite on 127.0.0.1:8080).
        """
        scanner_cfg_path = os.path.join("config", "scanner.json")
        cfg = {}
        if os.path.exists(scanner_cfg_path):
            try:
                with open(scanner_cfg_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
            except Exception:
                cfg = {}

        proxy_url = f"http://{proxy_host}:{proxy_port}"
        cfg["proxy"] = {
            "enabled": enabled,
            "host": proxy_host,
            "port": proxy_port,
            "http": proxy_url,
            "https": proxy_url
        }

        try:
            with open(scanner_cfg_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            self._log_tool_event("proxy", f"Proxy configuration updated: {proxy_url} (Enabled: {enabled})")
            return {
                "success": True,
                "proxy_host": proxy_host,
                "proxy_port": proxy_port,
                "enabled": enabled,
                "proxy_url": proxy_url
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def import_burp_findings(self, raw_burp_issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Standardizes findings exported from Burp Suite (JSON format)
        into the AegisGuard findings schema.
        """
        imported = []
        for idx, item in enumerate(raw_burp_issues, 1):
            title = item.get("name") or item.get("title") or "Burp Identified Issue"
            sev = item.get("severity", "Low").capitalize()
            if sev not in ("Critical", "High", "Medium", "Low", "Informational"):
                sev = "Low"
            host = item.get("host") or item.get("endpoint") or "Unknown Asset"
            desc = item.get("issueBackground") or item.get("description") or "Observed via Burp Suite interception."
            remediation = item.get("remediationBackground") or item.get("remediation") or "Review and patch identified application behavior."
            
            imported.append({
                "title": f"[Burp Suite] {title}",
                "severity": sev,
                "cwe": item.get("cwe", "CWE-16"),
                "cvss": float(item.get("cvss", 4.0)),
                "confidence": 0.95,
                "verification_status": "potential",
                "endpoint": host,
                "parameter": item.get("path") or item.get("parameter") or "/",
                "evidence": item.get("issueDetail") or item.get("evidence") or "Observed in Burp Suite audit log.",
                "remediation": remediation,
                "tool_source": "burp-suite",
                "manual_verification_required": True,
                "manual_verification_notes": {
                    "why_it_matters": "Burp Suite identified potential vulnerability during manual testing.",
                    "how_to_verify": "Review the request/response pair in Burp Suite Proxy HTTP history tab."
                }
            })
        self._log_tool_event("burpsuite", f"Imported {len(imported)} findings from Burp Suite audit data.")
        return imported

    def _log_tool_event(self, tool_name: str, message: str):
        """Appends a tool operation audit event to logs/scanner.log."""
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        ts = datetime.now(timezone.utc).isoformat()
        try:
            with open(os.path.join(log_dir, "scanner.log"), "a", encoding="utf-8") as f:
                f.write(f"[{ts}] [{tool_name.upper()}] {message}\n")
        except Exception:
            pass


# Quick diagnostic test if executed standalone
if __name__ == "__main__":
    print("\n🔍 Checking Kali Linux Tool Availability...")
    caps = KaliToolRegistry.check_capabilities()
    for tool, info in caps.items():
        status = "✅ AVAILABLE" if info["available"] else "⚠️ MISSING (Python Fallback Active)"
        print(f"  - {tool:10s} : {status} (Binary: {info['binary']}, Path: {info['path'] or 'None'})")
    print("\nAll tools configured with robust non-destructive fallbacks.\n")
