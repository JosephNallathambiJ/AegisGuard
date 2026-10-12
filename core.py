"""
core.py - Bug-Bounty Scope-Aware Security Assessment Engine
Provides safe, non-destructive vulnerability and misconfiguration checks
for authorized bug-bounty programs and security assessments.
"""

import os
import json
import socket
import ssl
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
import requests

from report_generator import redact_sensitive_evidence
from scope_manager import ScopeManager
from rate_limiter import RateLimiter

def load_scanner_config() -> Dict[str, Any]:
    cfg_path = os.path.join("config", "scanner.json")
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

SCANNER_CONFIG = load_scanner_config()

DEFAULT_USER_AGENT = "AegisGuard/2.0 (Bug Bounty Security Assessment; Non-Destructive; RFC-9110)"
REQUEST_TIMEOUT = 8.0

METADATA_IPS = {
    "169.254.169.254",   # AWS / GCP / Azure metadata
    "100.100.100.200",   # Alibaba Cloud metadata
    "fd00:ec2::254",     # AWS IPv6 metadata
}

DISALLOWED_SCHEMES = {}
LOGS_DIR = "logs"


class SecurityFinding:
    """
    Standardized bug-bounty vulnerability and misconfiguration finding schema.
    Conforms to HackerOne/Bugcrowd submission standards.
    """
    def __init__(
        self,
        finding_id: str,
        title: str,
        severity: str,
        category: str,
        endpoint: str,
        description: str,
        evidence: str,
        impact: str,
        remediation: str,
        confidence: float = 0.90,
        cwe: str = "CWE-16",
        cvss: Optional[float] = 4.0,
        parameter: Optional[str] = None,
        references: Optional[List[str]] = None,
        verification_status: str = "potential",  # potential, confirmed, false_positive
        scope_status: str = "in_scope",
        manual_verification_required: bool = False,
        manual_verification_notes: Optional[Dict[str, str]] = None
    ):
        self.finding_id = finding_id
        self.title = title
        self.severity = severity  # Informational, Low, Medium, High, Critical
        self.category = category
        self.endpoint = endpoint
        self.description = description
        self.evidence = redact_sensitive_evidence(evidence)
        self.impact = impact
        self.remediation = remediation
        self.confidence = round(confidence, 2)
        self.cwe = cwe
        self.cvss = round(cvss, 1) if cvss is not None else None
        self.parameter = parameter
        self.references = references or []
        self.verification_status = verification_status
        self.scope_status = scope_status
        self.manual_verification_required = manual_verification_required
        self.manual_verification_notes = manual_verification_notes or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "evidence": self.evidence,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "references": self.references,
            "verification_status": self.verification_status,
            "scope_status": self.scope_status,
            "manual_verification_required": self.manual_verification_required,
            "manual_verification_notes": self.manual_verification_notes
        }


def log_audit_event(filename: str, message: str):
    """Appends operational event to logs directory."""
    import os
    os.makedirs(LOGS_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).isoformat()
    try:
        with open(os.path.join(LOGS_DIR, filename), "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {message}\n")
    except Exception:
        pass


def validate_and_sanitize_target(url_str: str, allow_local_lab: bool = False) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Validates and normalizes target URL with strict SSRF defenses.
    Enforces scheme constraints and blocks sensitive cloud metadata endpoints.
    """
    if not url_str or not isinstance(url_str, str):
        return False, "Target URL must be a non-empty string.", {}

    raw_url = url_str.strip()
    if not (raw_url.startswith("http://") or raw_url.startswith("https://")):
        raw_url = "https://" + raw_url

    parsed = urllib.parse.urlsplit(raw_url)

    if parsed.scheme.lower() in DISALLOWED_SCHEMES or parsed.scheme.lower() not in {"http", "https"}:
        return False, f"Unsupported or dangerous URI scheme: '{parsed.scheme}'", {}

    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid host in target URL.", {}

    # Reject cloud metadata hostnames
    if hostname in {"instance-data", "metadata.google.internal"} or "169.254.169.254" in hostname:
        return False, "Access to cloud instance metadata services is prohibited.", {}

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    try:
        addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ips = list({entry[4][0] for entry in addr_info})
    except socket.gaierror as e:
        return False, f"DNS resolution failed for host '{hostname}': {str(e)}", {}

    for ip in resolved_ips:
        if ip in METADATA_IPS:
            return False, f"Resolved IP {ip} is a restricted cloud metadata address.", {}
        if not allow_local_lab:
            if ip.startswith("127.") or ip.startswith("10.") or ip.startswith("192.168.") or ip == "::1":
                return False, f"Resolved internal IP {ip} is blocked (Local Lab profile required for internal testing).", {}

    normalized_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))

    metadata = {
        "hostname": hostname,
        "scheme": parsed.scheme,
        "port": port,
        "resolved_ips": resolved_ips,
        "path": parsed.path or "/"
    }
    return True, normalized_url, metadata


# ==============================================================================
# Security Check Modules
# ==============================================================================

def analyze_tls_configuration(hostname: str, port: int, endpoint: str) -> List[SecurityFinding]:
    """Safe, non-intrusive TLS/SSL certificate and cipher suite analysis."""
    findings: List[SecurityFinding] = []
    if port not in (443, 8443) and not endpoint.startswith("https"):
        return findings

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                version = ssock.version()
                cipher = ssock.cipher()
                cert = ssock.getpeercert(binary_form=False)

                if version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    findings.append(SecurityFinding(
                        finding_id="TLS-001",
                        title=f"Insecure Legacy TLS Protocol In Use: {version}",
                        severity="High",
                        category="TLS/SSL Analysis",
                        endpoint=endpoint,
                        description=f"Server negotiates legacy protocol {version}. Deprecated protocols are vulnerable to downgrade attacks and structural cryptographic weaknesses (BEAST, POODLE).",
                        evidence=f"Negotiated Protocol: {version}\nCipher Suite: {cipher[0] if cipher else 'Unknown'}",
                        impact="Adversaries on local networks could perform cryptographic downgrade attacks or intercept sensitive session data.",
                        remediation="Disable TLS 1.0 and TLS 1.1 on load balancers and web servers. Enforce TLS 1.2 and TLS 1.3.",
                        confidence=0.98,
                        cwe="CWE-326",
                        cvss=7.4,
                        references=["https://datatracker.ietf.org/doc/rfc8996/"],
                        verification_status="confirmed",
                        manual_verification_required=True,
                        manual_verification_notes={
                            "why_it_matters": "Bug bounty programs prioritize protocol downgrades when modern ciphers are disabled.",
                            "how_to_verify": f"Run 'openssl s_client -connect {hostname}:{port} -tls1' to confirm handshake succeeds.",
                            "rule_check": "Ensure program rules permit TLS configuration testing without DoS."
                        }
                    ))

                if cert and "notAfter" in cert:
                    try:
                        expire_str = cert["notAfter"]
                        expire_date = datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_remaining = (expire_date - datetime.now(timezone.utc)).days
                        if days_remaining < 0:
                            findings.append(SecurityFinding(
                                finding_id="TLS-002",
                                title="Expired SSL/TLS Certificate",
                                severity="High",
                                category="TLS/SSL Analysis",
                                endpoint=endpoint,
                                description=f"The server certificate expired {abs(days_remaining)} days ago on {expire_str}.",
                                evidence=f"Certificate Expiration: {expire_str} ({days_remaining} days remaining)",
                                impact="Browsers display prominent security warnings, eroding client trust and leaving users susceptible to man-in-the-middle attacks.",
                                remediation="Renew and install a valid X.509 certificate immediately.",
                                confidence=0.99,
                                cwe="CWE-295",
                                cvss=7.5,
                                references=["https://cwe.mitre.org/data/definitions/295.html"],
                                verification_status="confirmed"
                            ))
                        elif days_remaining < 21:
                            findings.append(SecurityFinding(
                                finding_id="TLS-003",
                                title="SSL/TLS Certificate Expiring Soon",
                                severity="Low",
                                category="TLS/SSL Analysis",
                                endpoint=endpoint,
                                description=f"The certificate will expire in {days_remaining} days ({expire_str}).",
                                evidence=f"Days Remaining: {days_remaining}\nValid Until: {expire_str}",
                                impact="Unscheduled certificate expiration causes service disruption and SSL connection failures.",
                                remediation="Schedule automatic renewal before expiration.",
                                confidence=0.95,
                                cwe="CWE-295",
                                cvss=3.5,
                                verification_status="confirmed"
                            ))
                    except Exception:
                        pass
    except Exception:
        pass

    return findings


def analyze_security_headers(headers: Dict[str, str], scheme: str, endpoint: str) -> List[SecurityFinding]:
    """Inspects response headers for missing or weak security configurations."""
    findings: List[SecurityFinding] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    # 1. HSTS
    if scheme == "https":
        if "strict-transport-security" not in lower_headers:
            findings.append(SecurityFinding(
                finding_id="HDR-001",
                title="Missing Strict-Transport-Security (HSTS) Header",
                severity="Medium",
                category="Security Headers",
                endpoint=endpoint,
                description="Strict-Transport-Security (HSTS) enforces HTTPS connections for modern browsers, protecting users against SSL-stripping and man-in-the-middle attacks.",
                evidence="HTTP Response Headers:\n" + "\n".join([f"{k}: {v}" for k, v in headers.items() if k.lower() in ("server", "date", "content-type")]),
                impact="Users visiting the site over insecure public Wi-Fi can have their initial plaintext HTTP request intercepted before redirection.",
                remediation="Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                confidence=0.96,
                cwe="CWE-319",
                cvss=5.4,
                references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"],
                verification_status="confirmed"
            ))

    # 2. Content-Security-Policy
    if "content-security-policy" not in lower_headers:
        findings.append(SecurityFinding(
            finding_id="HDR-002",
            title="Missing Content-Security-Policy (CSP)",
            severity="Medium",
            category="Security Headers",
            endpoint=endpoint,
            description="Content Security Policy helps detect and mitigate Cross-Site Scripting (XSS), data injection, and unauthorized frame embedding.",
            evidence="Header 'Content-Security-Policy' was absent in the HTTP response.",
            impact="Increases vulnerability to stored/reflected XSS and unauthorized malicious script execution.",
            remediation="Define a restrictive Content-Security-Policy, e.g.: default-src 'self'; script-src 'self'; object-src 'none';",
            confidence=0.94,
            cwe="CWE-1021",
            cvss=6.1,
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
            verification_status="confirmed"
        ))

    # 3. X-Frame-Options
    if "x-frame-options" not in lower_headers and "content-security-policy" not in lower_headers:
        findings.append(SecurityFinding(
            finding_id="HDR-003",
            title="Missing X-Frame-Options (Clickjacking Protection)",
            severity="Low",
            category="Security Headers",
            endpoint=endpoint,
            description="The X-Frame-Options header indicates whether a browser should be allowed to render a page in a <frame>, <iframe>, or <embed>.",
            evidence="Header 'X-Frame-Options' not defined in HTTP response.",
            impact="Adversaries could frame the endpoint on a malicious site and perform UI redress / clickjacking attacks.",
            remediation="Set: X-Frame-Options: DENY (or SAMEORIGIN).",
            confidence=0.92,
            cwe="CWE-1021",
            cvss=4.3,
            references=["https://owasp.org/www-community/attacks/Clickjacking"],
            verification_status="confirmed"
        ))

    # 4. X-Content-Type-Options
    xcto = lower_headers.get("x-content-type-options", "").lower()
    if "nosniff" not in xcto:
        findings.append(SecurityFinding(
            finding_id="HDR-004",
            title="Missing or Weak X-Content-Type-Options Header",
            severity="Low",
            category="Security Headers",
            endpoint=endpoint,
            description="Lacks 'nosniff' directive, allowing browsers to MIME-sniff response bodies and execute malicious payloads masquerading as static files.",
            evidence=f"X-Content-Type-Options: {xcto or 'Header Absent'}",
            impact="Increases risk of drive-by download attacks and XSS via uploaded files served with generic MIME types.",
            remediation="Set: X-Content-Type-Options: nosniff on all responses.",
            confidence=0.95,
            cwe="CWE-16",
            cvss=3.7,
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"],
            verification_status="confirmed"
        ))

    # 5. Referrer-Policy
    if "referrer-policy" not in lower_headers:
        findings.append(SecurityFinding(
            finding_id="HDR-005",
            title="Missing Referrer-Policy Header",
            severity="Informational",
            category="Security Headers",
            endpoint=endpoint,
            description="Controls how much referrer information is sent along with requests, preventing URI token and query parameter leakage.",
            evidence="Header 'Referrer-Policy' not defined.",
            impact="Sensitive query string parameters (session tokens, email addresses) may leak to external domains in the HTTP Referer header.",
            remediation="Set: Referrer-Policy: strict-origin-when-cross-origin",
            confidence=0.90,
            cwe="CWE-200",
            cvss=2.0,
            verification_status="potential"
        ))

    return findings


def analyze_cookie_security(cookies: requests.cookies.RequestsCookieJar, raw_headers: Dict[str, str], endpoint: str) -> List[SecurityFinding]:
    """Evaluates cookie security attributes (Secure, HttpOnly, SameSite)."""
    findings: List[SecurityFinding] = []

    set_cookie_headers = [v for k, v in raw_headers.items() if k.lower() == "set-cookie"]

    for cookie in cookies:
        cookie_name = cookie.name
        is_secure = cookie.secure
        is_httponly = bool(cookie.has_nonstandard_attr("httponly") or "httponly" in cookie._rest.keys())
        samesite = cookie.get_nonstandard_attr("samesite")

        for raw in set_cookie_headers:
            if cookie_name in raw:
                raw_lower = raw.lower()
                if "httponly" in raw_lower: is_httponly = True
                if "secure" in raw_lower: is_secure = True
                if "samesite=strict" in raw_lower: samesite = "Strict"
                elif "samesite=lax" in raw_lower: samesite = "Lax"
                elif "samesite=none" in raw_lower: samesite = "None"

        if not is_secure:
            findings.append(SecurityFinding(
                finding_id=f"CK-001-{cookie_name}",
                title=f"Cookie Without Secure Attribute: '{cookie_name}'",
                severity="Medium",
                category="Cookie Security",
                endpoint=endpoint,
                parameter=cookie_name,
                description=f"The cookie '{cookie_name}' lacks the 'Secure' flag, allowing it to be transmitted unencrypted over cleartext HTTP.",
                evidence=f"Cookie: {cookie_name}; Domain: {cookie.domain}; Secure: False",
                impact="Network eavesdroppers can capture the cookie over unencrypted HTTP requests.",
                remediation=f"Add '; Secure' attribute to Set-Cookie directive for '{cookie_name}'.",
                confidence=0.95,
                cwe="CWE-614",
                cvss=5.3,
                references=["https://owasp.org/www-community/controls/SecureFlag"],
                verification_status="confirmed"
            ))

        if not is_httponly:
            findings.append(SecurityFinding(
                finding_id=f"CK-002-{cookie_name}",
                title=f"Cookie Without HttpOnly Attribute: '{cookie_name}'",
                severity="Medium",
                category="Cookie Security",
                endpoint=endpoint,
                parameter=cookie_name,
                description=f"The cookie '{cookie_name}' lacks 'HttpOnly', allowing client-side JavaScript access via document.cookie.",
                evidence=f"Cookie: {cookie_name}; HttpOnly: False",
                impact="If an XSS vulnerability exists anywhere on the domain, session cookies can be stolen by script injection.",
                remediation=f"Add '; HttpOnly' to the Set-Cookie header for '{cookie_name}'.",
                confidence=0.92,
                cwe="CWE-1004",
                cvss=5.0,
                references=["https://owasp.org/www-community/HttpOnly"],
                verification_status="confirmed"
            ))

        if not samesite:
            findings.append(SecurityFinding(
                finding_id=f"CK-003-{cookie_name}",
                title=f"Cookie Missing SameSite Attribute: '{cookie_name}'",
                severity="Low",
                category="Cookie Security",
                endpoint=endpoint,
                parameter=cookie_name,
                description=f"The cookie '{cookie_name}' does not specify a SameSite policy, increasing susceptibility to Cross-Site Request Forgery (CSRF).",
                evidence=f"Cookie: {cookie_name}; SameSite: Not Specified",
                impact="Browsers may send the cookie along with cross-site top-level navigations or API requests.",
                remediation=f"Set SameSite=Lax or SameSite=Strict for '{cookie_name}'.",
                confidence=0.90,
                cwe="CWE-1275",
                cvss=4.2,
                verification_status="confirmed"
            ))

    return findings


def analyze_cors_configuration(target_url: str, session: requests.Session, rate_limiter: RateLimiter) -> List[SecurityFinding]:
    """Safe, non-destructive probe to check for insecure CORS configurations."""
    findings: List[SecurityFinding] = []
    test_origin = "https://audit-security-test.example.org"

    try:
        if not rate_limiter.acquire():
            return findings

        resp = session.options(
            target_url,
            headers={"Origin": test_origin, "Access-Control-Request-Method": "GET"},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False
        )
        headers = {k.lower(): v for k, v in resp.headers.items()}
        allow_origin = headers.get("access-control-allow-origin", "")
        allow_credentials = headers.get("access-control-allow-credentials", "").lower() == "true"

        if allow_origin == "*":
            findings.append(SecurityFinding(
                finding_id="CORS-001",
                title="CORS Wildcard (*) Origin Configured",
                severity="Low",
                category="CORS Misconfiguration",
                endpoint=target_url,
                description="The server returns 'Access-Control-Allow-Origin: *', allowing any arbitrary domain to access this resource via XMLHttpRequest or fetch.",
                evidence=f"Access-Control-Allow-Origin: {allow_origin}",
                impact="If sensitive or private data is returned by this endpoint, external sites can read response contents.",
                remediation="If this endpoint handles private or authenticated data, specify exact authorized origin domains instead of wildcard.",
                confidence=0.93,
                cwe="CWE-942",
                cvss=3.5,
                verification_status="potential"
            ))

        if allow_origin == test_origin and allow_credentials:
            findings.append(SecurityFinding(
                finding_id="CORS-002",
                title="Insecure CORS Origin Reflection with Credentials Enabled",
                severity="High",
                category="CORS Misconfiguration",
                endpoint=target_url,
                description="The server dynamically reflects untrusted third-party Origin headers and enables Access-Control-Allow-Credentials: true. This allows unauthorized cross-origin reading of authenticated session data.",
                evidence=f"Origin Sent: {test_origin}\nReflected Access-Control-Allow-Origin: {allow_origin}\nAccess-Control-Allow-Credentials: true",
                impact="An attacker hosting an external website can read authenticated user data or trigger sensitive cross-origin API actions.",
                remediation="Maintain an explicit whitelist of trusted origins and do not reflect arbitrary client Origin headers when credentials are true.",
                confidence=0.98,
                cwe="CWE-942",
                cvss=7.8,
                references=["https://portswigger.net/web-security/cors"],
                verification_status="potential",
                manual_verification_required=True,
                manual_verification_notes={
                    "why_it_matters": "High-severity bug bounty finding if authenticated session data is returned.",
                    "how_to_verify": "Send a non-destructive curl command with a custom Origin header while observing Access-Control-Allow-Credentials.",
                    "rule_check": "Verify that CORS testing does not violate program data-extraction policies."
                }
            ))
    except Exception:
        pass

    return findings


def analyze_http_methods(target_url: str, session: requests.Session, rate_limiter: RateLimiter) -> List[SecurityFinding]:
    """Non-destructive detection of permitted HTTP methods via OPTIONS probe."""
    findings: List[SecurityFinding] = []

    try:
        if not rate_limiter.acquire():
            return findings

        resp = session.options(target_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        allow_header = resp.headers.get("allow") or resp.headers.get("Allow") or ""
        allowed_methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]

        dangerous_methods = {"TRACE", "TRACK"}
        for method in dangerous_methods:
            if method in allowed_methods:
                findings.append(SecurityFinding(
                    finding_id="MTHD-001",
                    title=f"Insecure HTTP Method Enabled: {method}",
                    severity="Medium",
                    category="HTTP Methods",
                    endpoint=target_url,
                    description=f"Method {method} is supported. In the presence of XSS, TRACE can facilitate Cross-Site Tracing (XST) to steal HttpOnly cookies.",
                    evidence=f"Allow Header: {allow_header}",
                    impact="Enables cross-site tracing techniques to bypass HttpOnly cookie protections in certain browser configurations.",
                    remediation=f"Disable the {method} method in web server configuration.",
                    confidence=0.97,
                    cwe="CWE-749",
                    cvss=5.0,
                    verification_status="confirmed"
                ))

        if "PUT" in allowed_methods or "DELETE" in allowed_methods:
            findings.append(SecurityFinding(
                finding_id="MTHD-002",
                title="State-Modifying HTTP Methods (PUT/DELETE) Advertised",
                severity="Low",
                category="HTTP Methods",
                endpoint=target_url,
                description="The OPTIONS response advertises state-altering verbs (PUT/DELETE). Ensure these endpoints are protected with strict authentication and CSRF tokens.",
                evidence=f"Allow Header: {allow_header}",
                impact="Potential unauthorized modification or deletion of resources if authentication is misconfigured.",
                remediation="Ensure PUT/DELETE verbs require appropriate authentication and permission checks.",
                confidence=0.88,
                cwe="CWE-650",
                cvss=3.8,
                verification_status="potential"
            ))
    except Exception:
        pass

    return findings


def analyze_redirect_behavior(
    target_url: str,
    session: requests.Session,
    rate_limiter: RateLimiter,
    scope_manager: ScopeManager
) -> Tuple[List[SecurityFinding], int]:
    """Examines HTTP to HTTPS redirection and checks for out-of-scope redirects."""
    findings: List[SecurityFinding] = []
    blocked_count = 0
    parsed = urllib.parse.urlsplit(target_url)

    if parsed.scheme == "https":
        http_url = urllib.parse.urlunsplit(("http", parsed.netloc, parsed.path or "/", parsed.query, ""))
        try:
            if rate_limiter.acquire():
                resp = session.get(http_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
                if resp.status_code in (301, 302, 307, 308):
                    loc = resp.headers.get("location", "")
                    in_scope, reason = scope_manager.is_redirect_in_scope(http_url, loc)
                    if not in_scope:
                        blocked_count += 1
                        findings.append(SecurityFinding(
                            finding_id="RED-002",
                            title="Out-of-Scope Redirect Blocked by Scope Engine",
                            severity="Informational",
                            category="Redirect Analysis",
                            endpoint=http_url,
                            description=f"HTTP redirection pointed to an out-of-scope host: '{loc}'. AegisGuard halted automated navigation to preserve program boundaries.",
                            evidence=f"Location Header: {loc}\nScope Decision: Blocked",
                            impact="Automated scanners without scope controls could inadvertently attack unauthorized third-party infrastructure.",
                            remediation="Ensure redirection targets stay within authorized corporate domains.",
                            confidence=0.99,
                            cwe="CWE-601",
                            cvss=0.0,
                            verification_status="confirmed"
                        ))
                else:
                    findings.append(SecurityFinding(
                        finding_id="RED-001",
                        title="Plaintext HTTP Does Not Automatically Redirect to HTTPS",
                        severity="Medium",
                        category="Redirect Analysis",
                        endpoint=http_url,
                        description=f"Plaintext requests to {http_url} returned HTTP {resp.status_code} rather than a 301/308 redirect to HTTPS.",
                        evidence=f"HTTP status code: {resp.status_code} for plaintext request.",
                        impact="Users inadvertently accessing the site via HTTP will transmit credentials and session data in the clear.",
                        remediation="Configure the web server to enforce an immediate permanent redirect (301) from HTTP to HTTPS.",
                        confidence=0.94,
                        cwe="CWE-311",
                        cvss=4.8,
                        verification_status="confirmed"
                    ))
        except Exception:
            pass

    return findings, blocked_count


def analyze_information_disclosure(
    headers: Dict[str, str],
    body_text: str,
    base_url: str,
    session: requests.Session,
    rate_limiter: RateLimiter
) -> List[SecurityFinding]:
    """Identifies version leakage, framework banners, and sensitive passive paths."""
    findings: List[SecurityFinding] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    # 1. Server header disclosure
    server_val = lower_headers.get("server", "")
    if server_val:
        has_version = bool(re.search(r"\d+\.\d+", server_val))
        findings.append(SecurityFinding(
            finding_id="DISC-001",
            title=f"Server Banner Version Disclosure: '{server_val}'",
            severity="Low" if has_version else "Informational",
            category="Information Disclosure",
            endpoint=base_url,
            description="The Server response header discloses specific web server software and version numbers, aiding threat reconnaissance.",
            evidence=f"Server: {server_val}",
            impact="Adversaries can tailor specific CVE search queries against the revealed server release.",
            remediation="Suppress or genericize the Server header in web server configuration (e.g. ServerTokens Prod).",
            confidence=0.96,
            cwe="CWE-200",
            cvss=4.0 if has_version else 2.0,
            verification_status="confirmed"
        ))

    # 2. X-Powered-By / X-AspNet-Version
    for flag_hdr in ("x-powered-by", "x-aspnet-version", "x-generator"):
        if flag_hdr in lower_headers:
            val = lower_headers[flag_hdr]
            findings.append(SecurityFinding(
                finding_id=f"DISC-002-{flag_hdr}",
                title=f"Backend Technology Banner Disclosed: '{flag_hdr}: {val}'",
                severity="Low",
                category="Information Disclosure",
                endpoint=base_url,
                description=f"The header '{flag_hdr}' advertises the underlying runtime or CMS framework.",
                evidence=f"{flag_hdr}: {val}",
                impact="Aids targeted reconnaissance of backend frameworks and known version vulnerabilities.",
                remediation=f"Disable the '{flag_hdr}' header in application configuration or reverse proxy.",
                confidence=0.95,
                cwe="CWE-200",
                cvss=3.8,
                verification_status="confirmed"
            ))

    # 3. Passive check of robots.txt for sensitive paths
    parsed = urllib.parse.urlsplit(base_url)
    robots_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/robots.txt", "", ""))
    try:
        if rate_limiter.acquire():
            r_resp = session.get(robots_url, timeout=REQUEST_TIMEOUT)
            if r_resp.status_code == 200 and "disallow" in r_resp.text.lower():
                disallowed_entries = re.findall(r"Disallow:\s*([^\r\n]+)", r_resp.text, re.IGNORECASE)
                sensitive_keywords = ["admin", "login", "internal", "config", "backup", "secret", "private"]
                leaked_paths = [p.strip() for p in disallowed_entries if any(k in p.lower() for k in sensitive_keywords)]
                if leaked_paths:
                    findings.append(SecurityFinding(
                        finding_id="DISC-003",
                        title="Sensitive Administrative Paths Disclosed in robots.txt",
                        severity="Informational",
                        category="Information Disclosure",
                        endpoint=robots_url,
                        description="Robots.txt lists disallowed routes that hint at sensitive administrative or internal interfaces to passive search engines.",
                        evidence=f"Highlighted Disallow rules:\n" + "\n".join(leaked_paths[:4]),
                        impact="Assists bug-bounty researchers and attackers in discovering unlinked internal administrative interfaces.",
                        remediation="Ensure sensitive endpoints are safeguarded by strong authentication, not reliant on robots.txt obscurity.",
                        confidence=0.91,
                        cwe="CWE-200",
                        cvss=2.5,
                        verification_status="potential"
                    ))
    except Exception:
        pass

    return findings


def analyze_safe_owasp_indicators(body_text: str, status_code: int, endpoint: str) -> List[SecurityFinding]:
    """Safe, non-destructive detection of stack traces and diagnostic leakage."""
    findings: List[SecurityFinding] = []

    patterns = [
        (r"(Exception in thread|Traceback \(most recent call last\):)", "Python Traceback / Debug Disclosure", "High", 7.0),
        (r"(Fatal error:.*on line \d+|Warning:.*in /var/www/)", "PHP Internal Diagnostic Error Leakage", "Medium", 6.0),
        (r"(java\.lang\.[A-Za-z]+Exception|org\.springframework\.)", "Java Stack Trace Disclosure", "Medium", 6.2),
        (r"(Microsoft OLE DB Provider for SQL Server|SQLSTATE\[[0-9A-Z]+\])", "Database Diagnostic Message Leakage", "High", 7.5),
        (r"(Django Version:\s*\d+\.\d+|DEBUG = True)", "Django Debug Mode Enabled", "High", 7.2)
    ]

    for regex, title, sev, cvss in patterns:
        match = re.search(regex, body_text)
        if match:
            snippet = match.group(0)[:80]
            findings.append(SecurityFinding(
                finding_id="OWASP-001",
                title=title,
                severity=sev,
                category="Error Handling",
                endpoint=endpoint,
                description="Application responses contain unhandled exception traces or internal database diagnostics, aiding attack surface mapping.",
                evidence=f"Matched diagnostic signature: '{snippet}'",
                impact="Discloses internal source file paths, database architectures, and variable values to unauthorized observers.",
                remediation="Disable debug modes in production. Implement global error handlers returning generic status pages.",
                confidence=0.96,
                cwe="CWE-209",
                cvss=cvss,
                verification_status="potential",
                manual_verification_required=True,
                manual_verification_notes={
                    "why_it_matters": "Information disclosure reports in bug bounties often qualify for rewards if database structures or internal logic is leaked.",
                    "how_to_verify": "Reproduce the request with curl or browser to confirm debug messages are publicly returned.",
                    "rule_check": "Do not attempt destructive exploitation or SQL injection on the leaking endpoint."
                }
            ))
            break

    return findings


def detect_technology_stack(headers: Dict[str, str], body_text: str) -> Dict[str, List[str]]:
    """Passive fingerprinting of server software, frameworks, and CMS."""
    tech: Dict[str, List[str]] = {
        "web_servers": [],
        "frameworks": [],
        "languages": []
    }
    lower_headers = {k.lower(): v for k, v in headers.items()}
    lower_body = body_text.lower()

    server = lower_headers.get("server", "").lower()
    if "nginx" in server: tech["web_servers"].append("Nginx")
    if "apache" in server: tech["web_servers"].append("Apache")
    if "caddy" in server: tech["web_servers"].append("Caddy")
    if "cloudflare" in server: tech["web_servers"].append("Cloudflare Proxy")

    powered = lower_headers.get("x-powered-by", "").lower()
    if "php" in powered or "php" in lower_body: tech["languages"].append("PHP")
    if "express" in powered: tech["frameworks"].append("Express.js (Node.js)")
    if "asp.net" in powered: tech["frameworks"].append("ASP.NET")
    if "next.js" in powered or "__next" in lower_body: tech["frameworks"].append("Next.js")
    if "react" in lower_body or "data-reactroot" in lower_body: tech["frameworks"].append("React")
    if "wp-content" in lower_body: tech["frameworks"].append("WordPress CMS")

    return {k: list(set(v)) for k, v in tech.items()}


# ==============================================================================
# Qwen3 Local LLM Bug-Bounty Analysis Assistant
# ==============================================================================

class QwenAnalysisEngine:
    """
    Local LLM analysis assistant for bug-bounty researchers.
    Integrates locally running Qwen3 models (via Ollama or custom API) to produce:
    - Executive summary
    - Impact analysis
    - Remediation roadmap
    - Bug-bounty report draft
    - Chain-of-thought verification trace
    """
    def __init__(
        self,
        ollama_url: str = "http://localhost:11434/api/generate",
        model_name: str = "qwen3:latest",
        timeout_seconds: int = 65
    ):
        self.ollama_url = ollama_url
        self.model_name = model_name
        self.timeout_seconds = timeout_seconds
        self.detect_available_model()

    def detect_available_model(self):
        """Auto-detects available models from Ollama to ensure qwen3:latest is used if present."""
        try:
            tags_url = self.ollama_url.replace("/api/generate", "/api/tags")
            res = requests.get(tags_url, timeout=2.0)
            if res.status_code == 200:
                models_info = res.json().get("models", [])
                available_names = [m.get("name") for m in models_info if m.get("name")]
                # Prioritize qwen3:latest if installed
                for candidate in ["qwen3:latest", "qwen3", "qwen2.5-coder:latest", "qwen2.5:7b", "qwen2.5:3b"]:
                    if candidate in available_names:
                        self.model_name = candidate
                        break
        except Exception:
            pass

    def is_available(self) -> bool:
        """Checks if local Ollama service is responding."""
        try:
            resp = requests.get(self.ollama_url.replace("/api/generate", "/api/tags"), timeout=1.5)
            return resp.status_code == 200
        except Exception:
            return False

    def generate_findings_analysis(self, target_url: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Synthesizes high-level remediation and risk narrative under strict safety boundaries."""
        if not findings:
            return {
                "executive_summary": f"Clean security posture observed for {target_url}. Zero vulnerabilities or misconfigurations detected during non-destructive assessment.",
                "risk_prioritization": "Low overall risk profile.",
                "remediation_roadmap": ["Maintain continuous dependency scanning and SSL/TLS certificate renewal vigilance."],
                "bug_bounty_draft": "No reproducible vulnerabilities identified.",
                "llm_engine_used": "Deterministic Defensive Intelligence Engine"
            }

        findings_summary_text = "\n".join([
            f"- [{f.get('severity')}] {f.get('title')} (CWE: {f.get('cwe')}, Status: {f.get('verification_status')})"
            for f in findings[:15]
        ])

        system_boundary = (
            "You are a professional defensive bug-bounty security assistant.\n"
            "Be direct, concise, and structured. Avoid lengthy internal reasoning.\n"
            "Do not generate instructions for bypassing security controls, credential attacks,\n"
            "destructive exploitation, persistence, or stealth.\n"
            "Focus on interpreting evidence and producing responsible remediation."
        )

        prompt = (
            f"Authorized Target: {target_url}\n"
            f"Verified Findings:\n{findings_summary_text}\n\n"
            "Directly provide:\n"
            "1. An executive summary of the target's defensive posture.\n"
            "2. Security impact analysis.\n"
            "3. Prioritized remediation roadmap.\n"
            "4. Professional Bug Bounty Submission Draft for the top finding."
        )

        try:
            payload = {
                "model": self.model_name,
                "system": system_boundary,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "num_predict": 500
                }
            }
            res = requests.post(self.ollama_url, json=payload, timeout=self.timeout_seconds)
            if res.status_code == 200:
                res_data = res.json()
                raw_text = res_data.get("response", "").strip()
                thinking_text = res_data.get("thinking", "").strip()

                # If response was absorbed into thinking block, extract it
                if not raw_text and thinking_text:
                    raw_text = thinking_text

                return {
                    "executive_summary": raw_text[:400] + "..." if len(raw_text) > 400 else raw_text,
                    "risk_prioritization": f"Synthesized via local {self.model_name} model inference.",
                    "remediation_roadmap": [
                        "Review and implement specific headers identified by Qwen3.",
                        "Harden cookie flags and CORS directives across all origin endpoints.",
                        "Enforce TLS 1.2+ and renew expiring certificates."
                    ],
                    "bug_bounty_draft": raw_text,
                    "qwen3_reasoning_trace": thinking_text[:500] + "..." if thinking_text else "",
                    "llm_engine_used": f"Local Ollama ({self.model_name})"
                }
        except Exception as e:
            print(f"[core.py] Qwen3 inference notice (falling back to defensive heuristics): {e}")

        # Robust Heuristic Defensive Analysis Engine (Reliable fallback)
        sev_counts = {}
        for f in findings:
            sev = f.get("severity", "Informational")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        high_or_crit = sev_counts.get("Critical", 0) + sev_counts.get("High", 0)
        risk_level = "Elevated" if high_or_crit > 0 else ("Moderate" if sev_counts.get("Medium", 0) > 0 else "Low")

        roadmap = []
        if any(f.get("category") == "TLS/SSL Analysis" for f in findings):
            roadmap.append("1. Upgrade TLS configuration to support TLS 1.2+ and renew near-expiry certificates.")
        if any(f.get("category") == "Security Headers" for f in findings):
            roadmap.append("2. Implement defense-in-depth HTTP headers (Strict-Transport-Security, CSP, X-Content-Type-Options: nosniff).")
        if any(f.get("category") == "Cookie Security" for f in findings):
            roadmap.append("3. Enforce 'Secure', 'HttpOnly', and 'SameSite=Lax' flags on all session and application state cookies.")
        if any(f.get("category") == "CORS Misconfiguration" for f in findings):
            roadmap.append("4. Restrict CORS access to authorized origins; eliminate wildcard (*) reflection with credentials.")
        if any(f.get("category") == "Information Disclosure" for f in findings):
            roadmap.append("5. Remove server banners and runtime versions in proxy configuration to minimize footprint.")

        if not roadmap:
            roadmap.append("Maintain routine defensive audits and scheduled vulnerability monitoring.")

        top_finding = findings[0]
        draft = (
            f"**Title:** {top_finding.get('title', 'Security Finding')}\n"
            f"**Severity:** {top_finding.get('severity', 'Low')}\n"
            f"**Vulnerability Type:** {top_finding.get('cwe', 'CWE-16')}\n"
            f"**Target Asset:** {top_finding.get('endpoint', target_url)}\n\n"
            f"**Description:**\n{top_finding.get('description', 'Configuration weakness observed.')}\n\n"
            f"**Evidence:**\n```\n{top_finding.get('evidence', 'No raw evidence.')}\n```\n\n"
            f"**Remediation:**\n{top_finding.get('remediation', 'Implement recommended defense-in-depth hardening.')}"
        )

        return {
            "executive_summary": (
                f"Authorized assessment for {target_url} identified {len(findings)} security observations "
                f"({sev_counts.get('Critical', 0)} Critical, {sev_counts.get('High', 0)} High, "
                f"{sev_counts.get('Medium', 0)} Medium, {sev_counts.get('Low', 0)} Low). "
                f"Overall security posture indicates a {risk_level.lower()} risk posture requiring standard hardening."
            ),
            "risk_prioritization": f"{risk_level} Priority - Address high-impact cryptographic and session configurations first.",
            "remediation_roadmap": roadmap,
            "bug_bounty_draft": draft,
            "llm_engine_used": "Deterministic Defensive Intelligence Engine (Qwen3 offline fallback)"
        }


# ==============================================================================
# Master Scanner Pipeline
# ==============================================================================

def execute_security_scan(
    target_url: str,
    policy_profile: str = "Bug Bounty Standard",
    scope_manager: Optional[ScopeManager] = None,
    rate_limiter: Optional[RateLimiter] = None
) -> Dict[str, Any]:
    """
    Executes an end-to-end scope-aware, rate-limited non-destructive security audit.
    """
    start_time = datetime.now(timezone.utc)

    if scope_manager is None:
        scope_manager = ScopeManager()

    if rate_limiter is None:
        rate_limiter = RateLimiter(requests_per_second=2.0)

    # 1. Scope & Target Validation Pipeline
    is_valid, sanitized_url, meta = scope_manager.validate_target_url(target_url, policy_profile=policy_profile)
    if not is_valid:
        log_audit_event("scanner.log", f"[VALIDATION_FAIL] Target '{target_url}' rejected: {sanitized_url}")
        return {
            "success": False,
            "error": sanitized_url,
            "findings": [],
            "metadata": {}
        }

    # Reset rate limiter telemetry for this target
    rate_limiter.reset_for_target(meta["hostname"], rps=meta.get("max_rps", 2.0))
    log_audit_event("scanner.log", f"[SCAN_START] Target: {sanitized_url} | Policy: {policy_profile} | Rate: {rate_limiter.requests_per_second} req/s")

    # Fetch policy profile permissions
    profile_data = scope_manager.get_policies().get(policy_profile, {})
    permitted_checks = profile_data.get("checks", [
        "tls_inspection", "security_headers", "cookie_attributes",
        "cors_configuration", "http_methods_options", "redirect_behavior",
        "server_banners", "tech_fingerprint", "passive_error_leakage"
    ])

    findings: List[SecurityFinding] = []
    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

    # Optional local proxy routing (e.g. Burp Suite 127.0.0.1:8080)
    current_scanner_cfg = load_scanner_config()
    proxy_cfg = current_scanner_cfg.get("proxy", {})
    if proxy_cfg.get("enabled"):
        p_http = proxy_cfg.get("http", "http://127.0.0.1:8080")
        p_https = proxy_cfg.get("https", "http://127.0.0.1:8080")
        session.proxies.update({"http": p_http, "https": p_https})
        session.verify = False

    # Primary Request
    response_headers: Dict[str, str] = {}
    response_body: str = ""
    status_code: int = 0
    blocked_redirects_count = 0

    try:
        if not rate_limiter.acquire():
            return {"success": False, "error": "Request ceiling reached for target host.", "findings": [], "metadata": meta}

        # Check for redirects manually to enforce scope
        resp = session.get(sanitized_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
        status_code = resp.status_code

        # If redirected, verify in-scope destination
        if resp.status_code in (301, 302, 307, 308) and "location" in resp.headers:
            dest_loc = resp.headers["location"]
            in_scope, dest_url = scope_manager.is_redirect_in_scope(sanitized_url, dest_loc)
            if not in_scope:
                blocked_redirects_count += 1
                findings.append(SecurityFinding(
                    finding_id="RED-SCOPE-001",
                    title="Out-of-Scope Initial Redirect Blocked",
                    severity="Informational",
                    category="Redirect Analysis",
                    endpoint=sanitized_url,
                    description=f"Target redirected to '{dest_loc}', which is outside authorized program scope.",
                    evidence=f"Redirect Status: {resp.status_code}\nLocation: {dest_loc}\nAction: Navigation Halted",
                    impact="Prevents automated testing against unauthorized third-party infrastructure.",
                    remediation="Ensure program scope targets match application production endpoints.",
                    confidence=0.99,
                    verification_status="confirmed"
                ))
            else:
                # Follow redirect safely
                if rate_limiter.acquire():
                    resp = session.get(dest_url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
                    status_code = resp.status_code

        response_headers = dict(resp.headers)
        response_body = resp.text
        cookies = resp.cookies
    except Exception as e:
        log_audit_event("scanner.log", f"[CONNECT_ERROR] Target: {sanitized_url} | Error: {str(e)}")
        return {
            "success": False,
            "error": f"Failed to connect to target {sanitized_url}: {str(e)}",
            "findings": [],
            "metadata": meta
        }

    # 2. TLS/SSL Inspection
    if "tls_inspection" in permitted_checks:
        tls_findings = analyze_tls_configuration(meta["hostname"], meta["port"], sanitized_url)
        findings.extend(tls_findings)

    # 3. Security Headers
    if "security_headers" in permitted_checks:
        hdr_findings = analyze_security_headers(response_headers, meta["scheme"], sanitized_url)
        findings.extend(hdr_findings)

    # 4. Cookie Attributes
    if "cookie_attributes" in permitted_checks:
        cookie_findings = analyze_cookie_security(cookies, response_headers, sanitized_url)
        findings.extend(cookie_findings)

    # 5. CORS Analysis
    if "cors_configuration" in permitted_checks and profile_data.get("allow_cors_probe", True):
        cors_findings = analyze_cors_configuration(sanitized_url, session, rate_limiter)
        findings.extend(cors_findings)

    # 6. HTTP Methods
    if "http_methods_options" in permitted_checks and profile_data.get("allow_options_probe", True):
        mthd_findings = analyze_http_methods(sanitized_url, session, rate_limiter)
        findings.extend(mthd_findings)

    # 7. Redirect Behavior
    if "redirect_behavior" in permitted_checks and profile_data.get("allow_redirect_probe", True):
        red_findings, extra_blocked = analyze_redirect_behavior(sanitized_url, session, rate_limiter, scope_manager)
        findings.extend(red_findings)
        blocked_redirects_count += extra_blocked

    # 8. Server Banners & Disclosure
    if "server_banners" in permitted_checks:
        disc_findings = analyze_information_disclosure(response_headers, response_body, sanitized_url, session, rate_limiter)
        findings.extend(disc_findings)

    # 9. Passive OWASP Diagnostic Indicators
    if "passive_error_leakage" in permitted_checks:
        owasp_findings = analyze_safe_owasp_indicators(response_body, status_code, sanitized_url)
        findings.extend(owasp_findings)

    # 10. Technology Fingerprinting
    tech_stack = detect_technology_stack(response_headers, response_body)

    end_time = datetime.now(timezone.utc)
    duration_sec = round((end_time - start_time).total_seconds(), 2)
    scheduler_telemetry = rate_limiter.get_telemetry()

    findings_dicts = [f.to_dict() for f in findings]

    # Audit Logging
    for fd in findings_dicts:
        log_audit_event("findings.log", f"[FINDING] Target: {sanitized_url} | [{fd['severity']}] {fd['title']} | CWE: {fd['cwe']}")

    log_audit_event("scanner.log", f"[SCAN_COMPLETE] Target: {sanitized_url} | Findings: {len(findings)} | Requests: {scheduler_telemetry['requests_sent']} | Blocked Redirects: {blocked_redirects_count}")

    return {
        "success": True,
        "target_url": sanitized_url,
        "policy_profile": policy_profile,
        "scan_timestamp": start_time.isoformat(),
        "scan_duration_seconds": duration_sec,
        "status_code": status_code,
        "blocked_redirects_count": blocked_redirects_count,
        "scheduler_telemetry": scheduler_telemetry,
        "metadata": {
            **meta,
            "tech_stack": tech_stack
        },
        "findings": findings_dicts
    }
