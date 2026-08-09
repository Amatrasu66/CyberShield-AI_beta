"""
Log Analyzer Service.

DETERMINISTIC PLACEHOLDER (this phase):
Logs are parsed and analyzed with transparent, rule-based heuristics so the API
contract can be exercised without any ML model.

Future phase (ML integration): anomaly detection will be replaced by the trained
model behind ``app/ml/log_analyzer.py``. The service method signature
``analyze_logs(content) -> dict`` will NOT change.

Safety: input is size-limited and processed line by line; nothing is persisted.
"""

import re
from urllib.parse import unquote

from ..errors import ValidationError

# Apache combined / common log format.
COMBINED_LOG_REGEX = re.compile(
    r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d{3}) (\S+)'
)

MAX_REPORTED_ANOMALIES = 200

FAILED_AUTH_STATUS = {401, 403}
SERVER_ERROR_STATUS = {500, 502, 503, 504}

# Applied to the URL-decoded request path to catch encoded payloads too.
SQLI_PATTERN = re.compile(
    r"\b(select|union|insert|update|delete|drop|sleep)\b|--|/\*|['\"]\s*or\s*['\"]|\b1\s*=\s*1\b",
    re.IGNORECASE,
)
TRAVERSAL_PATTERN = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)", re.IGNORECASE)
XSS_PATTERN = re.compile(r"(<script|onerror=|javascript:)", re.IGNORECASE)
SUSPICIOUS_USER_AGENTS = {"sqlmap", "nikto", "nessus", "nmap", "curl", "wget", "python-requests", "scanner", "zgrab"}


class LogService:
    """Deterministic rule-based log analysis placeholder."""

    ANALYZER_ID = "deterministic-rule-based-placeholder"

    @staticmethod
    def analyze_logs(log_content: str, log_format: str = "auto") -> dict:
        """Parse and analyze server log text."""
        if not isinstance(log_content, str):
            raise ValidationError("'content' must be a string", details={"field": "content"})

        lines = log_content.splitlines()
        anomalies = []
        status_counts = {}
        ip_request_counts = {}
        parsed = 0
        failed_auth_by_ip = {}
        suspicious_ua_ips = set()

        for idx, line in enumerate(lines, start=1):
            line = line.strip()
            if not line:
                continue
            match = COMBINED_LOG_REGEX.match(line)
            if not match:
                continue
            parsed += 1
            ip, _ts, method, path, _proto, status_str, _size = match.groups()
            decoded_path = unquote(path)
            status = int(status_str)
            status_counts[status] = status_counts.get(status, 0) + 1
            ip_request_counts[ip] = ip_request_counts.get(ip, 0) + 1

            # Rule-based anomaly detection (deterministic).
            if status in FAILED_AUTH_STATUS:
                failed_auth_by_ip[ip] = failed_auth_by_ip.get(ip, 0) + 1
                _add_anomaly(anomalies, idx, "failed_authentication", "High",
                             f"HTTP {status} from {ip} on {path}")
            if status in SERVER_ERROR_STATUS:
                _add_anomaly(anomalies, idx, "server_error", "Medium",
                             f"HTTP {status} on {path}")
            if SQLI_PATTERN.search(decoded_path):
                _add_anomaly(anomalies, idx, "sql_injection_attempt", "High",
                             f"SQL metacharacters in request {path}")
            if TRAVERSAL_PATTERN.search(decoded_path):
                _add_anomaly(anomalies, idx, "path_traversal_attempt", "High",
                             f"Directory traversal pattern in {path}")
            if XSS_PATTERN.search(decoded_path):
                _add_anomaly(anomalies, idx, "xss_attempt", "Medium",
                             f"XSS pattern in {path}")
            ua = _extract_user_agent(line)
            if ua and any(ua.lower().startswith(agent) for agent in SUSPICIOUS_USER_AGENTS):
                _add_anomaly(anomalies, idx, "suspicious_user_agent", "Medium",
                             f"Recognized automated UA '{ua}' from {ip}")
                suspicious_ua_ips.add(ip)

        # Aggregated: repeated failed logins from one source.
        for ip, count in failed_auth_by_ip.items():
            if count >= 3:
                _add_anomaly(anomalies, None, "brute_force_pattern", "High",
                             f"{count} failed authentication events from {ip}")

        threat_score = _threat_score(anomalies)
        total_lines = len([l for l in lines if l.strip()])

        return {
            "total_lines": total_lines,
            "parsed_lines": parsed,
            "skipped_lines": total_lines - parsed,
            "anomalies_detected": len(anomalies),
            "threat_score": threat_score,
            "severity": _severity(threat_score),
            "analyzer": LogService.ANALYZER_ID,
            "summary": (
                f"Analyzed {parsed} log line(s); {len(anomalies)} anomaly(ies) "
                f"detected. Threat score {threat_score}/100 ({_severity(threat_score)})."
            ),
            "stats": {
                "status_code_counts": status_counts,
                "unique_ips": len(ip_request_counts),
                "top_sources": sorted(
                    ip_request_counts.items(), key=lambda item: item[1], reverse=True
                )[:5],
            },
            "anomalies": anomalies[:MAX_REPORTED_ANOMALIES],
        }


def _add_anomaly(anomalies, line_number, anomaly_type, severity, evidence):
    anomalies.append({
        "line_number": line_number,
        "type": anomaly_type,
        "severity": severity,
        "evidence": evidence,
    })


def _extract_user_agent(line: str):
    m = re.search(r'"([^"]*(?:Mozilla|curl|wget|python-requests|sqlmap|nikto|nessus|nmap|zgrab)[^"]*)"', line, re.IGNORECASE)
    if not m:
        m = re.search(r'"[^"]*" "([^"]+)"', line)
    return m.group(1) if m else None


def _threat_score(anomalies: list) -> int:
    weights = {"High": 3, "Medium": 2, "Low": 1}
    score = 0
    for a in anomalies:
        score += weights.get(a["severity"], 1)
    return max(0, min(100, round(score * 4)))


def _severity(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"
