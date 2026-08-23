"""
CyberShield AI PDF Security Report Generator.

Renders a structured scan summary (``report_data``) into a styled,
professional PDF report using ReportLab. The generator is standalone:
it has no database, storage, network, or ML dependencies and writes the
finished PDF to the supplied ``output_path``.
"""

import os
from datetime import datetime
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Table,
    TableStyle,
)

NAVY = colors.HexColor("#0F2B46")
CYAN = colors.HexColor("#00B4D8")
BRAND = colors.HexColor("#0EA5E9")
TEXT = colors.HexColor("#1F2937")
MUTED = colors.HexColor("#6B7280")
LIGHT = colors.HexColor("#F3F4F6")
BORDER = colors.HexColor("#D9DEE3")
GREEN = colors.HexColor("#15803D")
AMBER = colors.HexColor("#B45309")
RED = colors.HexColor("#B91C1C")

PAGE_WIDTH, PAGE_HEIGHT = A4
MARGIN = 54
CONTENT_WIDTH = PAGE_WIDTH - (2 * MARGIN)

STYLE_BRAND = ParagraphStyle(
    "brand", fontName="Helvetica-Bold", fontSize=13, leading=15, textColor=NAVY
)
STYLE_TITLE = ParagraphStyle(
    "title", fontName="Helvetica-Bold", fontSize=24, leading=28, textColor=NAVY
)
STYLE_SUBTITLE = ParagraphStyle(
    "subtitle", fontName="Helvetica", fontSize=10.5, leading=13, textColor=CYAN,
    spaceAfter=12,
)
STYLE_H1 = ParagraphStyle(
    "h1", fontName="Helvetica-Bold", fontSize=13, leading=16, textColor=NAVY,
    spaceBefore=16, spaceAfter=2,
)
STYLE_H2 = ParagraphStyle(
    "h2", fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=BRAND,
    spaceBefore=10, spaceAfter=4,
)
STYLE_BODY = ParagraphStyle(
    "body", fontName="Helvetica", fontSize=9.5, leading=13, textColor=TEXT, spaceAfter=6
)
STYLE_NOTE = ParagraphStyle(
    "note", fontName="Helvetica-Oblique", fontSize=9.5, leading=13, textColor=MUTED,
    spaceAfter=6,
)
STYLE_META_LABEL = ParagraphStyle(
    "metalabel", fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=NAVY
)
STYLE_META_VALUE = ParagraphStyle(
    "metavalue", fontName="Helvetica", fontSize=9, leading=12, textColor=TEXT
)
STYLE_CELL = ParagraphStyle(
    "cell", fontName="Helvetica", fontSize=8.5, leading=11, textColor=TEXT
)
STYLE_CELL_BOLD = ParagraphStyle(
    "cellbold", fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=TEXT
)
STYLE_CELL_HEAD = ParagraphStyle(
    "cellhead", fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=colors.white
)

WEBSITE_KEYS = ("website_scan", "website_scans", "website")
EMAIL_KEYS = ("email_scan", "email_scans", "email")
PASSWORD_KEYS = ("password_scan", "password_scans", "password")
LOG_KEYS = ("log_scan", "log_scans", "log_analysis", "logs")
PORT_KEYS = ("port_scan", "port_scans", "port", "port_scanner")
FINDINGS_KEYS = ("findings", "risk_findings", "risks")
SUMMARY_KEYS = ("summary", "overall_summary", "security_summary", "executive_summary")


def _esc(value):
    if value is None:
        return "—"
    return _xml_escape(str(value))


def _first(mapping, *keys, default=None):
    for key in keys:
        if isinstance(mapping, dict):
            value = mapping.get(key)
        else:
            value = getattr(mapping, key, None)
        if value is not None:
            return value
    return default


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _hex(color):
    return "#" + color.hexval()[2:]


def _status_color(status):
    key = str(status).strip().lower()
    table = {
        "passed": GREEN, "ok": GREEN, "safe": GREEN, "low": GREEN,
        "good": GREEN, "strong": GREEN, "weak": RED, "breached": RED,
        "warning": AMBER, "suspicious": AMBER, "medium": AMBER, "fair": AMBER,
        "failed": RED, "fail": RED, "high": RED, "critical": RED, "phishing": RED,
    }
    return table.get(key, MUTED)


def _fmt_date(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M")
    text = str(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return text


def _fmt_ms(value):
    if value is None:
        return "—"
    try:
        return f"{float(value):.0f} ms"
    except (ValueError, TypeError):
        return str(value)


def _fmt_percent(value):
    if value is None:
        return "—"
    try:
        return f"{float(value) * 100:.0f}%"
    except (ValueError, TypeError):
        return str(value)


def _fmt_top_sources(value):
    if not value:
        return "—"
    parts = []
    for entry in _as_list(value):
        if isinstance(entry, (list, tuple)) and len(entry) >= 2:
            parts.append(f"{entry[0]} ({entry[1]})")
        elif isinstance(entry, dict):
            host = entry.get("ip") or entry.get("host") or entry.get("source")
            count = entry.get("count")
            if host is not None and count is not None:
                parts.append(f"{host} ({count})")
            else:
                parts.append(_esc(entry))
        else:
            parts.append(_esc(entry))
    return ", ".join(parts)


def _risk_label(score):
    if score is None:
        return "Not assessed"
    if score >= 75:
        return "Low"
    if score >= 60:
        return "Medium"
    if score >= 40:
        return "High"
    return "Critical"


def _overall_score(data):
    scores = []
    website = _first(data, *WEBSITE_KEYS)
    if isinstance(website, dict) and isinstance(website.get("score"), (int, float)):
        scores.append(website["score"])
    email = _first(data, *EMAIL_KEYS)
    if isinstance(email, dict) and isinstance(email.get("risk_score"), (int, float)):
        scores.append(100 - email["risk_score"])
    password = _first(data, *PASSWORD_KEYS)
    if isinstance(password, dict) and isinstance(password.get("strength_score"), (int, float)):
        scores.append(password["strength_score"])
    log = _first(data, *LOG_KEYS)
    if isinstance(log, dict) and isinstance(log.get("threat_score"), (int, float)):
        scores.append(100 - log["threat_score"])
    if not scores:
        return None
    return round(sum(scores) / len(scores))


def _severity_map(status):
    key = str(status).strip().lower()
    mapping = {
        "critical": "critical", "high": "high", "medium": "medium", "low": "low",
        "info": "info", "failed": "high", "warning": "medium", "warn": "medium",
        "passed": "info", "ok": "info", "safe": "low",
    }
    return mapping.get(key, "info")


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class PDFReportGenerator:
    """Compiles scan summaries into a professional CyberShield AI PDF report."""

    @classmethod
    def generate_pdf(cls, report_data: dict, output_path: str) -> str:
        if report_data is None:
            report_data = {}
        if not isinstance(report_data, dict):
            raise ValueError("report_data must be a dict")
        if output_path is None:
            raise ValueError("output_path is required")
        output_path = str(output_path)
        parent = os.path.dirname(os.path.abspath(output_path))
        os.makedirs(parent, exist_ok=True)

        story = cls._build_story(report_data)
        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=MARGIN,
            rightMargin=MARGIN,
            topMargin=72,
            bottomMargin=54,
            title=_first(report_data, "title", default="CyberShield AI Security Report"),
            author="CyberShield AI",
            pageCompression=0,
        )
        doc.build(story, onFirstPage=cls._draw_frame, onLaterPages=cls._draw_frame)
        return output_path

    # ------------------------------------------------------------ story
    @classmethod
    def _build_story(cls, data: dict) -> list:
        title = _first(data, "title", default="Security Audit Report")
        generated = _first(
            data, "generated_at", "generated_date", "generation_date", "created_at"
        )

        story = [
            Paragraph("CYBERSHIELD AI", STYLE_BRAND),
            Paragraph(_esc(title), STYLE_TITLE),
            Paragraph("Security &amp; Compliance Report", STYLE_SUBTITLE),
            HRFlowable(width="100%", thickness=2, color=CYAN, spaceAfter=12),
        ]
        story.append(cls._kv_table([
            ("Report Title", title),
            ("Report ID", _first(data, "id", "report_id", default="—")),
            ("Generated", _fmt_date(generated) or "—"),
            ("Report Type", _first(data, "report_type", default="PDF")),
        ]))
        story += cls._overall_section(data, title, generated)
        story += cls._website_section(data)
        story += cls._email_section(data)
        story += cls._password_section(data)
        story += cls._log_section(data)
        story += cls._port_section(data)
        story += cls._findings_section(data)
        return story

    @classmethod
    def _overall_section(cls, data, title, generated):
        story = cls._heading("1. Overall Security Summary")
        summary = _first(data, *SUMMARY_KEYS)
        if summary:
            story.append(Paragraph(_esc(summary), STYLE_BODY))
        else:
            when = _fmt_date(generated) or "the generated report date"
            story.append(Paragraph(
                _esc(f"Report '{title}' generated on {when} using the included scan results."),
                STYLE_BODY,
            ))

        score = _overall_score(data)
        risk = _risk_label(score)
        risk_color = _status_color(risk)
        score_display = f"{score} / 100" if score is not None else "Not assessed"
        story.append(cls._kv_table([
            ("Overall Security Score", score_display),
            ("Overall Risk Level", f'<font color="{_hex(risk_color)}"><b>{_esc(risk)}</b></font>'),
        ]))
        return story

    @classmethod
    def _website_section(cls, data):
        story = cls._heading("2. Website Security Scan")
        items = _as_list(_first(data, *WEBSITE_KEYS))
        if not items:
            story.append(Paragraph("No website scan data was included in this report.", STYLE_NOTE))
            return story

        for index, scan in enumerate(items):
            if len(items) > 1:
                story.append(Paragraph(f"Target {index + 1}", STYLE_H2))
            if not isinstance(scan, dict):
                story.append(Paragraph(_esc(scan), STYLE_BODY))
                continue
            if scan.get("reachable") is False or scan.get("error"):
                message = scan.get("message") or scan.get("error_message")
                story.append(Paragraph(
                    _esc(message or "Target could not be scanned."), STYLE_BODY
                ))
                continue

            summary = _first(scan, "summary")
            if summary:
                story.append(Paragraph(_esc(summary), STYLE_BODY))
            story.append(cls._kv_table([
                ("Target", _first(scan, "target", "url", default="Unknown target")),
                ("Final URL", _first(scan, "final_url", default="—")),
                ("HTTP Status", _first(scan, "final_status_code", "status_code", default="—")),
                ("Security Score", f"{_first(scan, 'score', default='—')} / 100"),
                ("Grade", _first(scan, "grade", default="—")),
                ("Scan Duration", _fmt_ms(_first(scan, "scan_duration_ms"))),
            ]))

            checks = scan.get("checks")
            if checks:
                story.append(Paragraph("Security Checks", STYLE_H2))
                story.append(cls._checks_table(checks))
            else:
                story.append(Paragraph("No individual checks were recorded.", STYLE_NOTE))
        return story

    @classmethod
    def _email_section(cls, data):
        story = cls._heading("3. Email Security Scan")
        items = _as_list(_first(data, *EMAIL_KEYS))
        if not items:
            story.append(Paragraph("No email scan data was included in this report.", STYLE_NOTE))
            return story

        for scan in items:
            if not isinstance(scan, dict):
                story.append(Paragraph(_esc(scan), STYLE_BODY))
                continue
            summary = _first(scan, "summary")
            if summary:
                story.append(Paragraph(_esc(summary), STYLE_BODY))
            story.append(cls._kv_table([
                ("Subject", _first(scan, "subject", default="—")),
                ("Sender", _first(scan, "sender_email", "sender", default="—")),
                ("Predicted Label", cls._predicted_label(scan)),
                ("Risk Level", _first(scan, "risk_level", default="—")),
                ("Risk Score", f"{_first(scan, 'risk_score', default='—')} / 100"),
                ("Confidence", _fmt_percent(_first(scan, "confidence"))),
                ("Analyzer", _first(scan, "analyzer", "model_version", default="—")),
            ]))

            indicators = scan.get("indicators")
            if indicators:
                story.append(Paragraph("Phishing Indicators", STYLE_H2))
                story.append(cls._indicators_table(indicators))
            else:
                story.append(Paragraph("No phishing indicators were recorded.", STYLE_NOTE))
        return story

    @classmethod
    def _password_section(cls, data):
        story = cls._heading("4. Password Strength Analysis")
        items = _as_list(_first(data, *PASSWORD_KEYS))
        if not items:
            story.append(Paragraph("No password scan data was included in this report.", STYLE_NOTE))
            return story

        for scan in items:
            if not isinstance(scan, dict):
                story.append(Paragraph(_esc(scan), STYLE_BODY))
                continue
            char_classes = scan.get("char_classes")
            story.append(cls._kv_table([
                ("Strength", _first(scan, "strength", "strength_label", default="—")),
                ("Strength Score", f"{_first(scan, 'strength_score', default='—')} / 100"),
                ("Length", _first(scan, "length", "password_length", default="—")),
                ("Entropy", f"{_first(scan, 'entropy_bits', 'entropy', default='—')} bits"),
                ("Character Classes", ", ".join(map(str, char_classes)) if char_classes else "—"),
                ("Estimated Crack Time", _first(scan, "crack_time_estimate", default="—")),
                ("Matches Common List", "Yes" if scan.get("in_common_list") else "No"),
            ]))

            recommendations = scan.get("recommendations")
            if recommendations:
                story.append(Paragraph("Recommendations", STYLE_H2))
                story.append(cls._recommendations_table(recommendations))
            else:
                story.append(Paragraph("No recommendations were generated.", STYLE_NOTE))
        return story

    @classmethod
    def _log_section(cls, data):
        story = cls._heading("5. Log Analysis")
        items = _as_list(_first(data, *LOG_KEYS))
        if not items:
            story.append(Paragraph("No log analysis data was included in this report.", STYLE_NOTE))
            return story

        for scan in items:
            if not isinstance(scan, dict):
                story.append(Paragraph(_esc(scan), STYLE_BODY))
                continue
            stats = scan.get("stats") if isinstance(scan.get("stats"), dict) else {}
            summary = _first(scan, "summary")
            if summary:
                story.append(Paragraph(_esc(summary), STYLE_BODY))
            story.append(cls._kv_table([
                ("Lines Analyzed", f"{_first(scan, 'parsed_lines', default='—')} of "
                                   f"{_first(scan, 'total_lines', default='—')}"),
                ("Anomalies Detected", _first(scan, "anomalies_detected", "anomaly_count", default="—")),
                ("Threat Score", f"{_first(scan, 'threat_score', default='—')} / 100"),
                ("Severity", _first(scan, "severity", "risk_level", default="—")),
                ("Unique IPs", _first(stats, "unique_ips", default="—")),
                ("Top Sources", _fmt_top_sources(_first(stats, "top_sources"))),
            ]))

            anomalies = scan.get("anomalies")
            if anomalies:
                story.append(Paragraph("Detected Anomalies", STYLE_H2))
                story.append(cls._anomalies_table(anomalies))
            else:
                story.append(Paragraph("No anomalies were detected.", STYLE_NOTE))
        return story

    @classmethod
    def _port_section(cls, data):
        story = cls._heading("6. Port Scanner and IP Reputation")
        items = _as_list(_first(data, *PORT_KEYS))
        # Filter out None entries; _as_list returns [] for None due to _first returning None then _as_list -> []
        # But if port_scan is a single dict, wrap; if already list with one dict, ok
        # Remove empty None
        items = [x for x in items if x is not None]
        if not items:
            story.append(Paragraph("No port scan data was included in this report.", STYLE_NOTE))
            return story

        for scan in items:
            if not isinstance(scan, dict):
                story.append(Paragraph(_esc(scan), STYLE_BODY))
                continue
            # Port scan core
            story.append(Paragraph("Port Scan — Target & Results", STYLE_H2))
            if scan.get("summary"):
                story.append(Paragraph(_esc(scan.get("summary")), STYLE_BODY))
            story.append(cls._kv_table([
                ("Target", _first(scan, "target", default="—")),
                ("Resolved IP", _first(scan, "resolved_ip", default="—")),
                ("Scan Date", _fmt_date(_first(scan, "created_at", "scan_date")) or "—"),
                ("Scan Duration", _fmt_ms(_first(scan, "scan_duration_ms"))),
                ("Ports Scanned", _first(scan, "ports_scanned", default="—")),
                ("Open Ports", _first(scan, "open_port_count", default="—")),
                ("Closed Ports", _first(scan, "closed_ports", default="—")),
                ("Filtered Ports", _first(scan, "filtered_ports", default="—")),
                ("Port Risk Level", _first(scan, "risk_level", default="—")),
                ("Status", _first(scan, "status", default="—")),
            ]))
            # Distinct: PORT RISK vs IP REPUTATION — already separated by subheadings
            ports = scan.get("open_ports") or scan.get("ports") or []
            if ports:
                story.append(Paragraph("Discovered Ports (service / state / banner)", STYLE_H2))
                story.append(cls._port_table(ports))
            else:
                story.append(Paragraph("No port details were recorded for this scan.", STYLE_NOTE))

            # IP Reputation subsection — clearly distinguished
            story.append(Paragraph("IP Reputation — AbuseIPDB (independent from port risk)", STYLE_H2))
            rep = scan.get("ip_reputation") or scan.get("reputation")
            if not isinstance(rep, dict) or not rep:
                story.append(Paragraph("Not available — this scan was created before IP reputation was enabled or the provider returned no data.", STYLE_NOTE))
            else:
                # Sanitize/no API key exposure — only allowed fields already filtered in service
                story.append(cls._kv_table([
                    ("IP Address", _first(rep, "ip", default="—")),
                    ("Reputation", _first(rep, "reputation", default="—")),
                    ("Confidence", _first(rep, "confidence", default="—")),
                    ("Malicious", "Yes" if rep.get("malicious") else "No"),
                    ("Suspicious", "Yes" if rep.get("suspicious") else "No"),
                    ("Abuse Reports", _first(rep, "reports", default="—")),
                    ("Country", _first(rep, "country", default="—")),
                    ("ASN", _first(rep, "asn", default="—")),
                    ("Organization", _first(rep, "organization", default="—")),
                    ("ISP", _first(rep, "isp", default="—")),
                    ("Last Reported", _fmt_date(_first(rep, "last_reported_at")) or "—"),
                    ("Provider", _first(rep, "provider", default="—")),
                    ("Checked At", _fmt_date(_first(rep, "checked_at")) or "—"),
                ]))
                # Note distinction
                story.append(Paragraph(
                    "Note: Port risk is derived from open ports/services; IP reputation is an independent AbuseIPDB signal. No combined score is computed in this report.",
                    STYLE_NOTE,
                ))
        return story

    @classmethod
    def _findings_section(cls, data):
        story = cls._heading("7. Risk & Findings Summary")
        findings = cls._compile_findings(data)
        if not findings:
            story.append(Paragraph(
                "No significant findings were identified in the included scans.", STYLE_NOTE
            ))
            return story

        story.append(Paragraph(
            f"The report identified <b>{len(findings)}</b> finding(s) across the included scans.",
            STYLE_BODY,
        ))
        counts = {}
        for item in findings:
            counts[item["severity"]] = counts.get(item["severity"], 0) + 1
        labels = [f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info")
                  if s in counts]
        if labels:
            story.append(Paragraph(_esc(", ".join(labels) + "."), STYLE_BODY))

        rows = [[
            Paragraph("Severity", STYLE_CELL_HEAD),
            Paragraph("Source", STYLE_CELL_HEAD),
            Paragraph("Finding", STYLE_CELL_HEAD),
        ]]
        for item in findings:
            color = _status_color(item["severity"])
            description = item["description"]
            if item["recommendation"]:
                description += f" Recommended: {item['recommendation']}"
            rows.append([
                Paragraph(
                    f'<font color="{_hex(color)}"><b>{_esc(item["severity"].upper())}</b></font>',
                    STYLE_CELL,
                ),
                Paragraph(_esc(item["source"]), STYLE_CELL),
                Paragraph(_esc(description), STYLE_CELL),
            ])
        table = Table(rows, colWidths=[70, 100, CONTENT_WIDTH - 170], repeatRows=1)
        table.setStyle(cls._table_style())
        story.append(table)
        return story

    # ------------------------------------------------------------ tables
    @staticmethod
    def _heading(text: str):
        return [Paragraph(text.replace("&", "&amp;"), STYLE_H1),
                HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=6)]

    @staticmethod
    def _table_style():
        return TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ])

    @classmethod
    def _kv_table(cls, rows):
        body = []
        for label, value in rows:
            body.append([
                Paragraph(_esc(label), STYLE_META_LABEL),
                Paragraph(_esc(value) if "<font" not in str(value) else value, STYLE_META_VALUE),
            ])
        table = Table(body, colWidths=[150, CONTENT_WIDTH - 150], spaceBefore=2, spaceAfter=8)
        table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
            ("BACKGROUND", (0, 0), (0, -1), LIGHT),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return table

    @classmethod
    def _checks_table(cls, checks):
        rows = [[Paragraph("Status", STYLE_CELL_HEAD), Paragraph("Check", STYLE_CELL_HEAD),
                 Paragraph("Details", STYLE_CELL_HEAD), Paragraph("Recommendation", STYLE_CELL_HEAD)]]
        for check in checks:
            status = _first(check, "status", default="info")
            color = _status_color(status)
            rows.append([
                Paragraph(f'<font color="{_hex(color)}"><b>{_esc(status.upper())}</b></font>', STYLE_CELL),
                Paragraph(_esc(_first(check, "name", default="—")), STYLE_CELL),
                Paragraph(_esc(_first(check, "detail", "details", "description", default="—")), STYLE_CELL),
                Paragraph(_esc(_first(check, "recommendation", default="—")), STYLE_CELL),
            ])
        table = Table(rows, colWidths=[60, 110, 170, CONTENT_WIDTH - 340], repeatRows=1)
        table.setStyle(cls._table_style())
        return table

    @classmethod
    def _indicators_table(cls, indicators):
        rows = [[Paragraph("Severity", STYLE_CELL_HEAD), Paragraph("Indicator", STYLE_CELL_HEAD),
                 Paragraph("Evidence", STYLE_CELL_HEAD)]]
        for indicator in indicators:
            severity = _first(indicator, "severity", default="info")
            color = _status_color(severity)
            rows.append([
                Paragraph(f'<font color="{_hex(color)}"><b>{_esc(severity.upper())}</b></font>', STYLE_CELL),
                Paragraph(_esc(_first(indicator, "name", default="—")), STYLE_CELL),
                Paragraph(_esc(_first(indicator, "evidence", "detail", default="—")), STYLE_CELL),
            ])
        table = Table(rows, colWidths=[70, 120, CONTENT_WIDTH - 190], repeatRows=1)
        table.setStyle(cls._table_style())
        return table

    @classmethod
    def _recommendations_table(cls, recommendations):
        rows = [[Paragraph("#", STYLE_CELL_HEAD), Paragraph("Recommendation", STYLE_CELL_HEAD)]]
        for index, rec in enumerate(recommendations, start=1):
            rows.append([
                Paragraph(str(index), STYLE_CELL),
                Paragraph(_esc(_first(rec, "text", "recommendation", default="—")), STYLE_CELL),
            ])
        table = Table(rows, colWidths=[30, CONTENT_WIDTH - 30], repeatRows=1)
        table.setStyle(cls._table_style())
        return table

    @classmethod
    def _anomalies_table(cls, anomalies):
        rows = [[Paragraph("Line", STYLE_CELL_HEAD), Paragraph("Type", STYLE_CELL_HEAD),
                 Paragraph("Severity", STYLE_CELL_HEAD), Paragraph("Evidence", STYLE_CELL_HEAD)]]
        for anomaly in anomalies:
            severity = _first(anomaly, "severity", default="info")
            color = _status_color(severity)
            rows.append([
                Paragraph(_esc(_first(anomaly, "line_number", default="—")), STYLE_CELL),
                Paragraph(_esc(_first(anomaly, "type", "name", default="—")), STYLE_CELL),
                Paragraph(f'<font color="{_hex(color)}"><b>{_esc(severity.upper())}</b></font>', STYLE_CELL),
                Paragraph(_esc(_first(anomaly, "evidence", "detail", default="—")), STYLE_CELL),
            ])
        table = Table(rows, colWidths=[45, 110, 70, CONTENT_WIDTH - 225], repeatRows=1)
        table.setStyle(cls._table_style())
        return table

    @classmethod
    def _port_table(cls, ports):
        rows = [[Paragraph("Port", STYLE_CELL_HEAD), Paragraph("Service", STYLE_CELL_HEAD),
                 Paragraph("State", STYLE_CELL_HEAD), Paragraph("Banner", STYLE_CELL_HEAD)]]
        for port in ports:
            p = _first(port, "port", default="—")
            service = _first(port, "service", default="unknown")
            state = _first(port, "state", default="—")
            banner = _first(port, "banner", default="—")
            # Banner already sanitized in service, double-escape for PDF
            if banner is None or banner == "":
                banner = "—"
            color = _status_color(state) if state in ("open", "closed", "filtered") else MUTED
            rows.append([
                Paragraph(_esc(p), STYLE_CELL),
                Paragraph(_esc(service), STYLE_CELL),
                Paragraph(f'<font color="{_hex(color)}"><b>{_esc(str(state).upper())}</b></font>', STYLE_CELL),
                Paragraph(_esc(banner), STYLE_CELL),
            ])
        table = Table(rows, colWidths=[50, 110, 70, CONTENT_WIDTH - 230], repeatRows=1)
        table.setStyle(cls._table_style())
        return table

    # ------------------------------------------------------------ misc
    @staticmethod
    def _draw_frame(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica-Bold", 9)
        canvas.setFillColor(NAVY)
        canvas.drawString(MARGIN, PAGE_HEIGHT - 30, "CYBERSHIELD AI")
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(MUTED)
        canvas.drawRightString(PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 30, "Security Report")
        canvas.setStrokeColor(BRAND)
        canvas.setLineWidth(1.5)
        canvas.line(MARGIN, PAGE_HEIGHT - 36, PAGE_WIDTH - MARGIN, PAGE_HEIGHT - 36)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(MARGIN, 30, "Generated by CyberShield AI — Confidential")
        canvas.drawRightString(PAGE_WIDTH - MARGIN, 30, f"Page {canvas.getPageNumber()}")
        canvas.restoreState()

    @staticmethod
    def _predicted_label(scan):
        label = _first(scan, "predicted_label")
        if label:
            return label
        is_phishing = scan.get("is_phishing")
        if is_phishing is True:
            return "Phishing"
        if is_phishing is False:
            return "Safe"
        return "—"

    @classmethod
    def _compile_findings(cls, data):
        findings = []

        def add(source, severity, description, recommendation=""):
            if description is None:
                return
            findings.append({
                "severity": _severity_map(severity),
                "source": source,
                "description": str(description),
                "recommendation": str(recommendation or ""),
            })

        for item in _as_list(_first(data, *FINDINGS_KEYS)):
            if isinstance(item, str):
                add("Report", "info", item)
            elif isinstance(item, dict):
                add(
                    _first(item, "source", "section", "category", default="Report"),
                    _first(item, "severity", "risk_level", "level", "status", default="info"),
                    _first(item, "description", "detail", "message", "name", "text",
                           default=str(item)),
                    _first(item, "recommendation", "fix"),
                )

        for scan in _as_list(_first(data, *WEBSITE_KEYS)):
            if not isinstance(scan, dict):
                continue
            for check in _as_list(scan.get("checks")):
                if isinstance(check, dict) and check.get("status") in ("failed", "warning"):
                    add("Website Scan", check.get("status"),
                        _first(check, "detail", "details", "description", default="Check failed"),
                        _first(check, "recommendation"))

        for scan in _as_list(_first(data, *EMAIL_KEYS)):
            if not isinstance(scan, dict):
                continue
            for indicator in _as_list(scan.get("indicators")):
                if isinstance(indicator, dict) and str(indicator.get("severity", "")).lower() in {
                        "high", "medium", "critical"}:
                    add("Email Scan", indicator.get("severity"),
                        _first(indicator, "evidence", "detail", default="Phishing indicator"))

        for scan in _as_list(_first(data, *PASSWORD_KEYS)):
            if not isinstance(scan, dict):
                continue
            for rec in _as_list(scan.get("recommendations")):
                if not isinstance(rec, dict):
                    continue
                priority = rec.get("priority")
                try:
                    priority = int(priority)
                except (TypeError, ValueError):
                    priority = 3
                severity = "high" if priority <= 2 else ("medium" if priority <= 4 else "low")
                add("Password Scan", severity, _first(rec, "text", "recommendation"))

        for scan in _as_list(_first(data, *LOG_KEYS)):
            if not isinstance(scan, dict):
                continue
            for anomaly in _as_list(scan.get("anomalies")):
                if isinstance(anomaly, dict) and str(anomaly.get("severity", "")).lower() in {
                        "high", "medium", "critical"}:
                    add("Log Analysis", anomaly.get("severity"),
                        _first(anomaly, "evidence", "detail", default="Anomaly detected"))

        findings.sort(key=lambda item: _SEVERITY_RANK.get(item["severity"], 99))
        return findings
