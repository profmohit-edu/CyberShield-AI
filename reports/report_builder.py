"""Deterministic, presentation-only security report generation."""

import hashlib
import html
import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import cast
from urllib.parse import quote

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from markupsafe import Markup
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from security.base import AnalyzerFinding, Severity, SourceLocation
from services.consensus import ConsensusFinding, ConsensusReport
from services.orchestrator import AnalysisResult, AnalyzerExecutionMetadata

type JSONValue = None | bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"]

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATE_ROOT = _PROJECT_ROOT / "templates"
_PDF_THEME_PATH = _TEMPLATE_ROOT / "pdf" / "report_theme.json"
_SEVERITIES: tuple[Severity, ...] = ("critical", "high", "medium", "low", "informational")
_SEVERITY_COLORS = {
    "critical": "#7F1D1D",
    "high": "#DC2626",
    "medium": "#D97706",
    "low": "#2563EB",
    "informational": "#64748B",
}
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "informational": "note",
}
_SARIF_SECURITY_SEVERITY = {
    "critical": "10.0",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "informational": "0.0",
}
_SOLIDITY_TOKEN_PATTERN = re.compile(
    r"(//[^\n]*|/\*.*?\*/|\b(?:address|bool|bytes\d*|contract|else|emit|enum|error|event|"
    r"external|fallback|false|for|function|if|immutable|import|interface|internal|mapping|"
    r"memory|modifier|new|override|payable|pragma|private|public|pure|receive|require|return|"
    r"returns|revert|storage|string|struct|true|uint\d*|using|view|virtual|while)\b|"
    r"\b(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?)\b|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')",
    re.DOTALL,
)


class ReportInputError(ValueError):
    """Raised when report inputs violate the immutable pipeline contract."""


@dataclass(frozen=True, slots=True)
class ReportMetadata:
    """Immutable request context that is not carried by domain analysis models."""

    source_name: str
    source: str
    cybershield_version: str
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    total_execution_time_ms: float | None = None


class ReportBuilder:
    """Render one validated analysis and consensus report into five formats."""

    def __init__(
        self,
        analysis: AnalysisResult,
        consensus: ConsensusReport,
        metadata: ReportMetadata,
    ) -> None:
        self._validate_inputs(analysis, consensus, metadata)
        self._analysis = analysis
        self._consensus = consensus
        self._metadata = metadata
        self._generated_at = metadata.generated_at.astimezone(UTC)
        self._payload = self._build_payload()

    def build_json(self) -> str:
        """Return the canonical, deterministic CyberShield JSON report."""
        return _dump_json(self._payload)

    def build_markdown(self) -> str:
        """Return a deterministic GitHub-compatible Markdown report."""
        environment = Environment(
            loader=FileSystemLoader(_TEMPLATE_ROOT / "markdown"),
            undefined=StrictUndefined,
            autoescape=False,
            keep_trailing_newline=True,
        )
        return environment.get_template("report.md.j2").render(**self._template_context())

    def build_html(self) -> str:
        """Return a standalone responsive HTML report with highlighted snippets."""
        environment = Environment(
            loader=FileSystemLoader(_TEMPLATE_ROOT / "html"),
            undefined=StrictUndefined,
            autoescape=select_autoescape(default=True),
            keep_trailing_newline=True,
        )
        return environment.get_template("report.html.j2").render(**self._template_context())

    def build_sarif(self) -> str:
        """Return deterministic SARIF 2.1.0 suitable for GitHub Code Scanning."""
        rules, rule_indices = self._sarif_rules()
        results = [
            self._sarif_result(finding, rule_indices[self._sarif_rule_id(finding)])
            for finding in self._consensus.findings
        ]
        failed = [item for item in self._analysis.analyzers if item.status == "failed"]
        invocation: dict[str, JSONValue] = {
            "executionSuccessful": True,
            "startTimeUtc": _iso_timestamp(
                self._generated_at
                - timedelta(milliseconds=self._total_execution_time_ms())
            ),
            "endTimeUtc": _iso_timestamp(self._generated_at),
            "properties": {
                "orchestratorExecutionTimeMs": self._analysis.execution_time_ms,
                "totalExecutionTimeMs": self._total_execution_time_ms(),
                "analyzers": cast(
                    list[JSONValue],
                    [self._serialize_analyzer(item) for item in self._analysis.analyzers],
                ),
            },
        }
        if failed:
            invocation["toolExecutionNotifications"] = [
                {
                    "descriptor": {"id": f"{item.analyzer}/execution-failed"},
                    "level": "error",
                    "message": {"text": item.error.message if item.error else "Execution failed"},
                    "properties": {
                        "analyzer": item.analyzer,
                        "errorType": item.error.error_type if item.error else "UnknownError",
                    },
                }
                for item in failed
            ]

        sarif: dict[str, JSONValue] = {
            "$schema": (
                "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
                "sarif-schema-2.1.0.json"
            ),
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CyberShield AI",
                            "fullName": "CyberShield AI Smart Contract Security Analyzer",
                            "version": self._metadata.cybershield_version,
                            "semanticVersion": self._metadata.cybershield_version,
                            "rules": rules,
                        }
                    },
                    "automationDetails": {
                        "id": f"cybershield/{_slug(self._metadata.source_name)}/"
                        f"{self._source_digest()[:12]}"
                    },
                    "invocations": [invocation],
                    "results": cast(list[JSONValue], results),
                    "properties": {
                        "generatedAt": _iso_timestamp(self._generated_at),
                        "sourceSha256": self._source_digest(),
                        "consensusFindingCount": len(self._consensus.findings),
                        "sourceFindingCount": len(self._analysis.findings),
                        "severitySummary": self._severity_summary(),
                    },
                }
            ],
        }
        return _dump_json(sarif)

    def build_pdf(self) -> bytes:
        """Return a professional PDF report generated entirely in memory."""
        theme = self._load_pdf_theme()
        self._register_fonts()
        output = BytesIO()
        document = SimpleDocTemplate(
            output,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=20 * mm,
            bottomMargin=18 * mm,
            title=f"CyberShield AI Security Report — {self._metadata.source_name}",
            author="CyberShield AI",
            subject="Smart contract security analysis",
            creator=f"CyberShield AI {self._metadata.cybershield_version}",
        )
        styles = self._pdf_styles(theme)
        story = self._pdf_story(styles, theme)
        document.build(
            story,
            onFirstPage=self._draw_pdf_page,
            onLaterPages=self._draw_pdf_page,
        )
        return output.getvalue()

    def _build_payload(self) -> dict[str, JSONValue]:
        severity = self._severity_summary()
        raw_severity = self._raw_severity_summary()
        return {
            "schema_version": "1.0",
            "report": {
                "product": "CyberShield AI",
                "version": self._metadata.cybershield_version,
                "generated_at": _iso_timestamp(self._generated_at),
                "source_name": self._metadata.source_name,
                "source_sha256": self._source_digest(),
            },
            "execution": {
                "total_execution_time_ms": self._total_execution_time_ms(),
                "orchestrator_execution_time_ms": self._analysis.execution_time_ms,
                "source_size_bytes": len(self._metadata.source.encode("utf-8")),
                "enabled_analyzers": [
                    item.analyzer for item in self._analysis.analyzers if item.status != "disabled"
                ],
            },
            "summary": {
                "vulnerability_count": len(self._consensus.findings),
                "source_finding_count": len(self._analysis.findings),
                "severity_counts": severity,
                "source_severity_counts": raw_severity,
            },
            "analyzers": [self._serialize_analyzer(item) for item in self._analysis.analyzers],
            "consensus_findings": [
                self._serialize_consensus_finding(item) for item in self._consensus.findings
            ],
            "supporting_findings": [
                self._serialize_finding(item) for item in self._analysis.findings
            ],
            "recommendations": self._recommendations(),
        }

    def _serialize_analyzer(self, item: AnalyzerExecutionMetadata) -> dict[str, JSONValue]:
        error: JSONValue = None
        if item.error is not None:
            error = {
                "error_type": item.error.error_type,
                "message": item.error.message,
            }
        return {
            "analyzer": item.analyzer,
            "status": item.status,
            "execution_time_ms": item.execution_time_ms,
            "finding_count": item.finding_count,
            "error": error,
        }

    def _serialize_finding(self, item: AnalyzerFinding) -> dict[str, JSONValue]:
        return {
            "analyzer": item.analyzer,
            "rule_id": item.rule_id,
            "title": item.title,
            "severity": item.severity,
            "description": item.description,
            "location": self._serialize_location(item.location),
        }

    def _serialize_consensus_finding(self, item: ConsensusFinding) -> dict[str, JSONValue]:
        return {
            "title": item.title,
            "severity": item.severity,
            "confidence_score": item.confidence_score,
            "contributing_analyzers": list(item.contributing_analyzers),
            "rule_ids": list(item.rule_ids),
            "descriptions": list(item.descriptions),
            "location": self._serialize_location(item.location),
            "supporting_findings": [
                self._serialize_finding(finding) for finding in item.supporting_findings
            ],
        }

    def _serialize_location(self, item: SourceLocation | None) -> JSONValue:
        if item is None:
            return None
        return {
            "path": item.path,
            "start_line": item.start_line,
            "end_line": item.end_line,
            "start_column": item.start_column,
            "end_column": item.end_column,
        }

    def _severity_summary(self) -> dict[str, JSONValue]:
        counts = Counter(item.severity for item in self._consensus.findings)
        return {severity: counts[severity] for severity in _SEVERITIES}

    def _raw_severity_summary(self) -> dict[str, JSONValue]:
        counts = Counter(item.severity for item in self._analysis.findings)
        return {severity: counts[severity] for severity in _SEVERITIES}

    def _recommendations(self) -> list[JSONValue]:
        counts = Counter(item.severity for item in self._consensus.findings)
        recommendations: list[JSONValue] = []
        if counts["critical"] or counts["high"]:
            recommendations.append(
                "Block deployment until all critical and high-severity findings are remediated "
                "and independently retested."
            )
        if counts["medium"]:
            recommendations.append(
                "Review medium-severity findings against the contract threat model and resolve "
                "them before the next release."
            )
        if counts["low"] or counts["informational"]:
            recommendations.append(
                "Triage low and informational findings, documenting accepted risks and planned "
                "hardening work."
            )
        if not self._consensus.findings:
            recommendations.append(
                "No vulnerabilities were correlated; retain manual review and deployment tests "
                "because automated analysis cannot establish absence of defects."
            )
        recommendations.extend(
            [
                "Review every supporting analyzer finding before changing code; consensus scores "
                "express evidence agreement, not exploitability.",
                "Re-run all enabled analyzers after remediation and compare the new report with "
                "this baseline.",
            ]
        )
        return recommendations

    def _template_context(self) -> dict[str, object]:
        context = cast(dict[str, object], self._payload.copy())
        context["severity_order"] = _SEVERITIES
        context["severity_colors"] = _SEVERITY_COLORS
        context["findings"] = [
            self._template_finding(index, finding)
            for index, finding in enumerate(self._consensus.findings, start=1)
        ]
        context["source_name"] = self._metadata.source_name
        return context

    def _template_finding(self, index: int, finding: ConsensusFinding) -> dict[str, object]:
        snippet = self._snippet(finding.location)
        snippet_source = cast(str, snippet["source"])
        return {
            "number": index,
            "anchor": f"finding-{index}",
            "title": finding.title,
            "severity": finding.severity,
            "confidence_score": finding.confidence_score,
            "confidence_percent": f"{finding.confidence_score * 100:.1f}%",
            "contributing_analyzers": finding.contributing_analyzers,
            "rule_ids": finding.rule_ids,
            "descriptions": finding.descriptions,
            "location": _location_text(finding.location),
            "supporting_findings": [
                {
                    "analyzer": item.analyzer,
                    "rule_id": item.rule_id,
                    "severity": item.severity,
                    "title": item.title,
                    "description": item.description,
                    "location": _location_text(item.location),
                }
                for item in finding.supporting_findings
            ],
            "snippet": snippet,
            "highlighted_snippet": Markup(_highlight_solidity(snippet_source)),
            "markdown_fence": _markdown_fence(snippet_source),
        }

    def _snippet(self, location: SourceLocation | None) -> dict[str, object]:
        if location is None or Path(location.path).name != Path(self._metadata.source_name).name:
            return {"source": "", "start_line": None, "end_line": None}
        lines = self._metadata.source.splitlines()
        if not lines or location.start_line > len(lines):
            return {"source": "", "start_line": None, "end_line": None}
        start = max(1, location.start_line - 2)
        end = min(len(lines), max(location.end_line, location.start_line) + 2, start + 11)
        return {
            "source": "\n".join(lines[start - 1 : end]),
            "start_line": start,
            "end_line": end,
        }

    def _sarif_rules(self) -> tuple[list[JSONValue], dict[str, int]]:
        descriptors: dict[str, dict[str, JSONValue]] = {}
        for finding in self._consensus.findings:
            rule_id = self._sarif_rule_id(finding)
            if rule_id in descriptors:
                continue
            descriptors[rule_id] = {
                "id": rule_id,
                "name": _slug(finding.title),
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": "\n\n".join(finding.descriptions)},
                "defaultConfiguration": {"level": _SARIF_LEVEL[finding.severity]},
                "properties": {
                    "precision": "high" if finding.confidence_score >= 0.75 else "medium",
                    "problem.severity": finding.severity,
                    "security-severity": _SARIF_SECURITY_SEVERITY[finding.severity],
                    "tags": ["security", "smart-contract", *finding.rule_ids],
                },
            }
        ordered_ids = sorted(descriptors)
        return [descriptors[rule_id] for rule_id in ordered_ids], {
            rule_id: index for index, rule_id in enumerate(ordered_ids)
        }

    def _sarif_result(self, finding: ConsensusFinding, rule_index: int) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "ruleId": self._sarif_rule_id(finding),
            "ruleIndex": rule_index,
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": self._sarif_message(finding)},
            "partialFingerprints": {
                "cybershield/v1": self._finding_fingerprint(finding),
            },
            "properties": {
                "severity": finding.severity,
                "confidenceScore": finding.confidence_score,
                "contributingAnalyzers": list(finding.contributing_analyzers),
                "ruleIdentifiers": list(finding.rule_ids),
                "descriptions": list(finding.descriptions),
                "supportingFindings": [
                    self._serialize_finding(item) for item in finding.supporting_findings
                ],
            },
        }
        if finding.location is not None:
            region: dict[str, JSONValue] = {
                "startLine": finding.location.start_line,
                "endLine": finding.location.end_line,
            }
            if finding.location.start_column is not None:
                region["startColumn"] = finding.location.start_column
            if finding.location.end_column is not None:
                region["endColumn"] = finding.location.end_column
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": quote(finding.location.path.replace("\\", "/"), safe="/:"),
                        },
                        "region": region,
                    }
                }
            ]
        return result

    def _sarif_rule_id(self, finding: ConsensusFinding) -> str:
        return finding.rule_ids[0] if finding.rule_ids else f"cybershield/{_slug(finding.title)}"

    def _sarif_message(self, finding: ConsensusFinding) -> str:
        analyzers = ", ".join(finding.contributing_analyzers)
        return (
            f"{finding.title}: {finding.descriptions[0]} "
            f"(confidence {finding.confidence_score:.4f}; reported by {analyzers})"
        )

    def _finding_fingerprint(self, finding: ConsensusFinding) -> str:
        location = finding.location
        evidence = "\x1f".join(
            [
                finding.title.casefold(),
                ",".join(finding.rule_ids),
                location.path.casefold() if location else "",
                str(location.start_line) if location else "",
            ]
        )
        return hashlib.sha256(evidence.encode("utf-8")).hexdigest()

    def _pdf_story(
        self,
        styles: dict[str, ParagraphStyle],
        theme: dict[str, str],
    ) -> list[Flowable]:
        story: list[Flowable] = [
            Spacer(1, 14 * mm),
            Paragraph("CYBERSHIELD AI", styles["eyebrow"]),
            Paragraph("Smart Contract Security Report", styles["title"]),
            Paragraph(html.escape(self._metadata.source_name), styles["subtitle"]),
            Spacer(1, 7 * mm),
            self._pdf_metadata_table(styles, theme),
            Spacer(1, 8 * mm),
            Paragraph(
                f"{len(self._consensus.findings)} canonical vulnerabilities from "
                f"{len(self._analysis.findings)} analyzer findings",
                styles["summaryMetric"],
            ),
            PageBreak(),
            Paragraph("Executive Summary", styles["heading1"]),
            Paragraph(self._executive_summary(), styles["body"]),
            Spacer(1, 4 * mm),
            Paragraph("Severity Pie Summary", styles["heading2"]),
            self._pdf_severity_chart(theme),
            Paragraph("Consensus Table", styles["heading2"]),
            self._pdf_consensus_table(styles, theme),
            Spacer(1, 5 * mm),
            Paragraph("Analyzer Comparison", styles["heading2"]),
            self._pdf_analyzer_table(styles, theme),
            PageBreak(),
            Paragraph("Detailed Findings", styles["heading1"]),
        ]
        if not self._consensus.findings:
            story.append(Paragraph("No canonical vulnerabilities were reported.", styles["body"]))
        for index, finding in enumerate(self._consensus.findings, start=1):
            story.extend(self._pdf_finding(index, finding, styles, theme))
        story.extend(
            [
                PageBreak(),
                Paragraph("Recommendations", styles["heading1"]),
                *[
                    Paragraph(html.escape(str(item)), styles["recommendation"], bulletText="•")
                    for item in self._recommendations()
                ],
            ]
        )
        return story

    def _pdf_metadata_table(
        self,
        styles: dict[str, ParagraphStyle],
        theme: dict[str, str],
    ) -> Table:
        data = [
            ["Generated", _iso_timestamp(self._generated_at)],
            ["CyberShield AI", self._metadata.cybershield_version],
            ["Source SHA-256", self._source_digest()],
            ["Total execution", f"{self._total_execution_time_ms():.2f} ms"],
        ]
        table = Table(data, colWidths=[38 * mm, 112 * mm])
        table.setStyle(
            TableStyle(
                [
                    ("FONTNAME", (0, 0), (0, -1), "Inter-SemiBold"),
                    ("FONTNAME", (1, 0), (1, -1), "Inter-Regular"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor(theme["muted"])),
                    ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor(theme["text"])),
                    ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor(theme["border"])),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        return table

    def _pdf_severity_chart(self, theme: dict[str, str]) -> Drawing:
        width, height = 160 * mm, 54 * mm
        drawing = Drawing(width, height)
        counts = [
            cast(int, self._severity_summary()[severity])
            for severity in _SEVERITIES
        ]
        active = [
            (severity, count)
            for severity, count in zip(_SEVERITIES, counts, strict=True)
            if count
        ]
        chart = Pie()
        chart.x = 8 * mm
        chart.y = 3 * mm
        chart.width = 45 * mm
        chart.height = 45 * mm
        if active:
            chart.data = [count for _, count in active]
            chart.labels = [f"{severity.title()} ({count})" for severity, count in active]
            for index, (severity, _) in enumerate(active):
                chart.slices[index].fillColor = colors.HexColor(_SEVERITY_COLORS[severity])
        else:
            chart.data = [1]
            chart.labels = ["No findings"]
            chart.slices[0].fillColor = colors.HexColor(theme["border"])
        chart.slices.strokeColor = colors.white
        chart.slices.strokeWidth = 0.8
        chart.sideLabels = True
        chart.simpleLabels = False
        chart.slices.fontName = "Inter-Regular"
        chart.slices.fontSize = 7
        drawing.add(chart)
        drawing.add(
            String(
                108 * mm,
                31 * mm,
                str(len(self._consensus.findings)),
                fontName="Poppins-Bold",
                fontSize=24,
                fillColor=colors.HexColor(theme["primary"]),
                textAnchor="middle",
            )
        )
        drawing.add(
            String(
                108 * mm,
                23 * mm,
                "canonical findings",
                fontName="Inter-Regular",
                fontSize=8,
                fillColor=colors.HexColor(theme["muted"]),
                textAnchor="middle",
            )
        )
        return drawing

    def _pdf_consensus_table(
        self,
        styles: dict[str, ParagraphStyle],
        theme: dict[str, str],
    ) -> Table:
        data: list[list[object]] = [["#", "Finding", "Severity", "Confidence", "Analyzers"]]
        for index, finding in enumerate(self._consensus.findings, start=1):
            data.append(
                [
                    str(index),
                    Paragraph(html.escape(finding.title), styles["table"]),
                    finding.severity.title(),
                    f"{finding.confidence_score * 100:.1f}%",
                    Paragraph(
                        html.escape(", ".join(finding.contributing_analyzers)),
                        styles["table"],
                    ),
                ]
            )
        if len(data) == 1:
            data.append(["—", "No findings", "—", "—", "—"])
        return self._styled_pdf_table(
            data,
            [8 * mm, 58 * mm, 24 * mm, 24 * mm, 40 * mm],
            theme,
        )

    def _pdf_analyzer_table(
        self,
        styles: dict[str, ParagraphStyle],
        theme: dict[str, str],
    ) -> Table:
        data: list[list[object]] = [["Analyzer", "Status", "Runtime", "Findings", "Error"]]
        for item in self._analysis.analyzers:
            data.append(
                [
                    item.analyzer,
                    item.status.title(),
                    f"{item.execution_time_ms:.2f} ms",
                    str(item.finding_count),
                    Paragraph(
                        html.escape(item.error.message if item.error else "—"),
                        styles["table"],
                    ),
                ]
            )
        return self._styled_pdf_table(
            data,
            [32 * mm, 26 * mm, 29 * mm, 22 * mm, 45 * mm],
            theme,
        )

    def _styled_pdf_table(
        self,
        data: list[list[object]],
        widths: list[float],
        theme: dict[str, str],
    ) -> Table:
        table = Table(data, colWidths=widths, repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(theme["primary"])),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Inter-SemiBold"),
                    ("FONTNAME", (0, 1), (-1, -1), "Inter-Regular"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor(theme["border"])),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor(theme["surface"])],
                    ),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        return table

    def _pdf_finding(
        self,
        index: int,
        finding: ConsensusFinding,
        styles: dict[str, ParagraphStyle],
        theme: dict[str, str],
    ) -> list[Flowable]:
        title = f"{index}. {html.escape(finding.title)}"
        details: list[list[object]] = [
            ["Severity", finding.severity.title()],
            ["Confidence", f"{finding.confidence_score * 100:.1f}%"],
            ["Location", html.escape(_location_text(finding.location))],
            ["Analyzers", html.escape(", ".join(finding.contributing_analyzers))],
            ["Rules", html.escape(", ".join(finding.rule_ids))],
        ]
        flows: list[Flowable] = [
            Paragraph(title, styles["heading2"]),
            self._styled_pdf_table(details, [30 * mm, 124 * mm], theme),
            Spacer(1, 3 * mm),
        ]
        for description in finding.descriptions:
            flows.append(Paragraph(html.escape(description), styles["body"]))
        flows.append(Paragraph("Supporting evidence", styles["heading3"]))
        for support in finding.supporting_findings:
            flows.append(
                Paragraph(
                    f"<b>{html.escape(support.analyzer)}</b> · "
                    f"{html.escape(support.rule_id)} · {html.escape(support.severity.title())}<br/>"
                    f"{html.escape(support.description)}",
                    styles["evidence"],
                )
            )
        flows.append(Spacer(1, 5 * mm))
        return flows

    def _pdf_styles(self, theme: dict[str, str]) -> dict[str, ParagraphStyle]:
        sample = getSampleStyleSheet()
        return {
            "eyebrow": ParagraphStyle(
                "Eyebrow",
                parent=sample["Normal"],
                fontName="Inter-SemiBold",
                fontSize=9,
                textColor=colors.HexColor(theme["accent"]),
                alignment=TA_CENTER,
                spaceAfter=8,
            ),
            "title": ParagraphStyle(
                "Title",
                parent=sample["Title"],
                fontName="Poppins-Bold",
                fontSize=27,
                leading=32,
                textColor=colors.HexColor(theme["primary"]),
                alignment=TA_CENTER,
            ),
            "subtitle": ParagraphStyle(
                "Subtitle",
                parent=sample["Normal"],
                fontName="Inter-Regular",
                fontSize=12,
                textColor=colors.HexColor(theme["muted"]),
                alignment=TA_CENTER,
            ),
            "summaryMetric": ParagraphStyle(
                "SummaryMetric",
                parent=sample["Normal"],
                fontName="Poppins-Bold",
                fontSize=15,
                textColor=colors.HexColor(theme["primary"]),
                alignment=TA_CENTER,
            ),
            "heading1": ParagraphStyle(
                "Heading1",
                parent=sample["Heading1"],
                fontName="Poppins-Bold",
                fontSize=18,
                leading=22,
                textColor=colors.HexColor(theme["primary"]),
                spaceAfter=10,
            ),
            "heading2": ParagraphStyle(
                "Heading2",
                parent=sample["Heading2"],
                fontName="Poppins-Bold",
                fontSize=12,
                leading=15,
                textColor=colors.HexColor(theme["primary"]),
                spaceBefore=10,
                spaceAfter=6,
            ),
            "heading3": ParagraphStyle(
                "Heading3",
                parent=sample["Heading3"],
                fontName="Inter-SemiBold",
                fontSize=9,
                textColor=colors.HexColor(theme["text"]),
                spaceBefore=7,
                spaceAfter=4,
            ),
            "body": ParagraphStyle(
                "Body",
                parent=sample["BodyText"],
                fontName="Inter-Regular",
                fontSize=8.5,
                leading=12.5,
                textColor=colors.HexColor(theme["text"]),
                spaceAfter=6,
            ),
            "table": ParagraphStyle(
                "Table",
                parent=sample["BodyText"],
                fontName="Inter-Regular",
                fontSize=7.5,
                leading=9.5,
                textColor=colors.HexColor(theme["text"]),
            ),
            "evidence": ParagraphStyle(
                "Evidence",
                parent=sample["BodyText"],
                fontName="Inter-Regular",
                fontSize=7.8,
                leading=11,
                leftIndent=8,
                borderColor=colors.HexColor(theme["border"]),
                borderWidth=0.5,
                borderPadding=6,
                backColor=colors.HexColor(theme["surface"]),
                spaceAfter=5,
            ),
            "recommendation": ParagraphStyle(
                "Recommendation",
                parent=sample["BodyText"],
                fontName="Inter-Regular",
                fontSize=9,
                leading=13,
                leftIndent=12,
                firstLineIndent=-8,
                textColor=colors.HexColor(theme["text"]),
                spaceAfter=7,
            ),
        }

    def _draw_pdf_page(self, canvas: Canvas, document: BaseDocTemplate) -> None:
        theme = self._load_pdf_theme()
        canvas.saveState()
        canvas.setTitle(f"CyberShield AI Security Report — {self._metadata.source_name}")
        canvas.setAuthor("CyberShield AI")
        canvas.setFont("Inter-Regular", 7)
        canvas.setFillColor(colors.HexColor(theme["muted"]))
        canvas.drawString(18 * mm, 10 * mm, f"CyberShield AI {self._metadata.cybershield_version}")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {document.page}")
        canvas.restoreState()

    def _executive_summary(self) -> str:
        failed_count = sum(item.status == "failed" for item in self._analysis.analyzers)
        failure_note = (
            f" {failed_count} analyzer execution(s) failed and are identified in the comparison "
            "table; their absence may reduce coverage."
            if failed_count
            else " All enabled analyzers completed successfully."
        )
        return (
            f"CyberShield AI correlated {len(self._analysis.findings)} normalized analyzer "
            f"findings into {len(self._consensus.findings)} canonical vulnerabilities for "
            f"{html.escape(self._metadata.source_name)}.{failure_note} Confidence scores measure "
            "cross-analyzer agreement and should be considered alongside severity and evidence."
        )

    def _load_pdf_theme(self) -> dict[str, str]:
        with _PDF_THEME_PATH.open(encoding="utf-8") as theme_file:
            theme = json.load(theme_file)
        if not isinstance(theme, dict) or any(
            key not in theme or not isinstance(theme[key], str)
            for key in ("primary", "accent", "text", "muted", "surface", "border")
        ):
            raise ReportInputError("PDF report theme is invalid")
        return cast(dict[str, str], theme)

    def _register_fonts(self) -> None:
        fonts = {
            "Inter-Regular": _PROJECT_ROOT / "assets" / "fonts" / "Inter-Regular.ttf",
            "Inter-SemiBold": _PROJECT_ROOT / "assets" / "fonts" / "Inter-SemiBold.ttf",
            "Poppins-Bold": _PROJECT_ROOT / "assets" / "fonts" / "Poppins-Bold.ttf",
        }
        registered = set(pdfmetrics.getRegisteredFontNames())
        for name, path in fonts.items():
            if name not in registered:
                pdfmetrics.registerFont(TTFont(name, path))

    def _source_digest(self) -> str:
        return hashlib.sha256(self._metadata.source.encode("utf-8")).hexdigest()

    def _total_execution_time_ms(self) -> float:
        value = self._metadata.total_execution_time_ms
        return self._analysis.execution_time_ms if value is None else value

    def _validate_inputs(
        self,
        analysis: object,
        consensus: object,
        metadata: object,
    ) -> None:
        if not isinstance(analysis, AnalysisResult):
            raise ReportInputError("analysis must be an AnalysisResult")
        if not isinstance(consensus, ConsensusReport):
            raise ReportInputError("consensus must be a ConsensusReport")
        if not isinstance(metadata, ReportMetadata):
            raise ReportInputError("metadata must be ReportMetadata")
        if not metadata.source_name or metadata.source_name != metadata.source_name.strip():
            raise ReportInputError("source_name must be non-empty and trimmed")
        if not metadata.source or not metadata.source.strip():
            raise ReportInputError("source must be non-empty")
        if not metadata.cybershield_version or not metadata.cybershield_version.strip():
            raise ReportInputError("cybershield_version must be non-empty")
        if metadata.generated_at.tzinfo is None or metadata.generated_at.utcoffset() is None:
            raise ReportInputError("generated_at must be timezone-aware")
        if metadata.total_execution_time_ms is not None and (
            not math.isfinite(metadata.total_execution_time_ms)
            or metadata.total_execution_time_ms < 0
        ):
            raise ReportInputError("total_execution_time_ms must be finite and non-negative")
        if consensus.source_finding_count != len(analysis.findings):
            raise ReportInputError("consensus source finding count does not match analysis")
        analyzer_names = tuple(item.analyzer for item in analysis.analyzers)
        if consensus.registered_analyzers != analyzer_names:
            raise ReportInputError("consensus analyzer registration does not match analysis")
        supporting = [
            support
            for finding in consensus.findings
            for support in finding.supporting_findings
        ]
        if Counter(supporting) != Counter(analysis.findings):
            raise ReportInputError("consensus must preserve every source finding exactly once")
        if any(
            not math.isfinite(finding.confidence_score)
            or not 0 <= finding.confidence_score <= 1
            for finding in consensus.findings
        ):
            raise ReportInputError("consensus confidence scores must be between zero and one")


def _dump_json(value: JSONValue) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def _iso_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _location_text(location: SourceLocation | None) -> str:
    if location is None:
        return "Location unavailable"
    line = f"{location.start_line}"
    if location.end_line != location.start_line:
        line += f"-{location.end_line}"
    column = ""
    if location.start_column is not None:
        column = f":{location.start_column}"
        if location.end_column is not None and location.end_column != location.start_column:
            column += f"-{location.end_column}"
    return f"{location.path}:{line}{column}"


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")
    return slug or "finding"


def _markdown_fence(source: str) -> str:
    longest = max((len(match.group()) for match in re.finditer(r"`+", source)), default=0)
    return "`" * max(3, longest + 1)


def _highlight_solidity(source: str) -> str:
    fragments: list[str] = []
    cursor = 0
    for match in _SOLIDITY_TOKEN_PATTERN.finditer(source):
        fragments.append(html.escape(source[cursor : match.start()]))
        token = match.group()
        if token.startswith(("//", "/*")):
            token_class = "tok-comment"
        elif token.startswith(("\"", "'")):
            token_class = "tok-string"
        elif token[0].isdigit() or token.startswith("0x"):
            token_class = "tok-number"
        else:
            token_class = "tok-keyword"
        fragments.append(f'<span class="{token_class}">{html.escape(token)}</span>')
        cursor = match.end()
    fragments.append(html.escape(source[cursor:]))
    return "".join(fragments)
