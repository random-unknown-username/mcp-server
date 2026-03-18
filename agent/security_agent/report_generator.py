"""Report generator – produces JSON and Markdown vulnerability reports."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Finding, Severity

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates JSON and Markdown reports from findings."""

    def __init__(self, output_dir: str = "reports") -> None:
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, findings: list[Finding]) -> tuple[Path, Path]:
        """Write JSON and Markdown reports and return their paths."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        json_path = self._output_dir / f"report_{timestamp}.json"
        md_path = self._output_dir / f"report_{timestamp}.md"

        report_data = _build_report_data(findings)
        json_path.write_text(json.dumps(report_data, indent=2))
        md_path.write_text(_render_markdown(report_data))

        logger.info("Reports written to %s and %s", json_path, md_path)
        return json_path, md_path


def _build_report_data(findings: list[Finding]) -> dict[str, Any]:
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "verified_findings": sum(1 for f in findings if f.verified),
        "severity_summary": {
            s.value: sum(1 for f in findings if f.severity == s)
            for s in Severity
        },
        "findings": [f.to_dict() for f in findings],
    }


def _render_markdown(data: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# Security Research Agent – Findings Report")
    lines.append("")
    lines.append(f"**Generated:** {data['generated_at']}")
    lines.append(f"**Total findings:** {data['total_findings']}")
    lines.append(f"**Verified:** {data['verified_findings']}")
    lines.append("")

    lines.append("## Severity Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev, count in data["severity_summary"].items():
        lines.append(f"| {sev} | {count} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    for i, finding in enumerate(data["findings"], 1):
        verified_badge = "✅" if finding["verified"] else "❌"
        lines.append(
            f"### {i}. [{finding['severity'].upper()}] "
            f"{finding['vulnerability_type']} {verified_badge}"
        )
        lines.append("")
        lines.append(f"**Endpoint:** `{finding['endpoint']}`")
        lines.append("")
        lines.append(f"**Description:** {finding['description']}")
        lines.append("")
        if finding["reproduction_steps"]:
            lines.append("**Reproduction Steps:**")
            lines.append("")
            for step in finding["reproduction_steps"]:
                lines.append(f"1. {step}")
            lines.append("")
        if finding.get("modified_request"):
            req = finding["modified_request"]
            lines.append("**Modified Request:**")
            lines.append("")
            lines.append(f"```http")
            lines.append(f"{req['method']} {req['url']}")
            for hdr, val in req.get("headers", {}).items():
                lines.append(f"{hdr}: {val}")
            if req.get("body"):
                lines.append("")
                lines.append(req["body"])
            lines.append("```")
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)
