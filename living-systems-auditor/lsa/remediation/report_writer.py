from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from lsa.drift.models import RemediationReport


def write_report(report: RemediationReport, out_dir: str | Path) -> Path:
    output_dir = Path(out_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    safe_name = report.function.replace(".", "_")
    path = output_dir / f"{timestamp}_{safe_name}.md"
    path.write_text(report.to_markdown(), encoding="utf-8")
    return path
