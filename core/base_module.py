from dataclasses import dataclass, field
from typing import Optional
from core.context import RunContext


SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


@dataclass
class Finding:
    severity: str           # HIGH | MEDIUM | LOW | INFO
    title: str
    detail: Optional[str] = None
    reference: Optional[str] = None
    module: str = ""

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "module": self.module,
            "title": self.title,
            "detail": self.detail,
            "reference": self.reference,
        }


@dataclass
class RawOutput:
    """Raw command output to always include in the report, regardless of findings."""
    label: str
    content: str

    def to_dict(self) -> dict:
        return {"label": self.label, "content": self.content}


class BaseModule:
    name: str = "unnamed"
    description: str = ""
    slow: bool = False
    tags: list[str] = []
    requires_tools: list[str] = []

    def __init__(self):
        self.findings: list[Finding] = []
        self.raw_outputs: list[RawOutput] = []

    ### Interface for subclasses

    def collect(self, ctx: RunContext) -> None:
        """Gather raw data from the system. Store in self attributes."""
        raise NotImplementedError

    def analyse(self, ctx: RunContext) -> None:
        """Inspect collected data, call add_finding() for anything notable."""
        raise NotImplementedError

    ### Helpers for subclasses

    def add_finding(
        self,
        severity: str,
        title: str,
        detail: str = None,
        reference: str = None,
    ) -> None:
        self.findings.append(Finding(
            severity=severity.upper(),
            title=title,
            detail=detail,
            reference=reference,
            module=self.name,
        ))

    def add_raw(self, label: str, content: str) -> None:
        """Register raw command output to always include in the report."""
        if content and content.strip():
            self.raw_outputs.append(RawOutput(label=label, content=content.strip()))

    ### Runner interface

    def can_run(self, ctx: RunContext) -> tuple[bool, str]:
        """Check preconditions. Returns (ok, reason_if_skipped)."""
        missing = [t for t in self.requires_tools if not ctx.has_tool(t)]
        if missing:
            return False, f"missing tools: {', '.join(missing)}"
        return True, ""

    def run(self, ctx: RunContext) -> None:
        """Called by the runner. Executes collect then analyse."""
        self.collect(ctx)
        self.analyse(ctx)

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
