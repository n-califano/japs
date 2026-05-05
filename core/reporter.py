"""Stdout, plain text, and JSON report generation."""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.base_module import BaseModule, Finding, SEVERITY_ORDER
from core.context import RunContext

### ANSI colors 
RED    = "\033[0;31m"
YELLOW = "\033[1;33m"
GREEN  = "\033[0;32m"
CYAN   = "\033[0;36m"
BLUE   = "\033[0;34m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

SEVERITY_COLORS = {
    "HIGH":   RED,
    "MEDIUM": YELLOW,
    "LOW":    BLUE,
    "INFO":   GREEN,
}


class Reporter:
    def __init__(self, output_dir: Optional[str] = None, no_color: bool = False):
        self.output_dir = Path(output_dir) if output_dir else None
        self.no_color = no_color
        self.modules: list[BaseModule] = []
        self.ctx: Optional[RunContext] = None

        if self.output_dir:
            self.output_dir.mkdir(parents=True, exist_ok=True)

    def _c(self, color: str, text: str) -> str:
        """Apply color unless --no-color."""
        if self.no_color:
            return text
        return f"{color}{text}{RESET}"


    def print_banner(self, ctx: RunContext) -> None:
        self.ctx = ctx
        print(self._c(RED + BOLD, r"""
            ██╗ █████╗ ██████╗ ███████╗
            ██║██╔══██╗██╔══██╗██╔════╝
            ██║███████║██████╔╝███████╗
        ██   ██║██╔══██║██╔═══╝ ╚════██║
        ╚█████╔╝██║  ██║██║     ███████║
        ╚════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝
        """))
        print(f"  {self._c(BOLD, 'Just Another PrivEsc Script')}")
        print(f"  Run ID  : {self._c(CYAN, ctx.run_id)}")
        print(f"  Host    : {self._c(CYAN, ctx.hostname)}")
        print(f"  User    : {self._c(YELLOW, ctx.username)} (uid={ctx.uid})")
        print(f"  Kernel  : {ctx.kernel_version}")
        print(f"  OS      : {ctx.os_pretty}")
        if ctx.is_container:
            container_msg = f"[~] Running inside {ctx.container_type or 'container'} - some checks adjusted"
            print(f"  {self._c(YELLOW, container_msg)}")
        print()

    def print_module_header(self, module: BaseModule) -> None:
        sep = '=' * 42
        title = '  [*] ' + module.name.upper().replace('_', ' ')
        print('\n' + self._c(BOLD + CYAN, sep))
        print(self._c(BOLD + CYAN, title))
        print(self._c(BOLD + CYAN, sep))

    def print_module_skipped(self, module: BaseModule, reason: str) -> None:
        print(f"\n  {self._c(YELLOW, f'[~] Skipping {module.name}: {reason}')}")

    def print_module_results(self, module: BaseModule) -> None:
        """Print findings (sorted by severity) then raw output."""
        self.modules.append(module)

        # Findings first
        for finding in module.sorted_findings():
            color = SEVERITY_COLORS.get(finding.severity, RESET)
            tag = f"[{finding.severity:<6}]"
            print(f"  {self._c(color, tag)} {finding.title}")
            if finding.detail:
                for line in finding.detail.splitlines():
                    print(f"           {line}")
            if finding.reference:
                print(f"           {self._c(CYAN, '→ ' + finding.reference)}")

        if not module.findings:
            print(f"  {self._c(GREEN, '[INFO  ]')} No findings")

        # Raw output below findings
        if module.raw_outputs:
            print()
            for raw in module.raw_outputs:
                print(f"  {self._c(CYAN, '[>]')} {raw.label}:")
                for line in raw.content.splitlines():
                    print(f"      {line}")

    def print_summary(self) -> None:
        """Print a final findings summary across all modules."""
        all_findings = [f for m in self.modules for f in m.sorted_findings()]
        highs   = [f for f in all_findings if f.severity == "HIGH"]
        mediums = [f for f in all_findings if f.severity == "MEDIUM"]
        info = [f for f in all_findings if f.severity == "INFO"]

        print(f"\n{self._c(BOLD, '══════════════════════════════════════════')}")
        print(f"{self._c(BOLD, '  SUMMARY')}")
        print(f"{self._c(BOLD, '══════════════════════════════════════════')}")
        print(f"  Total findings : {len(all_findings)}")
        print(f"  {self._c(RED,    f'HIGH   : {len(highs)}')}")
        print(f"  {self._c(YELLOW, f'MEDIUM : {len(mediums)}')}")
        print(f"  {self._c(CYAN, f'INFO : {len(info)}')}")

        if highs:
            print(f"\n  {self._c(BOLD + RED, 'High severity findings:')}")
            for f in highs:
                print(f"    [{f.module}] {f.title}")

        print()

    ### File output 
    
    def write_reports(self) -> None:
        if not self.output_dir or not self.ctx:
            return

        run_id = self.ctx.run_id
        self._write_json(self.output_dir / f"run_{run_id}.json")
        self._write_text(self.output_dir / f"run_{run_id}.txt")
        print(f"  Reports saved to: {self._c(CYAN, str(self.output_dir))}")

    def _build_report_dict(self) -> dict:
        all_findings = [f for m in self.modules for f in m.sorted_findings()]
        return {
            "context": self.ctx.summary(),
            "findings": [f.to_dict() for f in all_findings],
            "raw_output": {
                m.name: [r.to_dict() for r in m.raw_outputs]
                for m in self.modules
            },
        }

    def _write_json(self, path: Path) -> None:
        report = self._build_report_dict()
        path.write_text(json.dumps(report, indent=2))

    def _write_text(self, path: Path) -> None:
        lines = []
        ctx = self.ctx
        lines.append("PRIVESC ENUMERATION REPORT")
        lines.append(f"Run ID  : {ctx.run_id}")
        lines.append(f"Host    : {ctx.hostname}")
        lines.append(f"User    : {ctx.username} (uid={ctx.uid})")
        lines.append(f"Kernel  : {ctx.kernel_version}")
        lines.append(f"Time    : {ctx.timestamp.isoformat()}")
        lines.append("")

        for module in self.modules:
            lines.append(f"\n[{module.name.upper()}]")
            for f in module.sorted_findings():
                lines.append(f"  [{f.severity}] {f.title}")
                if f.detail:
                    for dl in f.detail.splitlines():
                        lines.append(f"          {dl}")
                if f.reference:
                    lines.append(f"          -> {f.reference}")
            for raw in module.raw_outputs:
                lines.append(f"\n  {raw.label}:")
                for rl in raw.content.splitlines():
                    lines.append(f"    {rl}")

        path.write_text("\n".join(lines))
