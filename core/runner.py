"""Module discovery, filtering, and orchestration."""

import importlib
import pkgutil
from typing import Optional

import modules as modules_pkg
from core.base_module import BaseModule
from core.context import RunContext
from core.reporter import Reporter


def _discover_modules() -> list[BaseModule]:
    """Auto-discover all modules in the modules/ package."""
    discovered = []
    for _, module_name, _ in pkgutil.iter_modules(modules_pkg.__path__):
        mod = importlib.import_module(f"modules.{module_name}")
        # Each module file exposes a Module class
        if hasattr(mod, "Module"):
            discovered.append(mod.Module())
    return discovered


class Runner:
    def __init__(
        self,
        reporter: Reporter,
        quick: bool = False,
        only_module: Optional[str] = None,
        only_tags: Optional[list[str]] = None,
        skip_tags: Optional[list[str]] = None,
        min_severity: Optional[str] = None,
        mode: str = None,
    ):
        self.reporter = reporter
        self.quick = quick
        self.only_module = only_module
        self.only_tags = only_tags or []
        self.skip_tags = skip_tags or []
        self.min_severity = min_severity
        self.mode = mode

    def run(self, ctx: RunContext, raw_report) -> None:
        self.reporter.print_banner(ctx)
        modules = self._select_modules(_discover_modules())

        collect_report = None
        if raw_report:
            collect_report = self.reporter.load_report(raw_report)
        
        for module in modules:
            self.reporter.print_module_header(module)

            # Check preconditions
            ok, reason = module.can_run(ctx)
            if not ok:
                self.reporter.print_module_skipped(module, reason)
                continue

            try:
                if self.mode == "collect":
                    module.collect(ctx)
                elif self.mode == "analyse":
                    module.analyse(collect_report)
            except Exception as e:
                self.reporter.print_module_skipped(module, f"error: {e}")
                continue

            self.reporter.print_module_results(module, self.mode)

        self.reporter.print_summary(self.mode)
        self.reporter.write_reports()

    def _select_modules(self, modules: list[BaseModule]) -> list[BaseModule]:
        result = []
        for m in modules:
            # Single module filter
            if self.only_module and m.name != self.only_module:
                continue
            # Quick mode: skip slow modules
            if self.quick and m.slow:
                continue
            # Tag filters
            if self.only_tags and not any(t in m.tags for t in self.only_tags):
                continue
            if self.skip_tags and any(t in m.tags for t in self.skip_tags):
                continue
            result.append(m)
        return result

    def list_modules(self) -> None:
        modules = _discover_modules()
        print(f"{'Name':<20} {'Slow':<6} {'Tags'}")
        print("-" * 50)
        for m in modules:
            tags = ", ".join(m.tags) if m.tags else "-"
            slow = "yes" if m.slow else "no"
            print(f"  {m.name:<18} {slow:<6} {tags}")
