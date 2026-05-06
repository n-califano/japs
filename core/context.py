"""System context detected at startup."""

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from core.utils import run, run_raw, which_set

# Tools we care about across all modules
TRACKED_TOOLS = [
    "getcap", "find", "sudo", "nmap", "netstat", "ss",
    "ps", "env", "crontab", "python3", "python", "perl",
    "ruby", "php", "gcc", "curl", "wget", "nc", "socat",
    "docker", "lxc", "strace",
]


@dataclass
class RunContext:
    # Identity
    uid: int
    gid: int
    username: str
    groups: list[str]

    # Privilege level
    is_root: bool
    effective_uid: int

    # Environment
    is_container: bool
    container_type: Optional[str]   # "docker", "lxc", None

    # Available tools
    tools: set[str]

    # System
    hostname: str
    kernel_version: str
    os_pretty: str
    arch: str

    # Run metadata
    run_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: datetime = field(default_factory=datetime.now)

    def has_tool(self, tool: str) -> bool:
        return tool in self.tools

    def has_group(self, group: str) -> bool:
        return group in self.groups

    def summary(self) -> dict:
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp.isoformat(),
            "hostname": self.hostname,
            "username": self.username,
            "uid": self.uid,
            "is_root": self.is_root,
            "is_container": self.is_container,
            "container_type": self.container_type,
            "kernel": self.kernel_version,
            "os": self.os_pretty,
            "gid": self.gid,
            "groups": self.groups,
            "effective_uid": self.effective_uid,
            "tools": list(self.tools),
            "arch": self.arch
        }
    
    @classmethod
    def from_summary(cls, data: dict) -> "RunContext":
        return cls(
            run_id=data["run_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            hostname=data["hostname"],
            username=data["username"],
            uid=data["uid"],
            is_root=data["is_root"],
            is_container=data["is_container"],
            container_type=data["container_type"],
            kernel_version=data["kernel"],
            os_pretty=data["os"],
            gid=data["gid"],
            groups=data["groups"],
            effective_uid=data["effective_uid"],
            tools=set(data["tools"]),
            arch=data["arch"],
        )


def _detect_container() -> tuple[bool, Optional[str]]:
    """Detect if running inside a container and which kind."""
    # Docker
    if Path("/.dockerenv").exists():
        return True, "docker"

    # Check cgroup for docker/lxc markers
    try:
        cgroup = Path("/proc/1/cgroup").read_text()
        if "docker" in cgroup:
            return True, "docker"
        if "lxc" in cgroup:
            return True, "lxc"
    except Exception:
        pass

    # Check for container env var (set by some runtimes)
    if os.environ.get("container") == "lxc":
        return True, "lxc"

    return False, None


def _get_groups() -> list[str]:
    """Get group names for current user."""
    lines = run("id -Gn")
    if lines:
        return lines[0].split()
    return []


def _get_os_pretty() -> str:
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return run_raw("uname -s")


def build_context() -> RunContext:
    """Detect and return the full run context. Called once at startup."""
    uid = os.getuid()
    gid = os.getgid()
    euid = os.geteuid()
    username = run_raw("whoami") or str(uid)
    groups = _get_groups()
    is_container, container_type = _detect_container()
    tools = which_set(TRACKED_TOOLS)

    return RunContext(
        uid=uid,
        gid=gid,
        username=username,
        groups=groups,
        is_root=(uid == 0),
        effective_uid=euid,
        is_container=is_container,
        container_type=container_type,
        tools=tools,
        hostname=run_raw("hostname") or "unknown",
        kernel_version=run_raw("uname -r") or "unknown",
        os_pretty=_get_os_pretty(),
        arch=run_raw("uname -m") or "unknown",
    )
