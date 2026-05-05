import shutil
import subprocess
import os
import re


def run(cmd: str, timeout: int = 30) -> list[str]:
    """Run a shell command, return stdout lines. Never raises."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return [l for l in result.stdout.splitlines() if l.strip()]
    except Exception:
        return []


def run_raw(cmd: str, timeout: int = 30) -> str:
    """Run a shell command, return raw stdout string. Never raises."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return result.stdout.strip() + result.stderr.strip()
    except Exception:
        return ""


def which(binary: str) -> bool:
    """Return True if a binary exists on PATH."""
    return shutil.which(binary) is not None


def which_set(binaries: list[str]) -> set[str]:
    """Return the subset of binaries that exist on PATH."""
    return {b for b in binaries if which(b)}


def is_readable(path: str) -> bool:
    try:
        return os.access(path, os.R_OK)
    except Exception:
        return False


def is_writable(path: str) -> bool:
    try:
        return os.access(path, os.W_OK)
    except Exception:
        return False

def parse_sudo_version(raw: str) -> tuple:
    """
    Parse string such 'Sudo version 1.9.13p3' to (1, 9, 13)
    Strips patch suffixes like p1, p2, b1 etc.
    Returns (0, 0, 0) if parsing fails.
    """
    match = re.search(r'(\d+)\.(\d+)\.(\d+)', raw)
    if match:
        return tuple(int(x) for x in match.groups())
    # handle versions like 1.9 with no patch number
    match = re.search(r'(\d+)\.(\d+)', raw)
    if match:
        return (int(match.group(1)), int(match.group(2)), 0)
    return (0, 0, 0)