from core.base_module import BaseModule
from core.context import RunContext
from core.utils import run_raw
import os
import re


class Module(BaseModule):
    name = "cron"
    description = ""
    tags = ["basic"]

    def collect(self, ctx: RunContext) -> None:
        # user crontab (may fail if no crontab)
        self.crontab_user = run_raw("crontab -l 2>/dev/null")
        self.add_raw("crontab_user", self.crontab_user)

        # system‑wide cron dirs and files
        self.ls_cron_dirs = run_raw("ls -al /etc/cron* /etc/at* 2>/dev/null")
        self.cat_cron_files = run_raw(
            "cat /etc/cron* /etc/at* /etc/anacrontab "
            "/var/spool/cron/crontabs/root 2>/dev/null | grep -v '^#'"
        )
        self.add_raw("ls_cron_dirs", self.ls_cron_dirs)
        self.add_raw("cat_cron_files", self.cat_cron_files)

        # run-parts --test for the typical periodic dirs (if they exist)
        run_parts_output = ""
        for d in ["cron.hourly", "cron.daily", "cron.weekly", "cron.monthly"]:
            if os.path.isdir(f"/etc/{d}"):
                out = run_raw(f"run-parts --test /etc/{d} 2>/dev/null")
                if out.strip():
                    run_parts_output += f"\n--- /etc/{d} ---\n{out}"
        self.run_parts_test = run_parts_output
        self.add_raw("run_parts_test", self.run_parts_test)

        self._collect_writable_cron_dirs()
        self._collect_crontab_ui()
        self._collect_writable_path_dirs_in_cron_files()

        # collect contents of all periodic cron scripts (hourly, daily, weekly, monthly)
        self.cron_scripts_content = run_raw(
            "cat /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* 2>/dev/null"
        )
        self.add_raw("cron_scripts_content", self.cron_scripts_content)

        # --- Individually writable cron script files ---
        self.writable_cron_scripts = run_raw(
            "find /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly "
            "-type f -writable 2>/dev/null"
        )
        self.add_raw("writable_cron_scripts", self.writable_cron_scripts)

        self._collect_symlinks()
        self._collect_writable_binaries()
        self._collect_frequent_cron_jobs()

        # Collect a list of all directories writable by the current user.
        # We'll use this for multiple checks (backup source, symlink hijack, etc.).
        self.writable_dirs = run_raw("find / -type d -writable 2>/dev/null | grep -vE '^/(proc|sys|dev|run|snap)'")
        self.add_raw("writable_dirs", self.writable_dirs)

        # --- Invisible cron jobs detection (carriage return trick) ---
        self.cron_invisible_raw = run_raw(
            "cat -A /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null; "
            "sed -n 'l' /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null"
        )
        self.add_raw("cron_invisible_raw", self.cron_invisible_raw)

    def analyse(self, collect_report: dict) -> None:
        self._populate_class(collect_report["raw_output"][self.name])

        self._analyse_writable_dirs()

        # Display cron contents for manual review
        if self.cat_cron_files or self.crontab_user:
            summary = ""
            if self.cat_cron_files:
                summary += f"System cron files (non-comments):\n{self.cat_cron_files[:1000]}...\n"
            if self.crontab_user:
                summary += f"User crontab:\n{self.crontab_user[:500]}...\n"
            self.add_finding(
                "INFO",
                "Cron jobs present. manual review for vulnerable scripts/paths",
                summary +
                "Look for: writable scripts, wildcard vulnerabilities, PATH abuse, "
                "or scripts that reference files in world-writable directories."
            )

        # run-parts --test reveals actual script names that would be executed
        if self.run_parts_test.strip():
            self.add_finding(
                "INFO",
                "run-parts --test output available",
                "Lists all scripts that will be run by cron. If a directory is writable, "
                "your script must follow the naming convention shown (see 'man run-parts').\n"
                f"{self.run_parts_test.strip()[:1000]}"
            )

        self._analyse_crontab_ui()
        self._analyse_cron_path()
        self._analyse_scripts_content()
        self._analyse_bash_arithmetic_injection()
        self._analyse_writable_cron_scripts()
        self._analyse_directories_used_by_cron_scripts_for_symlink_hijack()
        self._analyse_symlinks()
        self._analyse_writable_binaries()
        self._analyse_frequent_cron_jobs()
        self._analyse_invisible_cron_jobs()

    def _analyse_invisible_cron_jobs(self):
        # --- Invisible cron jobs (carriage return after comment) ---
        if self.cron_invisible_raw:
            ref_url = "https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#invisible-cron-jobs"
            # Search for carriage return indicators in the raw output
            if '^M' in self.cron_invisible_raw or '\\r' in self.cron_invisible_raw:
                self.add_finding(
                    "HIGH",
                    "Invisible cron job detected via carriage return trick",
                    "A carriage return (\\r) in a cron file can hide a cron job on a line after a comment. "
                    "The raw output shows the control character (^M or \\r). This is a known stealth technique. "
                    "Review the raw output below to identify the hidden entry.\n\n"
                    f"{self.cron_invisible_raw[:2000]}",
                    ref_url
                )
            else:
                # No hidden entries, but still provide for manual review if curious
                self.add_finding(
                    "INFO",
                    "No invisible cron jobs found (carriage return check passed)",
                    ref_url
                )

    def _analyse_frequent_cron_jobs(self):
        # --- Frequent cron job detection ---
        if self.frequent_procs:
            suspicious = []
            for line in self.frequent_procs.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split(None, 1)       # split count and command
                if len(parts) < 2:
                    continue
                try:
                    count = int(parts[0])
                except ValueError:
                    continue
                command = parts[1].strip()

                # ignore monitoring overhead
                if command.startswith("ps -e") or command.startswith("sleep"):
                    continue

                # Very long command lines are unlikely to be cron jobs and clutter output
                if len(command) > 200:
                    continue

                # Only commands that appear a handful of times (1–10) in one minute
                # are likely periodic tasks, more than that is a persistent daemon.
                if 1 <= count <= 10:
                    suspicious.append((count, command))

            if suspicious:
                detail = "\n".join(f"  {cnt}x : {cmd}" for cnt, cmd in suspicious[:20])
                if len(suspicious) > 20:
                    detail += f"\n  ... and {len(suspicious)-20} more"
                self.add_finding(
                    "INFO",
                    f"Low-frequency recurrent processes found ({len(suspicious)} candidates)",
                    f"These appeared only a few times per minute -> likely cron jobs or timers. "
                    f"Review for writable scripts, wildcards, or PATH abuse.\n{detail}",
                    "https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#frequent-cron-jobs"
                )

    def _analyse_writable_binaries(self):
        # --- Custom-signed writable cron binaries ---
        if self.writable_cron_binaries:
            binaries = [b.strip() for b in self.writable_cron_binaries.splitlines() if b.strip()]
            if binaries:
                detail = "\n".join(f"  {b}" for b in sorted(binaries))
                self.add_finding(
                    "HIGH",
                    f"Writable ELF binaries in cron directories ({len(binaries)} found)",
                    "These are potentially custom-signed binaries executed via root cron. "
                    "If you are in the group that can write to them, you may be able to "
                    "replace the binary while preserving the expected signature (requires "
                    "leaking the signing material and observing the verification flow with pspy).\n"
                    f"{detail}\n\n"
                    "Manual steps: 1) run pspy to see the verify-and-execute pattern. "
                    "2) Leak the signing cert from backups/configs. "
                    "3) Forge a malicious ELF with the correct cert section.",
                    "https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#custom-signed-cron-binaries-with-writable-payloads"
                )

    def _analyse_symlinks(self):
        if self.symlinks_raw.strip():
            # The raw output contains interleaved readlink results and namei blocks;
            # we'll just present it as is for manual review.
            self.add_finding(
                "INFO",
                "Symlinks found in cron directories -> manual review for hijack opportunities",
                "Symlinks can redirect privileged writes to attacker-controlled locations. "
                "Check each target and verify that no intermediate directory is writable.\n\n"
                f"Full output:\n{self.symlinks_raw.strip()[:2000]}",
                "https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#symlink-validation-and-safer-file-handling"
            )

    def _analyse_directories_used_by_cron_scripts_for_symlink_hijack(self):
        if self.cron_scripts_content and self.writable_dirs:
            writable_dir_set = set(d.strip() for d in self.writable_dirs.splitlines() if d.strip())

            # Extract candidate directories from cron script content
            path_pattern = re.compile(r'/[a-zA-Z0-9._/-]+')
            raw_paths = path_pattern.findall(self.cron_scripts_content)
            candidate_dirs = set()
            for path in raw_paths:
                # skip virtual filesystems
                if path.startswith('/proc') or path.startswith('/sys') or path.startswith('/dev'):
                    continue
                dir_path = os.path.dirname(path)
                if dir_path not in ('/', ''):
                    candidate_dirs.add(dir_path)

            writable_dirs_found = []
            for d in candidate_dirs:
                if d in writable_dir_set:
                    writable_dirs_found.append(d)
                else:
                    parent = os.path.dirname(d)
                    if parent in writable_dir_set:
                        writable_dirs_found.append(f"{d} (via parent {parent})")

            if writable_dirs_found:
                detail = "\n".join(f"  {d}" for d in sorted(writable_dirs_found)[:15])
                if len(writable_dirs_found) > 15:
                    detail += f"\n  ... and {len(writable_dirs_found)-15} more"
                self.add_finding(
                    "HIGH",
                    f"Directories used by cron scripts are writable or can be hijacked ({len(writable_dirs_found)} found)",
                    f"These directories are referenced by root cron scripts and are modifiable by you.\n"
                    f"Possible attack: delete the directory and replace it with a symlink...\n{detail}",
                    "https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#cron-script-overwriting-and-symlink"
                )

    def _analyse_writable_cron_scripts(self):
        if self.writable_cron_scripts:
            scripts = [s.strip() for s in self.writable_cron_scripts.splitlines() if s.strip()]
            if scripts:
                self.add_finding(
                    "HIGH",
                    f"You can write to {len(scripts)} cron script(s)",
                    "Overwriting a cron script executed as root will give immediate command execution.\n"
                    f"Writable scripts:\n{chr(10).join(scripts)}\n\n"
                    "Example payload: echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /etc/cron.hourly/script"
                )        

    def _analyse_bash_arithmetic_injection(self):
        if self.cron_scripts_content:
            arith_lines = []
            for line in self.cron_scripts_content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                # look for arithmetic expansion or let builtin
                if re.search(r'\(\(|let\s+\S+=', stripped):
                    arith_lines.append(stripped)

            if arith_lines:
                preview = "\n".join(arith_lines[:10])
                if len(arith_lines) > 10:
                    preview += f"\n... and {len(arith_lines)-10} more lines"
                self.add_finding(
                    "INFO",
                    f"Cron scripts use arithmetic evaluation ({len(arith_lines)} line(s))",
                    f"Manual review required if any of these scripts operate on attacker-controllable input "
                    f"(logs, files, network data). Arithmetic injection can lead to code execution as root.\n{preview}\n",
                    "https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#bash-arithmetic-expansion-injection-in-cron-log-parsers"
                )

    def _analyse_scripts_content(self):
        # --- Look for wildcard injection in cron scripts ---
        self._check_wildcard_injection()
        self._check_backup_job_with_writable_source()

    def _analyse_cron_path(self):
        # --- Cron PATH hijack ---
        if self.cron_path_writable:
            writable_paths = [p.strip() for p in self.cron_path_writable.splitlines() if p.strip()]
            if writable_paths:
                self.add_finding(
                    "HIGH",
                    f"Writable directory in cron's PATH ({len(writable_paths)} found)",
                    "If a cron job runs a command without an absolute path, you can plant a "
                    "malicious script with the same name in one of these directories.\n"
                    f"Writable dirs: {', '.join(writable_paths)}\n"
                    "Example: echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh"
                )

    def _analyse_crontab_ui(self):
        ui_detected = self.crontab_ui_proc.strip() or self.localhost_8000.strip()

        if ui_detected:
            details = ""
            if self.crontab_ui_proc.strip():
                details += f"Process found:\n{self.crontab_ui_proc.strip()}\n"
            if self.localhost_8000.strip():
                details += f"Listening on localhost:8000:\n{self.localhost_8000.strip()}\n"
            self.add_finding(
                "HIGH",
                "Crontab UI (alseambusher) possibly running as root on localhost:8000",
                "If this web UI is accessible (even via SSH tunnel), you can schedule a root job. "
                "Look for Basic-Auth credentials in backups, environment files, or scripts.\n" + details
            )

    def _analyse_writable_dirs(self):
        if self.writable_cron_dirs:
            writable = [w for w in self.writable_cron_dirs.splitlines() if w.strip()]
            if writable:
                self.add_finding(
                    "HIGH",
                    f"Writable cron resource(s) found ({len(writable)}): {', '.join(writable)}",
                    "You can write to a cron directory or crontab file. This allows arbitrary command "
                    "execution as the user that runs the cron job (often root). Place a script in a "
                    "cron.hourly/daily directory, or append a job to a writable crontab file. "
                    "Check run-parts naming rules if targeting a periodic directory."
                )

    def _collect_frequent_cron_jobs(self):
        # TODO: may be worth to extend the monitoring to at least 5 minutes
        # Frequent cron jobs: monitor processes for ~61 seconds, then count occurrences
        self.frequent_procs = run_raw(
            "for i in $(seq 1 610); do ps -e --format cmd 2>/dev/null; sleep 0.1; done | "
            "sort | uniq -c | grep -v '\\['; "
        )
        self.add_raw("frequent_procs", self.frequent_procs)
    
    def _collect_writable_binaries(self):
        # --- Writable executables called by cron (potential custom-signed binaries) ---
        self.writable_cron_binaries = run_raw(
            "( find /etc/cron* /var/spool/cron -type f "
            "  \\( -perm -002 -o -perm -020 \\) "
            "  -exec file {} \\; "
            "  | grep 'ELF' "
            "  | cut -d: -f1 ) 2>/dev/null"
        )
        self.add_raw("writable_cron_binaries", self.writable_cron_binaries)
    
    def _collect_symlinks(self):
        # Find all symlinks under usual cron locations
        # readlink -f -> final target
        # namei -l -> full path resolution with permissions
        self.symlinks_raw = run_raw(
            "find /etc/cron* /var/spool/cron -type l "
            "\\( -exec readlink -f {} \\; \\) "
            "\\( -exec sh -c 'echo \"--- TARGET FOR {} ---\"' \\; \\) "
            "\\( -exec namei -l {} \\; \\) "
            "2>/dev/null"
        )
        self.add_raw("symlinks_raw", self.symlinks_raw)
    
    def _collect_writable_path_dirs_in_cron_files(self):
        # Look for 'PATH=' lines in cron files and take only writable dirs
        self.cron_path_writable = run_raw(
            "cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null "
            "| grep -E '^[[:space:]]*PATH=' "
            "| while IFS='=' read -r _ path_value; do "
            "  echo \"$path_value\" | tr ':' '\\n' | while read dir; do "
            "    if [ -w \"$dir\" ]; then echo \"$dir\"; fi; "
            "  done; "
            "done | sort -u"
        )
        self.add_raw("cron_path_writable", self.cron_path_writable)
    
    def _collect_crontab_ui(self):
        # Crontab UI detection: look for its process or listening port
        self.crontab_ui_proc = run_raw("ps aux 2>/dev/null | grep -E 'alseambusher|crontab.ui' | grep -v grep")
        self.localhost_8000 = run_raw("ss -ntlp 2>/dev/null | grep '127.0.0.1:8000'")

        self.add_raw("crontab_ui_proc", self.crontab_ui_proc)
        self.add_raw("localhost_8000", self.localhost_8000)

    def _collect_writable_cron_dirs(self):
        # writability of key cron resources (current user)
        # directories first: if writable, we can drop scripts
        writable_items = []
        for path in [
            "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
            "/etc/cron.monthly", "/etc/cron.d", "/etc/crontab",
            "/var/spool/cron/crontabs",
        ]:
            if os.path.exists(path):
                if os.access(path, os.W_OK):
                    writable_items.append(path)
                elif os.path.isdir(path) and run_raw(f"test -w '{path}' && echo yes || echo no").strip() == "yes":
                    # fallback in case os.access doesn't capture all
                    writable_items.append(path)
        self.writable_cron_dirs = "\n".join(writable_items)

        self.add_raw("writable_cron_dirs", self.writable_cron_dirs)

    def _populate_class(self, raw_data_dict: dict):
        get = lambda key: raw_data_dict.get(key, "")

        self.crontab_user = get("crontab_user")
        self.ls_cron_dirs = get("ls_cron_dirs")
        self.cat_cron_files = get("cat_cron_files")
        self.run_parts_test = get("run_parts_test")
        self.writable_cron_dirs = get("writable_cron_dirs")
        self.crontab_ui_proc = get("crontab_ui_proc")
        self.localhost_8000 = get("localhost_8000")
        self.cron_path_writable = get("cron_path_writable")
        self.cron_scripts_content = get("cron_scripts_content")
        self.writable_cron_scripts = get("writable_cron_scripts")
        self.symlinks_raw = get("symlinks_raw")
        self.writable_cron_binaries = get("writable_cron_binaries")
        self.writable_dirs = get("writable_dirs")
        self.cron_invisible_raw = get("cron_invisible_raw")
        self.frequent_procs = get("frequent_procs")

    def _check_wildcard_injection(self):
        if self.cron_scripts_content:
            # Simple pattern: a single asterisk (or ?) as an argument, not preceded by a path
            # This matches lines like: tar cvf backup.tar *
            # We avoid false positives on: /some/path/* or ./*
            wildcard_re = re.compile(r'(?<!\S)\*(?=\s|$|;)|(?<!\S)\?(?=\s|$|;)')

            suspicious_lines = []
            script_text = self.cron_scripts_content
            for line in script_text.splitlines():
                # skip comment/empty lines
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # find wildcard usage
                if wildcard_re.search(line):
                    suspicious_lines.append(line)

            if suspicious_lines:
                # limit output to avoid flooding
                preview = "\n".join(suspicious_lines[:20])
                if len(suspicious_lines) > 20:
                    preview += f"\n... and {len(suspicious_lines)-20} more lines"
                self.add_finding(
                    "HIGH",
                    f"Potential wildcard injection in cron scripts ({len(suspicious_lines)} suspicious line(s))",
                    "Lines with unquoted wildcards (* or ?) may be exploitable. "
                    "If the script runs as root, an attacker can create filenames that expand to command-line options.\n"
                    "Examples: rsync -a *.sh, tar cf *\n"
                    f"{preview}\n\n"
                    "Exploit: create files like '-e sh /tmp/script.sh' in the working directory."
                )
    
    def _check_backup_job_with_writable_source(self):
        # --- Root backup job with writable source ---
        if self.cron_scripts_content and self.writable_dirs:
            # Load the set of writable directories (pre‑collected on target)
            writable_dir_set = set(
                d.strip() for d in self.writable_dirs.splitlines() if d.strip()
            )
            # Commands that may copy a directory tree and preserve permissions
            BACKUP_CMDS = [
                "pg_basebackup", "rsync", "cp -a", "cp -r", "tar ", "cpio", "dump ", "rclone"
            ]
            for line in self.cron_scripts_content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if any(cmd in line for cmd in BACKUP_CMDS):
                    # Extract all absolute paths from the line
                    paths = re.findall(r'/[^\s\'"]*', line)
                    writable_in_cmd = [p for p in paths if p in writable_dir_set]
                    if writable_in_cmd:
                        self.add_finding(
                            "HIGH",
                            f"Root cron backup job uses a writable directory (source or destination)",
                            f"Command: {line}\n"
                            f"Writable directories detected: {', '.join(writable_in_cmd)}\n"
                            "WARNING: These may include the backup *destination*, which is often also writable. "
                            "Manually identify the **source** directory (the one being copied), "
                            "place a SUID binary there (cp /bin/bash .; chmod 6777 bash), "
                            "and wait for the cron job to copy it as root, preserving the setuid bit.",
                            "https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#root-backups-that-preserve-attacker-set-mode-bits-pg_basebackup"
                        )
                    else:
                        # Still interesting – maybe the source becomes writable later
                        self.add_finding(
                            "INFO",
                            f"Root cron job runs backup/copy command: {line}",
                            "Check source directory permissions manually. "
                            "If you can write to the source, plant a SUID binary and wait for the backup.",
                            "https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#root-backups-that-preserve-attacker-set-mode-bits-pg_basebackup"
                        )