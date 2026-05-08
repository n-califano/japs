import re
from core.base_module import BaseModule
from core.context import RunContext
from core.utils import run_raw

CRED_PATTERNS = re.compile(
    r'(password|passwd|pass|pwd|secret|token|api.?key|credential)[s]?\s*[=:]\s*\S+',
    re.IGNORECASE
)

INTERESTING_PROCS = {
    "httpd", "apache", "apache2", "nginx", "tomcat",
    "mysql", "mysqld", "postgres", "mongod", "redis-server",
    "docker", "containerd", "kubelet",
    "python", "python3", "ruby", "php", "perl", "node",
}

class Module(BaseModule):
    name = "processes"
    description = ""
    tags = ["basic"]

    def collect(self, ctx: RunContext) -> None:
        self.ps_aux      = run_raw("ps aux 2>/dev/null")
        self.ps_eo = run_raw("ps -eo pid,ppid,user,comm,args --sort=ppid 2>/dev/null")
        self.pstree = run_raw("pstree -alp 2>/dev/null")
        #self.top         = run_raw("top -n 1 -b 2>/dev/null")
        self.current_user = run_raw("whoami 2>/dev/null").strip()
        self.writable_proc_binaries = run_raw(
            "ps aux 2>/dev/null | awk 'NR>1 {print $11}' | grep '^/' | sort -u | "
            "while read b; do [ -w \"$b\" ] && echo \"$b\"; done"
        )
        # Deleted executables. One line per PID with a (deleted) exe, format: PID|USER|TARGET|CMDLINE
        self.deleted_exes = run_raw(
            "for pid in /proc/[0-9]*/exe; do "
            "  exe=$(readlink \"$pid\" 2>/dev/null); "
            "  if echo \"$exe\" | grep -qF '(deleted)'; then "
            "    pidnum=${pid#/proc/}; "
            "    pidnum=${pidnum%/exe}; "
            "    user=$(stat -c %U /proc/$pidnum 2>/dev/null); "
            "    cmdline=$(tr '\\0' ' ' < /proc/$pidnum/cmdline 2>/dev/null); "
            "    echo \"$pidnum|$user|$exe|$cmdline\"; "
            "  fi; "
            "done"
        )
        self.deleted_open_files = run_raw("lsof +L1 2>/dev/null")
        self.ptrace_scope = run_raw("cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null")
        # check /dev/mem readability; use dd to test without outputting content
        self.dev_mem_readable = run_raw("dd if=/dev/mem bs=1 count=0 2>/dev/null && echo 'readable' || echo 'no'")
        # own processes – just PID and short command
        self.own_procs = run_raw("ps -u $(whoami) -o pid,comm --no-headers 2>/dev/null")

        self.add_raw("ps_aux", self.ps_aux)
        self.add_raw("ps_eo", self.ps_eo)
        self.add_raw("pstree", self.pstree)
        #self.add_raw("top",          self.top)
        self.add_raw("current_user", self.current_user)
        self.add_raw("writable_proc_binaries", self.writable_proc_binaries)
        self.add_raw("deleted_exes", self.deleted_exes)
        self.add_raw("deleted_open_files", self.deleted_open_files)
        self.add_raw("ptrace_scope", self.ptrace_scope)
        self.add_raw("dev_mem_readable", self.dev_mem_readable)
        self.add_raw("own_procs", self.own_procs)

    def analyse(self, collect_report: dict) -> None:
        self._populate_class(collect_report["raw_output"][self.name])

        if not self.ps_aux:
            return

        lines = self.ps_aux.strip().splitlines()[1:]  # skip header

        root_procs       = []
        other_user_procs = []
        cred_leaks       = []

        for line in lines:
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue

            user    = parts[0]
            command = parts[10].strip()
            binary_name = command.split()[0].split("/")[-1] if command.split() else ""

            if user == "root" and binary_name in INTERESTING_PROCS:
                root_procs.append((binary_name, command))

            if user not in ("root", self.current_user) and not user.startswith("_"):
                other_user_procs.append((user, command))

            if CRED_PATTERNS.search(command):
                cred_leaks.append((user, command))

        if root_procs:
            detail = "\n".join(f"  {name}: {cmd}" for name, cmd in root_procs)
            self.add_finding("INFO",
                f"Interesting processes running as root ({len(root_procs)} found)",
                f"Review for exploitable services or writable binaries:\n{detail}"
            )

        if other_user_procs:
            seen_users = sorted({u for u, _ in other_user_procs})
            detail = "\n".join(f"  {user}: {cmd}" for user, cmd in other_user_procs)
            self.add_finding("INFO",
                f"Processes running as other users: {', '.join(seen_users)}",
                f"Potential pivot targets:\n{detail}"
            )

        if cred_leaks:
            detail = "\n".join(f"  [{user}] {cmd}" for user, cmd in cred_leaks)
            self.add_finding("HIGH",
                f"Possible credentials in process arguments ({len(cred_leaks)} found)",
                f"Review carefully:\n{detail}"
            )

        self._analyse_debuggers(lines)
        self._analyse_writable_binaries()
        self._analyse_cross_user_chains()
        self._analyse_deleted_exes()
        self._analyse_deleted_files()
        self._analyse_process_memory()

    def _analyse_process_memory(self):
        # --- ptrace_scope analysis ---
        if self.ptrace_scope:
            scope = self.ptrace_scope.strip()
            if scope == "0":
                if self.own_procs:
                    procs = [l.strip().split(maxsplit=1) for l in self.own_procs.strip().splitlines() if l.strip()]
                    detail = "\n".join(
                        f"  PID {pid}  {comm}"
                        for pid, comm in procs
                    )
                    self.add_finding(
                        "HIGH",
                        f"ptrace_scope = 0 -> you can dump memory of your own processes ({len(procs)} found)",
                        f"Dump any of these using gdb or dd, then strings the output for credentials:\n{detail}\n"
                        "Example: gdb -p <PID> ; dump memory /tmp/dump $start $end ; strings /tmp/dump | grep -i pass"
                    )
            elif scope == "1":
                self.add_finding(
                    "INFO",
                    "ptrace_scope = 1 -> only a parent can ptrace its child",
                    "If you launched a process and it is still running, you may be able to attach to it with gdb -p <PID>. "
                    "Otherwise, memory dumping is restricted."
                )
            elif scope in ("2", "3"):
                self.add_finding(
                    "INFO",
                    f"ptrace_scope = {scope} -> memory dumping requires CAP_SYS_PTRACE (root)",
                    "No direct memory access for unprivileged users. Look for other vectors."
                )

        # --- /dev/mem readability ---
        if self.dev_mem_readable and "readable" in self.dev_mem_readable:
            self.add_finding(
                "HIGH",
                "/dev/mem is readable -> you have physical memory access",
                "Dump with: dd if=/dev/mem bs=1M of=/tmp/mem.dump   then strings the dump for secrets. "
                "This typically requires root or membership in the 'kmem' group."
            )

    def _analyse_deleted_files(self):
        if self.deleted_open_files:
            # lsof +L1 header line is present; strip it if needed
            content = self.deleted_open_files.strip()
            if content:
                line_count = len(content.splitlines()) - 1  # minus header
                if line_count > 0:
                    self.add_finding(
                        "INFO",
                        f"Deleted files still open ({line_count} file descriptors)",
                        "Processes have open handles to files that no longer exist on disk. "
                        "Recoverable via /proc/<PID>/fd/<FD>. Look for credentials, configs, database exports…"
                    )

    def _analyse_deleted_exes(self):
        if self.deleted_exes:
            lines = [l.strip() for l in self.deleted_exes.splitlines() if l.strip()]
            detail = "\n".join(
                f"  PID {pid} ({user}): {exe}  cmd: {cmdline}"
                for pid, user, exe, cmdline in (l.split('|', 3) for l in lines)
            )
            self.add_finding(
                "HIGH",
                f"Processes running from deleted executables ({len(lines)} found)",
                f"These binaries have been removed from disk but are still active. "
                f"Investigate for privileged processes, possible tampering, or recoverable secrets.\n{detail}"
            )

    def _analyse_writable_binaries(self):
        if self.writable_proc_binaries:
            binaries = [b.strip() for b in self.writable_proc_binaries.splitlines() if b.strip()]
            detail = "\n".join(f"  {b}" for b in binaries)
            self.add_finding("HIGH",
                f"Writable binaries found for running processes ({len(binaries)} found)",
                f"Overwriting these allows code execution as the user running them:\n{detail}"
            )

    def _analyse_debuggers(self, lines):
        debugger_procs = []
        for line in lines:
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue
            user    = parts[0]
            command = parts[10].strip()
            if "--inspect" in command:
                debugger_procs.append((user, command))

        if debugger_procs:
            detail = "\n".join(f"  [{user}] {cmd}" for user, cmd in debugger_procs)
            self.add_finding("HIGH",
                f"Electron/CEF/Chromium debugger interface detected ({len(debugger_procs)} process/es)",
                f"Processes with --inspect flag can be abused to execute arbitrary JS as that user:\n{detail}\n"
                "See: https://hacktricks.wiki/en/linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse.html"
            )

    def _analyse_cross_user_chains(self):
        if self.ps_eo:
            # build pid -> (user, comm, args) map
            proc_map = {}
            eo_lines = self.ps_eo.strip().splitlines()[1:]  # skip header

            for line in eo_lines:
                parts = line.split(None, 4)
                if len(parts) < 4:
                    continue
                pid  = parts[0].strip()
                ppid = parts[1].strip()
                user = parts[2].strip()
                comm = parts[3].strip()
                args = parts[4].strip() if len(parts) > 4 else ""
                proc_map[pid] = {"ppid": ppid, "user": user, "comm": comm, "args": args}

            # expected transitions to suppress
            EXPECTED_CHILD_USERS  = {"nobody", "www-data", "daemon", "messagebus",
                                    "systemd-network", "systemd-resolve", "syslog"}
            EXPECTED_PARENT_USERS = {"root"}

            suspicious_chains = []
            for pid, proc in proc_map.items():
                ppid = proc["ppid"]
                if ppid not in proc_map:
                    continue    # parent process not available
                parent = proc_map[ppid]

                child_user  = proc["user"]
                parent_user = parent["user"]

                # same user, not interesting
                if child_user == parent_user:
                    continue

                # filter expected daemon dropdowns
                if parent_user in EXPECTED_PARENT_USERS and child_user in EXPECTED_CHILD_USERS:
                    continue

                suspicious_chains.append((
                    parent_user, parent["comm"], ppid,
                    child_user,  proc["comm"],   pid
                ))

            if suspicious_chains:
                detail = "\n".join(
                    f"  [{p_user}] {p_comm} (pid {ppid}) → [{c_user}] {c_comm} (pid {pid})"
                    for p_user, p_comm, ppid, c_user, c_comm, pid in suspicious_chains
                )
                self.add_finding("INFO",
                    f"Cross-user parent-child chains detected ({len(suspicious_chains)} found)",
                    f"Inspect parent command lines, configs, EnvironmentFiles, helper scripts, "
                    f"and working directories for writable paths:\n{detail}"
                )

            # flag specifically: current user is parent of a root process
            owned_parent_of_root = [
                (proc["comm"], pid, proc_map[proc["ppid"]]["comm"], proc["ppid"])
                for pid, proc in proc_map.items()
                if proc["user"] == "root"
                and proc["ppid"] in proc_map
                and proc_map[proc["ppid"]]["user"] == self.current_user
            ]
            if owned_parent_of_root:
                detail = "\n".join(
                    f"  you ({self.current_user}) → [{r_comm} pid {pid}] via parent [{p_comm} pid {ppid}]"
                    for r_comm, pid, p_comm, ppid in owned_parent_of_root
                )
                self.add_finding("HIGH",
                    f"Current user is parent of root-owned process(es) ({len(owned_parent_of_root)} found)",
                    f"You control the parent: inspect its config, EnvironmentFile, and helper scripts:\n{detail}"
                )

    def _populate_class(self, raw_data_dict: dict):
        get = lambda key: raw_data_dict.get(key, "")

        self.ps_aux       = get("ps_aux")
        #self.ps_ef        = get("ps_ef")
        #self.top          = get("top")
        self.current_user = get("current_user").strip()
        self.writable_proc_binaries = get("writable_proc_binaries")
        self.ps_eo  = get("ps_eo")
        self.pstree = get("pstree")
        self.deleted_exes = get("deleted_exes")
        self.deleted_open_files = get("deleted_open_files")
        self.ptrace_scope = get("ptrace_scope")
        self.dev_mem_readable = get("dev_mem_readable")
        self.own_procs = get("own_procs")