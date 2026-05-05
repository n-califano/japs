from core.base_module import BaseModule
from core.context import RunContext
from core.utils import run_raw

USEFUL_BINARIES = [
    # network / transfer
    "nmap", "nc", "ncat", "netcat", "nc.traditional", "wget", "curl", "ping", "socat", "fetch",
    # scripting / languages
    "python", "python2", "python3", "python2.6", "python2.7", "python3.6", "python3.7",
    "perl", "php", "ruby",
    # compilers / build
    "gcc", "g++", "make", "gdb",
    # encoding
    "base64",
    # cloud / containers
    "aws", "docker", "lxc", "ctr", "runc", "rkt", "kubectl",
    # privesc-relevant
    "doas", "sudo", "xterm",
]

# Binaries that are directly dangerous regardless of context
HIGH_INTEREST = {"nmap", "socat", "nc", "ncat", "netcat", "nc.traditional",
                "docker", "lxc", "ctr", "runc", "rkt", "kubectl", "doas"}

# Scripting interpreters: useful for payload execution / shell spawning
INTERPRETERS = {"python", "python2", "python3", "python2.6", "python2.7",
                "python3.6", "python3.7", "perl", "php", "ruby"}

class Module(BaseModule):
    name = "software"
    description = ""
    tags = ["basic"]

    def collect(self, ctx: RunContext) -> None:
        # which for every binary in one shell invocation
        binary_list = " ".join(USEFUL_BINARIES)
        self.found_binaries_raw = run_raw(f"which {binary_list} 2>/dev/null")

        # compiler detection: covers Debian (dpkg), RHEL (yum), and fallback (locate)
        self.compilers_raw = run_raw(
            "(dpkg --list 2>/dev/null | grep 'compiler' | grep -v 'decompiler\\|lib' "
            "|| yum list installed 'gcc*' 2>/dev/null | grep gcc) ; "
            "which gcc g++ 2>/dev/null || locate -r '/gcc[0-9\\.-]\\+$' 2>/dev/null | grep -v '/doc/'"
        )
        # full package list, kept raw for grepping, not printed whole
        self.packages_dpkg = run_raw("dpkg -l 2>/dev/null")
        self.packages_rpm  = run_raw("rpm -qa 2>/dev/null")

    def analyse(self, ctx: RunContext) -> None:
        # Binaries
        found = []
        if self.found_binaries_raw:
            # `which` returns one resolved path per line
            found = [p.strip() for p in self.found_binaries_raw.splitlines() if p.strip()]
            self.add_raw("Useful binaries found", "\n".join(found))

            found_names = {p.split("/")[-1] for p in found}   # basename only for set lookups

            high     = sorted(found_names & HIGH_INTEREST)
            interps  = sorted(found_names & INTERPRETERS)
            compilers = sorted(found_names & {"gcc", "g++", "make", "gdb"})

            if high:
                self.add_finding("INFO",f"High-interest binaries present: {', '.join(high)}",
                    "These are commonly used in post-exploitation and lateral movement, "
                    "check GTFOBins for each: https://gtfobins.github.io")
            if interps:
                self.add_finding("INFO", f"Script interpreters available: {', '.join(interps)}",
                    "Useful for spawning shells or running payloads; "
                    "e.g. python3 -c \"import pty; pty.spawn('/bin/bash')\"")

            # Compilers
            if self.compilers_raw or compilers:
                if self.compilers_raw:
                    self.add_raw("Compilers detected", self.compilers_raw)
                self.add_finding("INFO", f"Compiler toolchain present: {', '.join(compilers) if compilers else 'see raw output'}",
                    "Kernel exploits should be compiled on the target machine (or an identical one) "
                    "to match kernel headers and glibc version: having gcc here is a significant aid"
                )

        # Installed packages
        pkg_source = None
        pkg_data   = None
        if self.packages_dpkg:
            pkg_source = "dpkg"
            pkg_data   = self.packages_dpkg
        elif self.packages_rpm:
            pkg_source = "rpm"
            pkg_data   = self.packages_rpm

        if pkg_data:
            pkg_count = len(pkg_data.strip().splitlines())
            #TODO: should automate the finding of vulnerabilities in this pkg list (searchsploit, OSV / NVD APIs)
            # but running api calls and doing too much processing on the target machine is not stealth
            # consider splitting the script in two parts:
            # - part 1: collect the informations and create a structured report (json). this is run on target
            # - part 2: analyse the json with additional tools and produce the final report. this runs on attacking machine
            self.add_finding("INFO", f"Package list retrieved via {pkg_source} ({pkg_count} lines), manual review recommended",
                "Look for old versions of Nagios, Exim, Sudo, screen, tmux, OpenSMTPD, etc. "
                "Automated scanning with OpenVAS is recommended for thorough CVE coverage")