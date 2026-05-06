from core.base_module import BaseModule, RawOutput
from core.context import RunContext
from core.utils import run_raw, is_writable, parse_sudo_version

class Module(BaseModule):
    name = "system_info"
    description = "Kernel version, OS details, environment variables, sudo, dmesg, date, stats, cpu, printers, defenses"
    tags = ["basic"]

    def collect(self, ctx: RunContext) -> None:
        self._collect_os_info()
        self._collect_path()
        self._collect_env_info()
        self._collect_sudo()
        self._collect_dmesg()
        self._collect_date()
        self._collect_stats()
        self._collect_cpu()
        self._collect_printers()
        self._collect_defenses()
        
    def analyse(self, collect_report: dict) -> None:
        self._populate_class(collect_report["raw_output"][self.name])

        self._analyse_os_info()
        self._analyse_path()
        self._analyse_env_info()
        self._analyse_sudo()
        self._analyse_dmesg()
        self._analyse_date()
        self._analyse_stats()
        self._analyse_cpu()
        self._analyse_printers()
        self._analyse_defenses()


    def _collect_defenses(self):
        # AppArmor
        self.apparmor = (
            run_raw("aa-status 2>/dev/null") or
            run_raw("apparmor_status 2>/dev/null") or
            run_raw("ls -d /etc/apparmor* 2>/dev/null")
        )
        self.add_raw("AppArmor", self.apparmor)

        # SELinux
        self.selinux = run_raw("sestatus 2>/dev/null")
        self.add_raw("SELinux", self.selinux)

        # Grsecurity
        self.grsec = (
            run_raw("uname -r 2>/dev/null | grep -i grsec") or
            run_raw("grep -s 'grsecurity' /etc/sysctl.conf 2>/dev/null")
        )
        self.add_raw("Grsecurity", self.grsec)

        # PaX
        self.pax = run_raw("which paxctl-ng paxctl 2>/dev/null")
        self.add_raw("PaX", self.pax)

        # Execshield
        self.execshield = run_raw("grep 'exec-shield' /etc/sysctl.conf 2>/dev/null")
        self.add_raw("Execshield", self.execshield)

        # ASLR
        self.aslr = run_raw("cat /proc/sys/kernel/randomize_va_space 2>/dev/null")
        self.add_raw("ASLR (randomize_va_space)", self.aslr)

    def _analyse_defenses(self):
        # AppArmor
        if "not have enough privilege" in self.apparmor.lower() or "loaded" in self.apparmor.lower():
            self.add_finding("INFO", "AppArmor is loaded, profile details require root")

        # SELinux
        if self.selinux and "disabled" not in self.selinux.lower():
            self.add_finding("INFO", "SELinux is present, profile details require root")

        # Combined absence check: neither AppArmor nor SELinux present at all
        if not self.apparmor and (not self.selinux or "disabled" in self.selinux.lower()):
            self.add_finding("MEDIUM", "No active MAC system found (AppArmor or SELinux)",
                "No mandatory access control detected")

        # Grsecurity
        if self.grsec:
            self.add_finding("INFO", "Grsecurity detected", "Kernel hardening is active: memory corruption exploits are significantly harder")

        # PaX
        if self.pax:
            self.add_finding("INFO", "PaX detected", "Memory protection is active: RWX memory pages restricted")

        # Execshield
        if self.execshield:
            self.add_finding("INFO", "Execshield is configured", "Legacy non-executable stack protection: relevant only on very old systems")

        # ASLR
        if self.aslr:
            if self.aslr.strip() == "0":
                self.add_finding("HIGH","ASLR is disabled (randomize_va_space=0)",
                    "Memory addresses are predictable: memory corruption exploits do not need address leaks\n"
                    "Return-oriented programming and heap exploitation are significantly easier")
            elif self.aslr.strip() == "1":
                self.add_finding("MEDIUM", "ASLR is partially enabled (randomize_va_space=1)",
                    "Stack and VDSO are randomised but heap is not: partial bypass may be possible")
            else:
                self.add_finding("INFO", "ASLR is fully enabled (randomize_va_space=2)")

    def _collect_printers(self):
        self.printers     = run_raw("lpstat -a 2>/dev/null")
        self.add_raw("lpstat -a", self.printers)

        self.cups_version = run_raw("cups-config --version 2>/dev/null")
        self.add_raw("CUPS version", self.cups_version)

        self.cups_service = run_raw("systemctl is-active cups 2>/dev/null")
        self.add_raw("CUPS service", self.cups_service)

    def _analyse_printers(self):
        cups_running = self.cups_service.strip() == "active"
        cups_present = bool(self.cups_version)

        if cups_running:
            self.add_finding(
                "INFO",
                f"CUPS printing service is active (version {self.cups_version})",
                "CUPS has historical privesc CVEs: check version"
            )
        elif cups_present:
            self.add_finding(
                "INFO",
                f"CUPS installed but not active (version {self.cups_version})",
            )
        elif self.printers:
            self.add_finding(
                "INFO",
                "Print queues detected but CUPS status unclear, may be remote print server",
            )
   
    def _collect_cpu(self):
        self.cpu = run_raw("lscpu 2>/dev/null")
        self.add_raw("lscpu", self.cpu)

    def _analyse_cpu(self):
        VM_INDICATORS = {
            "KVM":          "KVM hypervisor",
            "QEMU":         "QEMU virtualisation",
            "VMware":       "VMware hypervisor",
            "VirtualBox":   "VirtualBox hypervisor",
            "Xen":          "Xen hypervisor",
            "Microsoft":    "Hyper-V hypervisor",
            "bochs":        "Bochs emulator",
            "Virtualization type:": "hardware virtualisation active",
            "hypervisor":   "hypervisor flag present in CPU flags",
        }

        cpu_lower = self.cpu.lower()
        hits = []
        for indicator, description in VM_INDICATORS.items():
            if indicator.lower() in cpu_lower:
                hits.append(description)

        if hits:
            self.add_finding(
                "INFO",
                "Running inside a virtual machine",
                "\n".join(f"- {h}" for h in hits) + 
                "\nConfirm architecture before compiling or running exploits"
            )

    def _collect_stats(self):
        self.df      = run_raw("df -h 2>/dev/null")
        self.add_raw("df -h", self.df)

        self.lsblk   = run_raw("lsblk 2>/dev/null")
        self.add_raw("lsblk", self.lsblk)

    def _analyse_stats(self):
        # Flag NFS mounts: no_root_squash is a privesc vector
        nfs_mounts = [
            line for line in self.df.splitlines()
            if line.startswith("//") or ":/" in line.split()[0]
        ]
        if nfs_mounts:
            self.add_finding(
                "MEDIUM",
                "NFS mounts detected: check for no_root_squash",
                "\n".join(nfs_mounts),
                "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration-pe"
            )

    def _collect_date(self):
        self.date = run_raw("date 2>/dev/null")
        self.add_raw("date", self.date)

    def _analyse_date(self):
        pass

    def _collect_dmesg(self):
        self.dmesg_sig = run_raw("dmesg 2>/dev/null | grep -iE 'signature|taint|unsigned module'")
        self.add_raw("dmesg signature warnings", self.dmesg_sig)

    def _analyse_dmesg(self):
        if self.dmesg_sig:
            self.add_finding(
                "MEDIUM",
                "Kernel module signature warnings found in dmesg",
                "Kernel integrity checking is producing warnings: unsigned or modified modules may be loadable.\n"
                "Check out https://app.hackthebox.com/machines/Smasher2?sort_by=created_at&sort_type=desc on how to exploit",
                "https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#dmesg-signature-verification-failed"
            )

    def _collect_sudo(self):
        self.sudo_version_raw = run_raw("sudo -V 2>/dev/null | grep 'Sudo ver'")    #ex: "Sudo version 1.8.27"
        self.add_raw("sudo", self.sudo_version_raw)

        self.chroot_test = run_raw("sudo -n -R woot woot </dev/null 2>&1", timeout=3)
        self.add_raw("chroot_escalation_test", self.chroot_test)

    def _analyse_sudo(self):
        v = parse_sudo_version(self.sudo_version_raw)

        # Broad check
        if v < (1, 8, 28):
            self.add_finding("HIGH", f"{self.sudo_version_raw} matches known vulnerable range (< 1.8.28)", 
                             "exploit 'sudo -u#-1 /bin/bash' may work", 
                             "https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version")

        if (1, 8, 8) <= v < (1, 9, 17):
            self.add_finding("MEDIUM", "CVE-2025-32462 host bypass, check for host-based sudoers rules", None,
                             "https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-host-based-rules-bypass-cve-2025-32462")

        if (1, 9, 14) <= v < (1, 9, 17) and self._is_chroot_vulnerable():
            self.add_finding("HIGH", "CVE-2025-32463 chroot escalation", "PoC: https://github.com/pr0v3rbs/CVE-2025-32463_chwoot",
                             "https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo--1917p1")

    def _collect_env_info(self):
        self.env_output = run_raw("(env || set) 2>/dev/null")
        self.add_raw("env", self.env_output)

    def _analyse_env_info(self):
        SENSITIVE_KEYWORDS = ["PASS", "SECRET", "TOKEN", "API_KEY", "CREDENTIAL", "AUTH", "PRIVATE"]

        sensitive = [
            line for line in self.env_output.splitlines()
            if any(k in line.upper() for k in SENSITIVE_KEYWORDS)
            and "=" in line  # make sure it's actually a variable assignment with a value
        ]

        if sensitive:
            self.add_finding(
                "HIGH",
                "Sensitive values found in environment variables",
                "\n".join(sensitive),
                "https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#env-info"
            )

    def _collect_path(self):
        self.path_raw = run_raw("echo $PATH")
        self.add_raw("$PATH", self.path_raw)

    def _analyse_path(self):
        path_dirs = self.path_raw.split(":")

        writable = [d for d in path_dirs if d and is_writable(d)]
        for d in writable:
            self.add_finding(
                "MEDIUM",
                f"Writable directory in PATH: {d}",
                "Can hijack binaries called without absolute path by root scripts or cron jobs",
                "https://hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#path"
            )
        
    def _collect_os_info(self):
        self.proc_version  = run_raw("cat /proc/version")
        self.add_raw("/proc/version", self.proc_version)
        
        self.uname         = run_raw("uname -a")
        self.add_raw("uname -a",      self.uname)

        self.os_release    = run_raw("cat /etc/os-release")
        self.add_raw("/etc/os-release", self.os_release)

        self.lsb_release   = run_raw("lsb_release -a")
        self.add_raw("lsb_release -a", self.lsb_release)

    def _analyse_os_info(self):
        pass    
    
    def _is_chroot_vulnerable(self) -> bool:
        return "No such file or directory" in self.chroot_test
    
    def _populate_class(self, raw_data_dict: dict):
        get = lambda key: raw_data_dict.get(key, "")

        self.apparmor         = get("AppArmor")
        self.selinux          = get("SELinux")
        self.grsec            = get("Grsecurity")
        self.pax              = get("PaX")
        self.execshield       = get("Execshield")
        self.aslr             = get("ASLR (randomize_va_space)")
        self.printers         = get("lpstat -a")
        self.cups_version     = get("CUPS version")
        self.cups_service     = get("CUPS service")
        self.cpu              = get("lscpu")
        self.df               = get("df -h")
        self.lsblk            = get("lsblk")
        self.date             = get("date")
        self.dmesg_sig        = get("dmesg signature warnings")
        self.sudo_version_raw = get("sudo")
        self.chroot_test      = get("chroot_escalation_test")
        self.env_output       = get("env")
        self.path_raw         = get("$PATH")
        self.proc_version     = get("/proc/version")
        self.uname            = get("uname -a")
        self.os_release       = get("/etc/os-release")
        self.lsb_release      = get("lsb_release -a")