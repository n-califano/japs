from core.base_module import BaseModule
from core.context import RunContext
from core.utils import run_raw

class Module(BaseModule):
    name = "drives"
    description = "dev, disks, mounts, fstab"
    tags = ["basic"]

    def collect(self, ctx: RunContext) -> None:
        self.dev_disks      = run_raw("ls /dev 2>/dev/null | grep -i 'sd'")
        self.fstab          = run_raw("cat /etc/fstab 2>/dev/null | grep -v '^#' | grep -Pv '\\W*\\#'")
        self.fstab_creds    = run_raw("grep -E '(user|username|login|pass|password|pw|credentials)[=:]' /etc/fstab /etc/mtab 2>/dev/null")

    def analyse(self, ctx: RunContext) -> None:
        self._analyse_block_devices()
        self._analyse_mounts()
        

    def _analyse_mounts(self):
        if self.fstab:
            self.add_raw("/etc/fstab (comments stripped)", self.fstab)
            # Flag world-writable or noexec-less NFS/CIFS mounts as noteworthy
            for line in self.fstab.strip().splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                fstype  = parts[2].lower()
                options = parts[3].lower() if len(parts) > 3 else ""
                device  = parts[0]
                mount   = parts[1]
                if fstype in ("nfs", "nfs4", "cifs", "smbfs"):
                    self.add_finding(
                        "INFO",
                        f"Network share in fstab: {device} → {mount} (type: {fstype})",
                        "Network mounts can be abused for file planting or symlink attacks if writable"
                    )

        if self.fstab_creds:
            self.add_raw("Credentials found in fstab/mtab", self.fstab_creds)
            self.add_finding(
                "HIGH",
                "Plaintext credentials found in /etc/fstab or /etc/mtab",
                "Credentials stored in fstab (e.g. for CIFS/NFS mounts) are readable by any user "
                "who can read the file: "
                f"{self.fstab_creds}"
            )

    def _analyse_block_devices(self):
        if self.dev_disks:
            self.add_raw("Block devices (/dev/sd*)", self.dev_disks)
            disk_list = self.dev_disks.strip().splitlines()
            # Partitions have a digit suffix (sda1, sdb2…), bare disks don't (sda, sdb…)
            bare_disks  = [d for d in disk_list if not d[-1].isdigit()]
            partitions  = [d for d in disk_list if d[-1].isdigit()]
            if bare_disks:
                self.add_finding(
                    "INFO",
                    f"Raw disk devices found: {', '.join(bare_disks)}",
                    "Direct read access to a raw disk (e.g. /dev/sdb) can expose unencrypted data "
                    "from unmounted partitions, check permissions with: ls -la /dev/sd*"
                )
            if partitions:
                self.add_finding(
                    "INFO",
                    f"Disk partitions found: {', '.join(partitions)}",
                    "Unmounted partitions may contain sensitive data; "
                    "cross-reference with fstab to spot anything not auto-mounted"
                )