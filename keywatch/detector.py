# detector.py — v1
# -----------------------------------------------------------------------------
# KeyWatch (detector / backend)
# - Heuristic checks for keylogger-style persistence on Windows
# - Looks at: Registry Run keys, Startup folders, Scheduled Tasks, Services,
#   running Processes, and recent executables/scripts in AppData.
# - Designed to be *fast* and *UI-friendly* (returns a simple dict payload).
# - Not an antivirus. Expect false positives → mitigated with whitelists & scoring.
# -----------------------------------------------------------------------------

import os, subprocess, hashlib
from pathlib import Path
from datetime import datetime, UTC
import psutil
import ctypes

try:
    import winreg  # Windows registry access
except ImportError:
    winreg = None  # Non-Windows: gracefully skip registry checks

# --- Whitelist of known safe publishers (expand as needed) --------------------
# If sigcheck says a file is signed by any of these, we treat it as trusted.
SAFE_PUBLISHERS = {
    "Microsoft Windows", "Google LLC", "Mozilla Corporation", "Oracle Corporation",
    "Adobe Systems Incorporated", "Intel Corporation", "HP Inc.", "Dell Inc.",
    "Lenovo (Beijing) Limited", "NVIDIA Corporation", "Realtek Semiconductor Corp.",
    "Broadcom Inc.", "Synaptics Incorporated", "Logitech Inc.", "Cisco Systems, Inc.",
    "VMware, Inc.", "Dropbox, Inc.", "Zoom Video Communications, Inc.", "Apple Inc.",
    "Samsung Electronics Co., Ltd.", "Western Digital Technologies, Inc.", "Microsoft Corporation"
}

# --- Known-safe subpaths (we avoid flagging these during sweeps) --------------
# These are noisy locations (browsers, Windows system dirs, installers, etc.).
# Paths are matched case-insensitively and with slashes normalized to backslashes.
KNOWN_SAFE_PATHS = [
    r"chrome\\user data\\default\\extensions",
    r"chrome\\user data\\profile ",
    r"microsoft\\edge\\user data\\default\\extensions",
    r"mozilla\\firefox\\profiles",
    r"\\appdata\\local\\packages\\microsoft.windows.",
    r"\\appdata\\local\\microsoft\\onedrive",
    r"\\appdata\\local\\google\\chrome\\user data\\default\\service worker",
    r"\\appdata\\local\\google\\chrome\\user data\\default\\",
    r"\\appdata\\local\\google\\chrome\\user data\\profile ",
    r"\\appdata\\local\\google\\chrome\\user data\\system profile",
    r"\\appdata\\local\\microsoft\\edge\\user data\\default\\",
    r"\\appdata\\local\\microsoft\\edge\\user data\\profile ",
    r"\\appdata\\local\\microsoft\\edge\\user data\\system profile",
    r"\\appdata\\local\\packages\\",
    r"\\appdata\\local\\temp\\chocolatey",
    r"\\appdata\\local\\temp\\nupkg",
    r"\\appdata\\local\\temp\\pip-",
    r"\\appdata\\local\\temp\\npm-",
    r"\\appdata\\local\\temp\\_MEI",
    r"\\appdata\\local\\temp\\_bazel_",
    r"\\appdata\\local\\temp\\_virtualenv-",
    r"\\appdata\\local\\temp\\tmp",
    r"\\appdata\\local\\temp\\7z",
    r"\\appdata\\local\\temp\\rar$",
    r"\\appdata\\local\\temp\\crashpad",
    r"\\appdata\\local\\temp\\scoped_dir",
    r"\\appdata\\local\\temp\\chrome_installer",
    r"\\appdata\\local\\temp\\edge_installer",
    r"\\appdata\\local\\temp\\firefox_installer",
    r"\\appdata\\local\\temp\\opera_installer",
    r"\\appdata\\local\\temp\\brave_installer",
    r"program files",
    r"windows\\system32",
    r"windows\\syswow64",
    r"windows\\winsxs",
    r"windows\\servicing",
    r"windows\\assembly",
    r"windows\\explorer.exe",
    r"windows\\notepad.exe",
    r"windows\\systemapps",
    r"windows\\web",
    r"windows\\help",
    r"windows\\inf",
    r"windows\\fonts",
    r"windows\\media",
    r"windows\\resources",
    r"windows\\diagnostics",
    r"windows\\appcompat",
    r"windows\\apppatch",
    r"windows\\security",
    r"windows\\servicing",
    r"windows\\temp",
    r"windows\\logs",
    r"windows\\tasks",
    r"windows\\performance",
    r"windows\\systemresources",
    r"windows\\system32\\drivers",
    r"windows\\system32\\config",
    r"windows\\system32\\spool",
    r"windows\\system32\\catroot",
    r"windows\\system32\\codeintegrity",
    r"windows\\system32\\driverstore",
    r"windows\\system32\\en-us",
    r"windows\\system32\\logfiles",
    r"windows\\system32\\wbem",
    r"windows\\system32\\winevt",
    r"windows\\system32\\wfp",
    r"windows\\system32\\wmsyspr9.prx",
    r"windows\\system32\\drivers\\etc",
    r"windows\\system32\\tasks",
    r"windows\\system32\\config\\systemprofile",
    r"windows\\system32\\config\\systemprofile\\appdata",
    r"windows\\system32\\config\\systemprofile\\appdata\\local",
    r"windows\\system32\\config\\systemprofile\\appdata\\roaming",
]

def _is_known_safe_path(p: str) -> bool:
    """Quick path allowlist check to cut down on false positives."""
    up = p.strip().lower().replace("/", "\\")
    return any(s in up for s in KNOWN_SAFE_PATHS)

def is_signed_and_trusted(path):
    """
    Returns True if 'path' is digitally signed by a safe publisher.
    - Uses Sysinternals 'sigcheck.exe' if present (set SIGCHECK_PATH env var).
    - If sigcheck is missing or errors, returns False (conservative).
    """
    try:
        import subprocess
        sigcheck = os.environ.get("SIGCHECK_PATH", r"C:\Sysinternals\sigcheck.exe")
        if not os.path.exists(sigcheck):
            return False  # No sigcheck = we can't verify signature
        out = subprocess.check_output([sigcheck, "-n", "-q", "-a", path], text=True, timeout=2.0)
        for line in out.splitlines():
            if "Publisher:" in line:
                pub = line.split(":",1)[1].strip()
                if pub in SAFE_PUBLISHERS:
                    return True
        return False
    except Exception:
        return False

def is_hidden(filepath):
    """Windows-only: returns True if the file has the HIDDEN attribute."""
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(filepath))
        return bool(attrs & 2)  # FILE_ATTRIBUTE_HIDDEN == 2
    except Exception:
        return False

# --- Heuristic signals for "keylogger-like" content --------------------------
KEYLOGGER_KEYWORDS = [
    "keylogger", "kl", "logger", "keyboard", "input", "capture", "record",
    "keystroke", "hook", "intercept", "monitor", "spy", "sniff", "grab",
    "logkeys", "type", "typed", "strokes"
]
KEYLOGGER_EXTS = (".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".js", ".ps1")
KEYLOGGER_DIRS = [r"appdata", r"temp", r"roaming", r"local", r"users", r"documents", r"downloads"]

def _is_keylogger_like(path: str) -> bool:
    """
    Soft heuristic:
    - filename contains classic keylogger-ish tokens    OR
    - executable/script placed under common user dirs (AppData/temp/etc.)
    """
    up = path.strip().lower().replace("/", "\\")
    base = os.path.basename(up)
    if any(k in base for k in KEYLOGGER_KEYWORDS):
        return True
    if base.endswith(KEYLOGGER_EXTS) and any(d in up for d in KEYLOGGER_DIRS):
        return True
    return False

def _has_network_activity(path: str) -> bool:
    """
    Returns True if a process with this 'path' is currently connected (INET).
    (Useful signal for exfil / active agent, keeps noise down.)
    """
    for p in psutil.process_iter(["exe", "connections"]):
        try:
            exe = (p.info.get("exe") or "").lower()
            if exe and exe == path.lower():
                conns = p.connections(kind="inet")
                if any(c.status == psutil.CONN_ESTABLISHED for c in conns):
                    return True
        except Exception:
            continue
    return False

def _should_flag(path: str) -> bool:
    """
    Main predicate:
    - Not empty
    - Not in our 'known safe' path list
    - Not signed by a trusted publisher
    - Looks keylogger-like
    - AND shows live network activity
    """
    if not path:
        return False
    if _is_known_safe_path(path):
        return False
    if os.path.exists(path) and is_signed_and_trusted(path):
        return False
    if not _is_keylogger_like(path):
        return False
    if not _has_network_activity(path):
        return False
    return True

# --- Path suspicion helpers (generic) ----------------------------------------
SUSPICIOUS_DIR_SNIPPETS = [
    r"appdata\\roaming",
    r"appdata\\local\\temp",
    r"\\temp\\",
    r":\\users\\",
    r"programdata\\",
]
FAKE_SYSTEM_NAMES = {"svchosts.exe","winlogon32.exe","expl0rer.exe","taskhostsx.exe","conhost32.exe"}
EXEC_EXTS = (".exe",".dll",".scr",".bat",".cmd",".vbs",".js",".ps1")

def _is_suspicious_path(p: str) -> bool:
    """
    Generic path smell test:
    - User/temp locations
    - Fake-ish system names in user space
    """
    if not p: return False
    up = p.strip().lower().replace("/", "\\")
    if any(s in up for s in SUSPICIOUS_DIR_SNIPPETS): return True
    base = os.path.basename(up)
    if base in FAKE_SYSTEM_NAMES and (":\\users\\" in up): return True
    return False

def _mk(kind, path, reason, score, extra=None):
    """Standard finding object used across all checks."""
    return {"kind":kind,"path":path or "", "reason":reason, "score":score, "extra":extra or {}}

# ---------------- Registry (Run) ---------------------------------------------
def _read_run_key(root, subkey):
    """Return list of (value_name, value_data) from a Run-like key (best-effort)."""
    vals = []
    if not winreg: return vals
    try:
        with winreg.OpenKey(root, subkey) as k:
            i = 0
            while True:
                try:
                    name, val, _ = winreg.EnumValue(k, i)
                    vals.append((name, str(val)))
                    i += 1
                except OSError:
                    break
    except OSError:
        pass
    return vals

def check_registry_autoruns():
    """
    Enumerate common Run keys under HKCU/HKLM.
    Flag entries whose target looks like a suspicious keylogger candidate.
    """
    if not winreg: return []
    findings = []
    keys = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    ]
    roots = [("HKCU", getattr(winreg, "HKEY_CURRENT_USER", None)),
             ("HKLM", getattr(winreg, "HKEY_LOCAL_MACHINE", None))]
    for root_name, root in roots:
        if root is None: continue
        for sub in keys:
            for name, raw in _read_run_key(root, sub):
                # Expand envvars; keep raw path (args may be present)
                target = os.path.expandvars(raw.strip().strip('"'))
                if _should_flag(target):
                    findings.append(_mk(
                        "autorun", target,
                        f"{root_name}\\{sub} value '{name}' points to suspicious file.",
                        score=3, extra={"value_name": name, "registry_path": sub, "hive": root_name}
                    ))
    return findings

# ---------------- Startup folders -------------------------------------------
def check_startup_folders():
    """
    Flag items present in Startup folders.
    - Heavier score for hidden files / suspicious user paths
    """
    findings = []
    user_startup = Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup"
    common_startup = Path(os.environ.get("PROGRAMDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\StartUp"
    for folder in (user_startup, common_startup):
        if folder.exists():
            for item in folder.iterdir():
                if item.is_file():
                    p = str(item)
                    if _should_flag(p):
                        hidden = is_hidden(p)
                        score = 4 if hidden else (3 if _is_suspicious_path(p) else 2)
                        findings.append(_mk(
                            "startup_folder", p,
                            f"File present in Startup folder: {folder}{' (hidden)' if hidden else ''}",
                            score=score
                        ))
    return findings

# ---------------- Tasks / Services / Processes / AppData ---------------------
def check_scheduled_tasks_fast():
    """
    Quick scheduled tasks pass via 'schtasks /query':
    Parse the action and flag if it looks suspicious.
    """
    findings = []
    try:
        out = subprocess.check_output(
            ["schtasks", "/query", "/fo", "CSV", "/nh"],
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            text=True, errors="ignore", timeout=2.0
        )
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith('"HostName"'): continue
            cols = [c.strip().strip('"') for c in line.split(",")]
            if len(cols) < 8: continue
            task_name, action = cols[0], os.path.expandvars(cols[7])
            if _should_flag(action):
                findings.append(_mk(
                    "task", action,
                    f"Scheduled task '{task_name}' launches suspicious file.",
                    score=2, extra={"task_name": task_name}
                ))
    except Exception:
        pass
    return findings

def _service_binpath(name: str) -> str:
    """Resolve service binary path via psutil, fallback to 'sc qc'."""
    try:
        svc = psutil.win_service_get(name)
        info = svc.as_dict()
        bp = info.get("binpath", "") or info.get("binpath_exe", "")
        return os.path.expandvars(str(bp or ""))
    except Exception:
        pass
    try:
        out = subprocess.check_output(
            ["sc", "qc", name], text=True, errors="ignore",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), timeout=1.0
        )
        for line in out.splitlines():
            if "BINARY_PATH_NAME" in line:
                return os.path.expandvars(line.split(":", 1)[1].strip())
    except Exception:
        pass
    return ""

def check_services():
    """
    Look at auto-start services; grab their binpath and run the heuristic.
    """
    findings = []
    try:
        for svc in psutil.win_service_iter():
            try:
                s = svc.as_dict()
                if (s.get("start_type") or "").lower().startswith("auto"):
                    bp = _service_binpath(s.get("name"))
                    if _should_flag(bp):
                        findings.append(_mk(
                            "service", bp,
                            f"Auto-start service '{s.get('name')}' binary is suspicious.",
                            score=3, extra={"service": s.get("name")}
                        ))
            except Exception:
                continue
    except Exception:
        pass
    return findings

def check_processes_fast(limit=180):
    """
    Scan a limited number of processes; flag if exe/cmdline looks suspicious.
    Limit keeps it responsive on dev machines.
    """
    findings, count = [], 0
    for p in psutil.process_iter(["pid","name","exe","cmdline"]):
        if limit and count >= limit: break
        pid = p.info.get("pid")
        exe = os.path.expandvars((p.info.get("exe") or "").strip())
        name = (p.info.get("name") or "").lower()
        cmd = os.path.expandvars(" ".join(p.info.get("cmdline") or []))
        if _should_flag(exe) or _should_flag(cmd):
            findings.append(_mk(
                "process", exe or cmd,
                f"Process {name or '?'} (PID {pid}) is suspicious.",
                score=2, extra={"pid": pid}
            ))
        count += 1
    return findings

def _sha256(path: str) -> str:
    """Return SHA-256 (first 16 hex) for quick fingerprinting; best-effort."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except Exception:
        return ""

def check_appdata_sweep(days=14, max_files=400):
    """
    Walk AppData + LocalAppData for recent executables/scripts and flag likely suspects.
    NOTE: This can be noisy on dev boxes → tune 'days' & 'max_files' as needed.
    """
    findings = []
    roots = [p for p in (os.environ.get("APPDATA"), os.environ.get("LOCALAPPDATA")) if p]
    now = datetime.now(UTC).timestamp()
    scanned = 0
    for root in map(Path, roots):
        try:
            for dirpath, _, files in os.walk(root):
                if scanned >= max_files: break
                for fn in files:
                    if scanned >= max_files: break
                    full = Path(dirpath) / fn
                    if _should_flag(str(full)):
                        try:
                            st = full.stat()
                            hidden = is_hidden(full)
                            if (now - st.st_mtime)/86400.0 <= days:
                                pstr = str(full)
                                findings.append(_mk(
                                    "filesystem", pstr,
                                    f"Recent suspicious executable/script in AppData (≤{days}d){' (hidden)' if hidden else ''}.",
                                    score=3 if hidden else 2,
                                    extra={"sha256_16": _sha256(pstr)}
                                ))
                                scanned += 1
                        except Exception:
                            continue
        except Exception:
            continue
    return findings

# --- Risk model ---------------------------------------------------------------
def score_to_risk(score:int)->str:
    """
    Tiny severity model:
    - score >= 6 → 'danger'
    - score >= 3 → 'warn'
    - else       → 'safe'
    (Score sums per finding; see each check's 'score' values.)
    """
    if score >= 6: return "danger"
    if score >= 3: return "warn"
    return "safe"

# --- Orchestration ------------------------------------------------------------
def scan_system(progress=None, include_tasks=False, include_processes=False, include_services=False, include_appdata_sweep=False):
    """
    Orchestrates all checks; returns a dict:
      {
        "timestamp": ISO8601,
        "risk": "safe"|"warn"|"danger",
        "score": int,
        "findings": [ {kind,path,reason,score,extra?}, ... ]
      }

    'progress' is a callback(label, i, n) to update UI with step text + progress.
    Deep scan toggles add more checks (tasks/services/processes/AppData sweep).
    """
    # Test mode hook (for demos): set KEYWATCH_TEST=1 to force sample output
    if os.environ.get("KEYWATCH_TEST") == "1":
        sample = [
            _mk("autorun", os.path.expandvars(r"%APPDATA%\svchosts.exe"), "Autorun points to user/temp directory.", 3),
            _mk("startup_folder", os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\kwsim.bat"),
                "File in Startup folder.", 3),
        ]
        return {"timestamp":"TEST","risk":score_to_risk(6),"score":6,"findings":sample}

    # Base steps (always on)
    steps = [
        ("Checking registry autoruns…",  check_registry_autoruns),
        ("Checking Startup folders…",    check_startup_folders),
    ]
    # Deep scan toggles
    if include_tasks:         steps.append(("Checking scheduled tasks…",   check_scheduled_tasks_fast))
    if include_services:      steps.append(("Checking services…",          check_services))
    if include_processes:     steps.append(("Checking running processes…", check_processes_fast))
    if include_appdata_sweep: steps.append(("Sweeping AppData (recent)…",  check_appdata_sweep))

    findings = []
    total = len(steps)

    # Run each step, streaming progress back to UI
    for i, (label, fn) in enumerate(steps, start=1):
        if progress:
            try: progress(label, i, total)
            except Exception: pass
        try:
            findings += fn()
        except Exception:
            continue  # best-effort: skip failures and keep going

    # Score and shape the final payload
    total_score = sum(f["score"] for f in findings)
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "risk": score_to_risk(total_score),
        "score": total_score,
        "findings": findings
    }

# --- CLI entry (debug/dev) ----------------------------------------------------
if __name__ == "__main__":
    import json
    print(json.dumps(scan_system(), indent=2))
