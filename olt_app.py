"""
OLT Finder App  (one file)
--------------------------
Base app: find an ONU by SN / MAC on BDCOM GPON (Telnet) and Huawei MA5800 (SSH), PON status,
PON monitor, output find bar.

Added features:
  1. "Today Losi" box (top right corner)
       - How many ONUs went down TODAY and are still down (LOSi + Offline). Dying Gasp is not counted.
       - Red = more than 0.  Green = 0.  Grey = not checked yet, or the check failed / not sure.
       - Click the box to see Area (OLT) -> PON -> ONU. It updates every 15 minutes.
  2. "AI Analyze" button (Gemini)
       - Select a Found ONU, click AI Analyze. It uses Power, Port and MAC of that ONU.
       - Rule check: Rx power must be -12 to -24 dBm, and the port must be up.
       - You paste the ERP login status, MikroTik bandwidth and MikroTik PPP text.
       - Gemini explains the result in simple English. It only suggests, it never runs commands.
         Passwords in the pasted text are removed before sending.
  3. Huawei MAC Address (display mac-address port F/S/P ont ID) runs BEFORE 'interface gpon F/S'.
     New mode "PON + ONU (manual)": pick OLT(s), type PON + ONU, see the details (BDCOM and Huawei).
  4. Fixes: Huawei Online / Offline count, Huawei Port Check runs by itself, cleaner output.

Run:  python OLT_Finder_App.py      (this is the only file you need)
Safety: only 'show' / 'display' commands, reboot/reset only by button + confirm,
        every command is written to ~/.olt_tool/audit.log (without passwords).
"""
import re
import os
import sys
import json
import time
import queue
import socket
import getpass
import threading
import configparser
from datetime import datetime, date
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog, filedialog
except ImportError:           # headless/test
    tk = None

try:
    import keyring            # optional: to save the password in Windows Credential Manager
except ImportError:
    keyring = None

try:
    import paramiko           # needed for Huawei (SSH)
except ImportError:
    paramiko = None

HOME = Path.home()
DATA_DIR = HOME / ".olt_tool"
OLT_FILE = DATA_DIR / "olts.json"
SETTINGS_FILE = DATA_DIR / "settings.json"
AUDIT_FILE = DATA_DIR / "audit.log"
KEYRING_SERVICE = "olt_finder"

MAX_WORKERS = 5               # maximum number of OLTs to log in to at the same time
DEFAULT_USER = "support"
SN_RE = re.compile(r"^[A-Za-z0-9:\-_.]{4,32}$")

# PON monitor: LOSi / LOS / LOBi (whole words only, case does not matter)
LOSI_RE = re.compile(r"\b(?:losi?|lobi)\b", re.I)
DYING_RE = re.compile(r"dying[\s_-]*gasp", re.I)
# opt-in 'Dying Gasp check': runs this command for each Offline ONU (title from PROFILES)
CAUSE_RE = re.compile(r"(?i)(?:down\s*-?\s*cause|dereg\w*\s*reason)")
CAUSE_CMD_TITLE = {"huawei": "10 time basic-info", "bdcom": "ONU Info"}
DG_MAX = 30                                # maximum number of ONUs to check the cause for, per PON (slow)
MONITOR_CMD_TITLE = "PON Inactive ONU"     # the PROFILES command used to get the ONU list of a PON
MIN_AUTO_SEC = 20                          # shortest auto refresh interval


# ---------------------------------------------------------------- helpers
def err_text(e):
    name = type(e).__name__
    if isinstance(e, ConnectionRefusedError):
        return "connection refused (are the IP/port correct?)"
    if isinstance(e, (socket.timeout, TimeoutError)):
        if str(e) and str(e) != "timed out":
            return f"timeout: {e}"
        return "timeout (cannot reach the OLT or it is not responding)"
    if isinstance(e, socket.gaierror):
        return "could not understand the host/IP"
    if name == "AuthenticationException":
        return "login failed (wrong username/password?)"
    if name == "SSHException":
        return f"SSH error: {e}"
    msg = str(e).splitlines()[0] if str(e) else ""
    return f"{name}: {msg}" if msg else name


def audit(olt_name, cmd):
    try:
        DATA_DIR.mkdir(exist_ok=True)
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S}\t{getpass.getuser()}\t{olt_name}\t{cmd}\n")
    except Exception:
        pass


def olt_key(o):
    return f"{o.get('group', '')}/{o['name']}"


def guess_vendor(name):
    n = name.lower()
    if re.search(r"switch|router|firewall|mikrotik|\blan\b|\bwan\b", n):
        return "other"            # not an OLT, not supported by this tool
    if re.search(r"huawei|huwaei", n):
        return "huawei"
    if re.search(r"v-?sol", n):
        return "vsol"
    if "epon" in n:
        return "epon"
    return "bdcom"


def hex12(text):
    return re.sub(r"[^0-9a-fA-F]", "", str(text)).lower()


def olt_clean(text):
    """Same as the web app: remove anything inside () and the words Huawei/Bdcom/V.Sol."""
    text = re.sub(r"\([^)]*\)?", " ", str(text))
    text = re.sub(r"(?i)huawei|bdcom|v\.?\s?sol", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def huawei_sn_short(text):
    """'HWTC:4577CE9A' / 'ECOM-9D03FF9B' -> '4577CE9A' / '9D03FF9B' (the web app's h_sn)."""
    parts = [t for t in re.split(r"[:\-\s]+", str(text).strip()) if t]
    return re.sub(r"(?i)^(hwtc|htwc)", "", parts[-1]).upper() if parts else ""


def sn_variants_bdcom(sn):
    """First the SN as the user typed it; if not found, try HWTC:xxxx / HWTC-xxxx / HWTCxxxx."""
    sn = sn.strip()
    out = [sn]
    m = re.fullmatch(r"([A-Za-z]{4})[:\-]?([0-9A-Fa-f]{8})", sn)
    if m:
        pre, rest = m.group(1).upper(), m.group(2).upper()
        for sep in (":", "-", ""):
            v = f"{pre}{sep}{rest}"
            if v not in out:
                out.append(v)
    return out


def sn_variants_huawei(sn):
    """First the web app's format (last 8 hex), then raw, HWTC-xxxxxxxx, then 16-digit hex."""
    sn = sn.strip()
    out = []
    for v in (huawei_sn_short(sn), sn):
        if v and v not in out:
            out.append(v)
    m = re.fullmatch(r"([A-Za-z]{4})[:\-]?([0-9A-Fa-f]{8})", sn)
    if m:
        pre, rest = m.group(1).upper(), m.group(2).upper()
        for v in (f"{pre}-{rest}", pre.encode().hex().upper() + rest):
            if v not in out:
                out.append(v)
    return out


def natural_key(text):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", str(text))]


def date_variants(text):
    """'26/10/2026', '2026-10-26', '26-10-2026' ... -> every format the OLT output may use.
    Returns None if the text is not a date."""
    t = str(text).strip()
    m = re.fullmatch(r"(\d{1,2})[/\-.](\d{1,2})[/\-.](\d{4})", t)
    if m:
        d, mo, y = int(m.group(1)), int(m.group(2)), int(m.group(3))
    else:
        m = re.fullmatch(r"(\d{4})[/\-.](\d{1,2})[/\-.](\d{1,2})", t)
        if not m:
            return None
        y, mo, d = int(m.group(1)), int(m.group(2)), int(m.group(3))
    try:
        dt = date(y, mo, d)
    except ValueError:
        return None
    return [f"{dt:%Y-%m-%d}", f"{dt:%d/%m/%Y}", f"{dt:%d-%m-%Y}", f"{dt:%Y/%m/%d}", f"{dt:%d.%m.%Y}"]


# ---------------------------------------------------------------- vendor profiles
BDCOM_ROW = re.compile(
    r"GPON(?P<slot>\d+)/(?P<pon>\d+):(?P<onu>\d+)\s+(?P<vid>\S+)\s+(?P<model>\S+)"
    r"\s+(?P<sn>\S+)\s+(?P<loid>\S+)"
    r"(?:\s+(?P<status>\S+)\s+(?P<cfg>\S+)\s+(?P<active>\d{4}-\d{2}-\d{2}\s+\S+))?")
BDCOM_IF = re.compile(r"GPON(\d+)/(\d+):(\d+)", re.I)
# One ONT row of Huawei 'display ont info summary': [F/S/P] ONT-ID  SN ...
HUAWEI_ROW = re.compile(r"^\s*(?:(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s+)?(\d{1,3})\s+([0-9A-Fa-f]{8,16})\b")


def parse_bdcom_sn(out):
    m = BDCOM_ROW.search(out)
    if not m:
        return None
    return {"frame": "", "slot": m.group("slot"), "pon": m.group("pon"), "onu": m.group("onu"),
            "model": m.group("model"), "loid": m.group("loid"), "sn": m.group("sn"),
            "status": m.group("status") or "", "active": m.group("active") or ""}


def parse_bdcom_mac(out, mac12=""):
    best = None
    for line in out.splitlines():
        m = BDCOM_IF.search(line)
        if not m:
            continue
        if mac12 and mac12 in hex12(line):
            best = m
            break
        best = best or m
    if not best:
        return None
    return {"frame": "", "slot": best.group(1), "pon": best.group(2), "onu": best.group(3),
            "model": "", "loid": "", "sn": "", "status": "", "active": ""}


def parse_huawei(out, mac12=""):
    m = re.search(r"F/S/P\s*:\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)", out)
    n = re.search(r"ONT-ID\s*:\s*(\d+)", out)
    if not (m and n):
        return None
    st = re.search(r"Run state\s*:\s*(\S+)", out)
    sn = re.search(r"\bSN\s*:\s*(\S+)", out)
    eq = re.search(r"Equipment-ID\s*:\s*(\S+)", out)
    return {"frame": m.group(1), "slot": m.group(2), "pon": m.group(3), "onu": n.group(1),
            "model": eq.group(1) if eq else "", "loid": "", "sn": sn.group(1) if sn else "",
            "status": st.group(1) if st else "", "active": ""}


def bdcom_mac_cmds(mac12):
    last4 = mac12[-4:]
    out = [f"show mac address-table | include {last4.upper()}"]
    if last4.lower() != last4.upper():
        out.append(f"show mac address-table | include {last4.lower()}")
    return out


def huawei_mac_cmds(mac12):
    m = mac12.upper()
    return [f"display location {m[0:4]}-{m[4:8]}-{m[8:12]}"]


# Placeholders: {frame} {slot} {pon} {onu}. auto=True -> runs as soon as the ONU is found.
PROFILES = {
    "bdcom": {
        "title": "BDCOM GPON",
        "setup": [],
        "paging_off": "terminal length 0",
        "width_cmd": "terminal width 200",       # keeps output from wrapping at 80 columns (ignored if not understood)
        "context": None,
        "find_sn": "show gpon onu-information sn {sn}",
        "sn_variants": sn_variants_bdcom,
        "parse_sn": parse_bdcom_sn,
        "mac_cmds": bdcom_mac_cmds,
        "parse_mac": parse_bdcom_mac,
        "commands": [
            {"title": "ONU Info", "auto": True,
             "cmd": "show gpon interface gpon {slot}/{pon}:{onu} onu basic-info"},
            {"title": "ONU Power", "auto": True,
             "cmd": "show gpon interface gpon {slot}/{pon}:{onu} onu optical-transceiver-diagnosis"},
            {"title": "Check Port", "auto": True,
             "cmd": "show gpon interface gpon {slot}/{pon}:{onu} onu port 1 state"},
            {"title": "Power in PON",
             "cmd": "show gpon onu-optical-transceiver-diagnosis interface gpon {slot}/{pon}"},
            {"title": "MAC Address", "auto": True,
             "cmd": "show mac address-table interface gpon {slot}/{pon}:{onu}"},
            {"title": "PON Inactive ONU",
             "cmd": "show gpon inactive-onu interface gpon {slot}/{pon}"},
            {"title": "PON LOSi",
             "cmd": "show gpon inactive-onu interface gpon {slot}/{pon} | include losi"},
            {"title": "All PON Status", "cmd": "show interface brief"},
            {"title": "PON port open", "cmd": "show interface range gpon {slot}/{pon}"},
            {"title": "Reboot ONU", "danger": True,
             "cmd": "gpon reboot onu interface gpon {slot}/{pon}:{onu}"},
        ],
    },
    "huawei": {
        "title": "Huawei MA5800",
        "setup": ["config"],                      # login -> enable (auto) -> config
        "paging_off": None,
        "context": "interface gpon {frame}/{slot}",
        "find_sn": "display ont info by-sn {sn}",
        "sn_variants": sn_variants_huawei,
        "parse_sn": parse_huawei,
        "mac_cmds": huawei_mac_cmds,
        "parse_mac": parse_huawei,
        "commands": [
            {"title": "ONU Info", "auto": True, "cmd": "display ont info {pon} {onu}"},
            {"title": "ONU Power", "auto": True, "cmd": "display ont optical-info {pon} {onu}"},
            {"title": "10 time basic-info", "auto": True, "cmd": "display ont register-info {pon} {onu}"},
            # global=True: runs in config mode BEFORE 'interface gpon F/S' (it is not an interface command)
            {"title": "MAC Address", "auto": True, "global": True,
             "cmd": "display mac-address port {frame}/{slot}/{pon} ont {onu}"},
            {"title": "Port Check", "cmd": "display ont port state {pon} {onu} eth-port all"},
            {"title": "ONU All Power", "cmd": "display ont optical-info history rx {pon} {onu}"},
            {"title": "PON Inactive ONU", "cmd": "display ont info summary {pon}"},
            {"title": "PON LOSi/LOBi", "cmd": "display ont info summary {pon} | include LOSi/LOBi"},
            {"title": "PON Offline ONU", "cmd": "display ont info summary {pon} | include offline"},
            {"title": "Reset ONU", "danger": True, "cmd": "ont reset {pon} {onu}"},
        ],
    },
}

# scope: onu = needs one ONU, pon = needs a PON number, olt = OLT level (needs no number)
_SCOPES = {"Power in PON": "pon", "PON Inactive ONU": "pon", "PON LOSi": "pon", "PON port open": "pon",
           "All PON Status": "olt", "PON LOSi/LOBi": "pon", "PON Offline ONU": "pon"}
for _p in PROFILES.values():
    for _c in _p["commands"]:
        _c.setdefault("scope", _SCOPES.get(_c["title"], "onu"))
PON_TITLES = sorted({c["title"] for _p in PROFILES.values() for c in _p["commands"]
                     if c["scope"] in ("pon", "olt")})

# Only these kinds of commands are allowed to run
SAFE_CMD = re.compile(
    r"^(?:show|display) [A-Za-z0-9 :/_.\-]+(?: \| include [A-Za-z0-9_\-/]+)?$")
DANGER_CMDS = (re.compile(r"^gpon reboot onu interface gpon \d+/\d+:\d+$"),
               re.compile(r"^ont reset \d+ \d+$"))
CTRL_CMD = re.compile(r"^(?:enable|config|quit|interface gpon \d+/\d+)$")

# IP/port/protocol known from the BDCOM.pdf screenshot (the other IPs will come from the Xshell import)
SEED_INFO = {
    "CTG Batterygoli Olt": ("10.201.10.11", 23, "TELNET"),
    "CTG Chandgaon Olt 2": ("10.201.10.10", 23, "TELNET"),
    "CTG Firingibazar Olt": ("10.201.10.13", 23, "TELNET"),
    "CTG Greenview Olt": ("10.201.10.3", 23, "TELNET"),
    "CTG Halishohor Olt": ("10.201.10.2", 23, "TELNET"),
    "CTG Hillview Olt 1": ("10.201.10.6", 23, "TELNET"),
    "CTG Khulshi Olt": ("10.201.10.5", 23, "TELNET"),
    "CTG Chandgaon Huawei Olt": ("10.201.10.33", 22, "SSH"),
    "CTG Shugondha Huawei Olt": ("10.201.10.20", 22, "SSH"),   # seen in Xshell: 10.201.10.20:22
}
SEED_OLTS = [
    ("CTG Reseller Olt", ["Chakaria Core Link EPON Olt", "Chakaria ECOM EPON Olt", "CU V-SOL Olt",
                          "Ma Baba Oxygen V-SOL Olt", "TRS Network EPON Olt 1", "TRS Network EPON Olt 2"]),
    ("OLT Chittagong", ["CTG Agrabad Huwaei Olt", "CTG Batterygoli Olt", "CTG Chandgaon Huawei Olt",
                        "CTG Chandgaon Olt 2", "CTG Firingibazar Olt", "CTG Firozshah Olt",
                        "CTG Greenview Olt", "CTG Greenview VSol Olt", "CTG Halishohor Olt",
                        "CTG Hillview Olt 1", "CTG Hillview Olt 2", "CTG Kalamiya Bazar Olt",
                        "CTG Khulshi Olt", "CTG Shugondha Huawei Olt"]),
    # The 'OLT Dhaka' folder was collapsed in the PDF (its contents were not visible).
    # Ars2 and Azimpur Backup Olt were at the root level in Xshell (under All Sessions).
    ("All Sessions", ["Ars2", "Azimpur Backup Olt"]),
]


# ---------------------------------------------------------------- OLT list (olts.json / Xshell)
def load_olts():
    try:
        return json.loads(OLT_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_olts(olts):
    DATA_DIR.mkdir(exist_ok=True)
    OLT_FILE.write_text(json.dumps(olts, indent=2, ensure_ascii=False), encoding="utf-8")


# Wrong IPs that were saved earlier (read wrongly from the PDF screenshot): (OLT name, old IP) -> correct IP
IP_FIXES = {("CTG Shugondha Huawei Olt", "10.201.20.22"): "10.201.10.20"}


def apply_ip_fixes(olts):
    """If olts.json has an old wrong IP, fix it when the app starts. Returns True if anything changed."""
    changed = False
    for o in olts:
        new = IP_FIXES.get((o.get("name"), o.get("host")))
        if new:
            o["host"] = new
            changed = True
    return changed


def seed_olts():
    out = []
    for group, names in SEED_OLTS:
        for n in names:
            host, port, proto = SEED_INFO.get(n, ("", 23, "TELNET"))
            out.append({"group": group, "name": n, "host": host, "port": port,
                        "protocol": proto, "vendor": guess_vendor(n)})
    return out


def find_xshell_sessions():
    """NetSarang Computer/<version>/Xshell/Sessions folders (newest version first)."""
    bases = [HOME / "Documents", HOME]
    bases += list(HOME.glob("OneDrive*/Documents")) + list(HOME.glob("OneDrive*"))
    for env in ("APPDATA", "LOCALAPPDATA"):
        if os.environ.get(env):
            bases.append(Path(os.environ[env]))
    found = []
    for base in bases:
        try:
            for p in sorted(base.glob("NetSarang Computer/*/Xshell/Sessions"), reverse=True):
                if p.is_dir() and p not in found:
                    found.append(p)
        except Exception:
            pass
    return found


def read_text_auto(path):
    raw = Path(path).read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", errors="replace")
    return raw.decode("utf-8", errors="replace")


def parse_xsh(path, root):
    """Reads host/port/protocol from an Xshell session file (.xsh). Passwords are NOT read here."""
    text = read_text_auto(path)
    cp = configparser.ConfigParser(strict=False, interpolation=None)
    try:
        cp.read_string(text)
    except configparser.Error:
        cp = configparser.ConfigParser(strict=False, interpolation=None)
        cp.read_string("[_top]\n" + text)
    sec = next((s for s in cp.sections() if s.upper() == "CONNECTION"), None)
    if not sec:
        return None
    host = cp.get(sec, "Host", fallback="").strip()
    port = cp.get(sec, "Port", fallback="23").strip()
    proto = cp.get(sec, "Protocol", fallback="TELNET").strip().upper()
    rel = str(Path(path).relative_to(root).parent).replace("\\", "/")
    name = Path(path).stem
    return {"group": "All Sessions" if rel == "." else rel, "name": name, "host": host,
            "port": int(port) if port.isdigit() else 23, "protocol": proto,
            "vendor": guess_vendor(name)}


def import_xshell(root):
    root = Path(root)
    olts = []
    for f in sorted(root.rglob("*.xsh")):
        try:
            o = parse_xsh(f, root)
        except Exception:
            o = None
        if o and o["host"]:
            olts.append(o)
    return olts


def import_all(folders):
    """Imports from every folder; if the same group/name appears twice, the first one (newer version) wins."""
    seen, out = set(), []
    for f in folders:
        for o in import_xshell(f):
            k = olt_key(o)
            if k not in seen:
                seen.add(k)
                out.append(o)
    return out


def merge_olts(old, new):
    """Union: old entries stay, new ones are added/updated (a manually edited vendor is kept)."""
    result = {olt_key(o): o for o in old}
    for o in new:
        prev = result.get(olt_key(o))
        if prev and prev.get("vendor"):
            o["vendor"] = prev["vendor"]
        result[olt_key(o)] = o
    return list(result.values())


# ---------------------------------------------------------------- transport (telnet / ssh)
IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240
OPT_NAWS = 31
NAWS_COLS, NAWS_ROWS = 200, 50
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
ANSI_LEFT = re.compile(r"\x1b\[(\d*)D")
PROMPT = re.compile(r"(?:^|\n)[\w\-.()/]+[#>]\s*$")
USER_P = re.compile(r"(?:user ?name|login)\s*:\s*$", re.I)
PASS_P = re.compile(r"pass ?word\s*:\s*$", re.I)
FAIL_P = re.compile(r"(fail|incorrect|invalid|denied|bad)", re.I)
MORE = re.compile(r"-{2,}\s*More\s*(?:\([^)]*\))?\s*-{2,}", re.I)
CONFIRM = re.compile(r"(\[y/n\]|\(y/n\)(?:\[[yn]\])?|\[confirm\]|\(yes/no\))\s*:?\s*$", re.I)
CR_PROMPT = re.compile(r"\{\s*<cr>[^}]*\}\s*:\s*$", re.I)


def strip_ansi(text):
    """Turns 'cursor-left' (ESC[nD) into backspace (render_term understands it) and removes other escapes."""
    text = ANSI_LEFT.sub(lambda m: "\b" * int(m.group(1) or 1), text)
    return ANSI.sub("", text)


def render_term(text):
    """Tiny terminal emulator: \\r (start of line) and \\b (backspace) overwrite text.
    If the device repaints a line again and again (garbled text), this fixes it."""
    lines, cur, pos = [], [], 0
    for ch in text:
        if ch == "\n":
            lines.append("".join(cur).rstrip())
            cur, pos = [], 0
        elif ch == "\r":
            pos = 0
        elif ch == "\b":
            pos = max(0, pos - 1)
        elif ch in "\x00\x07\x0b\x0c":
            continue
        else:
            if pos < len(cur):
                cur[pos] = ch
            else:
                cur.append(ch)
            pos += 1
    lines.append("".join(cur).rstrip())
    return "\n".join(lines)


class LoginError(Exception):
    pass


class Shell:
    """Common part of Telnet/SSH: buffer, read_until, run."""

    def __init__(self):
        self.buf = ""

    def _pump(self):
        raise NotImplementedError

    def _write(self, data):
        raise NotImplementedError

    def close(self):
        pass

    def send(self, text):
        self._write((text + "\r\n").encode("utf-8", errors="replace"))

    def read_until(self, patterns, timeout=12):
        """Returns (index, text); on timeout returns (-1, text)."""
        end = time.time() + timeout
        while True:
            for i, p in enumerate(patterns):
                m = p.search(self.buf)
                if m:
                    text, self.buf = self.buf[:m.end()], self.buf[m.end():]
                    return i, text
            if time.time() > end:
                text, self.buf = self.buf, ""
                return -1, text
            self._pump()

    def drain(self, wait=0.6):
        """Reads and discards the banner/warnings that keep arriving after login, until they stop."""
        end = time.time() + wait
        while time.time() < end:
            before = len(self.buf)
            self._pump()
            if len(self.buf) != before:
                end = time.time() + wait
        self.buf = ""

    def run(self, cmd, timeout=25, confirm_yes=False):
        self.send(cmd)
        out = ""
        while True:
            i, text = self.read_until([PROMPT, MORE, CONFIRM, CR_PROMPT], timeout)
            if i == 1:                       # --More-- : press space for the next page
                out += text[:MORE.search(text).start()]
                self._write(b" ")
                continue
            if i == 2:                       # device asked "[y/n]"
                out += text
                if not confirm_yes:
                    self.send("n")
                    raise RuntimeError("the device asked for confirmation, so I cancelled it")
                self.send("yes" if re.search(r"yes/no", text, re.I) else "y")
                continue
            if i == 3:                       # Huawei "{ <cr>|... }:" -> press Enter
                out += text
                self.send("")
                continue
            out += text
            if i == -1:
                raise TimeoutError(f"No reply to '{cmd}'. Last received: {out[-300:]!r}")
            break
        out = render_term(out)               # fix \r / backspace (garbled text fix)
        lines = out.split("\n")
        head = cmd.strip()[:12]              # remove the echoed command line (one or more)
        while lines and (not lines[0].strip() or head in lines[0]):
            lines = lines[1:]
        if lines and PROMPT.search("\n" + lines[-1]):
            lines = lines[:-1]
        return "\n".join(lines).strip()


class Telnet(Shell):
    def __init__(self, host, port=23, timeout=8):
        super().__init__()
        self.sock = socket.create_connection((host, int(port)), timeout=timeout)
        self.sock.settimeout(1.0)
        self.raw = b""
        self.sock.sendall(bytes([IAC, WILL, OPT_NAWS]))   # we want to send the window size (so output is wider)

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

    def _write(self, data):
        self.sock.sendall(data)

    def _pump(self):
        try:
            data = self.sock.recv(4096)
        except socket.timeout:
            return
        if not data:
            raise ConnectionError("the OLT closed the connection")
        self._feed(data)

    def _feed(self, data):
        data = self.raw + data
        self.raw = b""
        out = bytearray()
        i, n = 0, len(data)
        while i < n:
            b = data[i]
            if b != IAC:
                out.append(b)
                i += 1
                continue
            if i + 1 >= n:
                self.raw = data[i:]
                break
            cmd = data[i + 1]
            if cmd == IAC:
                out.append(IAC)
                i += 2
            elif cmd in (DO, DONT, WILL, WONT):
                if i + 2 >= n:
                    self.raw = data[i:]
                    break
                opt = data[i + 2]
                if cmd == WILL:
                    self.sock.sendall(bytes([IAC, DO if opt in (1, 3) else DONT, opt]))
                elif cmd == DO:
                    if opt == OPT_NAWS:
                        self.sock.sendall(bytes([IAC, SB, OPT_NAWS, 0, NAWS_COLS, 0, NAWS_ROWS, IAC, SE]))
                    else:
                        self.sock.sendall(bytes([IAC, WONT, opt]))
                i += 3
            elif cmd == SB:
                end = data.find(bytes([IAC, SE]), i + 2)
                if end < 0:
                    self.raw = data[i:]
                    break
                i = end + 2
            else:
                i += 2
        self.buf += strip_ansi(out.decode("utf-8", errors="replace"))


class SSHShell(Shell):
    """For Huawei. Needs paramiko (pip install paramiko). Not tested on a real OLT yet."""

    def __init__(self, host, port, user, pw, timeout=10):
        super().__init__()
        if paramiko is None:
            raise RuntimeError("SSH needs 'pip install paramiko'")
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            self.client.connect(host, port=int(port), username=user, password=pw, timeout=timeout,
                                banner_timeout=timeout, auth_timeout=timeout,
                                look_for_keys=False, allow_agent=False)
        except (socket.timeout, TimeoutError):
            raise TimeoutError(f"SSH connect timeout: could not connect to {host}:{port} within {timeout}s")
        self.chan = self.client.invoke_shell(term="xterm", width=200, height=1000)

    def close(self):
        for o in (getattr(self, "chan", None), getattr(self, "client", None)):
            try:
                if o:
                    o.close()
            except Exception:
                pass

    def _write(self, data):
        self.chan.send(data)

    def _pump(self):
        if self.chan.recv_ready():
            data = self.chan.recv(4096)
            self.buf += strip_ansi(data.decode("utf-8", errors="replace"))
            return
        if self.chan.closed or self.chan.exit_status_ready():
            raise ConnectionError("the SSH connection was closed")
        time.sleep(0.05)


def device_login(sh, user, pw, ssh=False):
    """Logs in and returns the last prompt text ('>' or '#')."""
    if ssh:
        i, got = sh.read_until([PROMPT], 20)
        if i != 0:
            raise TimeoutError(f"Did not get a prompt after login. The OLT sent: {got[-300:]!r}")
    else:
        i, got = sh.read_until([USER_P, PROMPT], 15)
        if i == 0:
            sh.send(user)
            i, _ = sh.read_until([PASS_P], 10)
            if i != 0:
                raise LoginError("password prompt did not appear")
            sh.send(pw)
            i, _ = sh.read_until([PROMPT, USER_P, FAIL_P], 12)
            if i != 0:
                raise LoginError("login failed (wrong username/password?)")
        elif i != 1:
            raise TimeoutError(f"Did not get a login prompt. The OLT sent: {got[-300:]!r}")
    sh.drain()                                # let the banner/warnings finish
    sh.send("")
    i, txt = sh.read_until([PROMPT], 8)
    if i != 0:
        raise TimeoutError(f"Did not get a prompt after Enter. The OLT sent: {txt[-300:]!r}")
    return txt


def post_login(sh, olt, prof, pw, prompt):
    if prompt.rstrip().endswith(">"):         # user mode -> enable
        audit(olt["name"], "enable")
        sh.send("enable")
        i, _ = sh.read_until([PASS_P, PROMPT], 8)
        if i == 0:
            sh.send(pw)
            sh.read_until([PROMPT], 8)
    for cmd in prof.get("setup", []):
        run_ctl(sh, olt, cmd)
    for key in ("paging_off", "width_cmd"):
        if prof.get(key):
            try:
                sh.run(prof[key])
            except Exception:
                pass


def run_ctl(sh, olt, cmd):
    if not CTRL_CMD.match(cmd):
        raise ValueError(f"Blocked command: {cmd!r}")
    audit(olt["name"], cmd)
    return sh.run(cmd)


def run_show(sh, olt, cmd, allow_danger=False):
    if SAFE_CMD.match(cmd):
        confirm = False
    elif allow_danger and any(r.match(cmd) for r in DANGER_CMDS):
        confirm = True
    else:
        raise ValueError(f"Blocked command: {cmd!r} (only show/display and the reboot/reset buttons are allowed)")
    audit(olt["name"], cmd)
    return sh.run(cmd, confirm_yes=confirm)


def open_session(olt, user, pw):
    vendor = olt.get("vendor", "bdcom")
    prof = PROFILES[vendor]
    ssh = str(olt.get("protocol") or "TELNET").upper() == "SSH"
    sh = SSHShell(olt["host"], olt.get("port", 22), user, pw) if ssh else Telnet(olt["host"], olt.get("port", 23))
    try:
        prompt = device_login(sh, user, pw, ssh=ssh)
        post_login(sh, olt, prof, pw, prompt)
    except Exception:
        sh.close()
        raise
    return sh, prof


# ---------------------------------------------------------------- search logic
class SearchState:
    def __init__(self, keys):
        self.lock = threading.Lock()
        self.pending = set(keys)
        self.hits = []
        self.searched = []
        self.skipped = {}
        self.errors = {}

    def remaining(self):
        with self.lock:
            return sorted(self.pending)

    def claim(self, key, hit):
        with self.lock:
            if key in self.pending:
                self.pending.discard(key)
                self.hits.append(hit)
                return True
            return False


def fmt_args(h):
    return {"frame": h.get("frame", ""), "slot": h["slot"], "pon": h["pon"], "onu": h["onu"]}


def fill(c, h):
    return c["cmd"].format(**fmt_args(h))


def find_key(sh, olt, prof, key, mode):
    """key = ONU SN (mode 'sn') or Router MAC (mode 'mac'). Returns a hit dict or None."""
    if mode == "sn":
        for v in prof["sn_variants"](key):
            out = run_show(sh, olt, prof["find_sn"].format(sn=v))
            d = prof["parse_sn"](out)
            if d:
                return make_hit(olt, key, d, out)
    else:
        mac = hex12(key)
        for cmd in prof["mac_cmds"](mac):
            out = run_show(sh, olt, cmd)
            d = prof["parse_mac"](out, mac)
            if d:
                return make_hit(olt, key, d, out)
    return None


def make_hit(olt, key, d, raw):
    return {"olt": olt["name"], "group": olt.get("group", ""), "sn_input": key,
            "sn_device": d["sn"] or key, "frame": d["frame"], "slot": d["slot"], "pon": d["pon"],
            "onu": d["onu"], "model": d["model"], "loid": d["loid"], "status": d["status"],
            "active": d["active"], "vendor": olt.get("vendor", "bdcom"), "olt_cfg": olt,
            "raw": raw, "details": []}


def run_in_context(sh, olt, prof, hit, items):
    """items: [(command_dict, allow_danger)]. On Huawei, first enters 'interface gpon F/S', then quits at the end."""
    ctx, entered, results = prof.get("context"), False, []

    def one(i, c, danger):
        cmd = fill(c, hit)
        try:
            out = run_show(sh, olt, cmd, allow_danger=danger)
        except Exception as e:
            out = f"(error: {err_text(e)})"
        results.append((i, c["title"], cmd, out))

    items = list(items)
    try:
        for i, (c, danger) in enumerate(items):          # 1) commands that run before 'interface gpon F/S'
            if c.get("global"):
                one(i, c, danger)
        if ctx and any(not c.get("global") for c, _d in items):
            run_ctl(sh, olt, ctx.format(**fmt_args(hit)))
            entered = True
        for i, (c, danger) in enumerate(items):          # 2) the rest, inside the interface
            if not c.get("global"):
                one(i, c, danger)
    finally:
        if entered:
            try:
                run_ctl(sh, olt, "quit")
            except Exception:
                pass
    results.sort(key=lambda r: r[0])
    return [(t, cmd, out) for _i, t, cmd, out in results]


def search_on_olt(olt, state, user, pw, status=lambda s: None, mode="sn"):
    name = olt["name"]
    if not state.remaining():
        return
    vendor = olt.get("vendor", "bdcom")
    prof = PROFILES.get(vendor)
    proto = str(olt.get("protocol") or "TELNET").upper()
    if not olt.get("host"):
        state.skipped[name] = "no IP given"
        return
    if not prof:
        state.skipped[name] = f"commands for vendor '{vendor}' are not added yet"
        return
    if proto not in ("TELNET", "SSH"):
        state.skipped[name] = f"{proto} is not supported"
        return
    if proto == "SSH" and paramiko is None:
        state.skipped[name] = "SSH needs 'pip install paramiko'"
        return
    sh = None
    try:
        status(f"{name}: connecting...")
        sh, prof = open_session(olt, user, pw)
        for key in state.remaining():
            status(f"{name}: searching for {key}...")
            hit = find_key(sh, olt, prof, key, mode)
            if hit and state.claim(key, hit):
                status(f"{name}: found {key}, getting details...")
                autos = [(c, False) for c in prof["commands"] if c.get("auto")]
                hit["details"].extend(run_in_context(sh, olt, prof, hit, autos))
        with state.lock:
            state.searched.append(name)
    except Exception as e:
        state.errors[name] = err_text(e)
    finally:
        if sh:
            sh.close()


def run_search(olts, keys, user, pw, status=lambda s: None, mode="sn"):
    state = SearchState(keys)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = [ex.submit(search_on_olt, o, state, user, pw, status, mode) for o in olts]
        for f in futures:
            f.result()
    return state


def run_for_hit(h, c, user, pw):
    """Button click: logs in again to the OLT of that ONU and runs one command. -> (cmd, output)"""
    olt = h["olt_cfg"]
    sh, prof = open_session(olt, user, pw)
    try:
        title, cmd, out = run_in_context(sh, olt, prof, h, [(c, bool(c.get("danger")))])[0]
    finally:
        sh.close()
    return cmd, out


# The device printed an error instead of data (wrong number, unknown command, ONU does not exist ...)
DEV_ERR_RE = re.compile(r"(?im)unknown command|invalid input|incomplete command|ambiguous command|"
                        r"unrecognized command|^\s*%|failure:|does not exist|not exist|no such")


def looks_bad(out):
    out = str(out or "").strip()
    return (not out) or out.startswith("(error:") or bool(DEV_ERR_RE.search(out))


def parse_pon_onu(vendor, text):
    """BDCOM: '7 48', '0/7 48', '0/7:48'.   Huawei: '0/1/7 12', '0/1/7:12'.
    Words like gpon / pon / onu / ont are allowed and ignored. -> dict(frame, slot, pon, onu)"""
    t = re.sub(r"(?i)gpon|pon|onu|ont", " ", str(text))
    t = re.sub(r"\s+", " ", t).strip()
    if vendor == "huawei":
        m = re.fullmatch(r"(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s*[ :,]\s*(\d+)", t)
        if not m:
            raise ValueError("For Huawei enter F/S/P and the ONT id, for example 0/1/7 12")
        return {"frame": m[1], "slot": m[2], "pon": m[3], "onu": m[4]}
    m = re.fullmatch(r"(?:(\d+)\s*/\s*)?(\d+)\s*[ :,]\s*(\d+)", t)
    if not m:
        raise ValueError("For BDCOM enter the PON and the ONU id, for example 7 48 or 0/7:48")
    return {"frame": "", "slot": m[1] or "0", "pon": m[2], "onu": m[3]}


def run_manual_onu(olts, pairs, user, pw, status=lambda s: None):
    """You choose the OLT(s) and give PON + ONU numbers. No SN is needed.
    For each pair it runs the same 'auto' commands that run after an ONU is found."""
    st = {"hits": [], "skipped": {}, "errors": {}, "done": []}
    lock = threading.Lock()

    def work(olt):
        name = olt["name"]
        vendor = olt.get("vendor", "bdcom")
        prof = PROFILES.get(vendor)
        proto = str(olt.get("protocol") or "TELNET").upper()
        if not olt.get("host"):
            st["skipped"][name] = "no IP given"
            return
        if not prof:
            st["skipped"][name] = f"commands for vendor '{vendor}' are not added yet"
            return
        if proto not in ("TELNET", "SSH"):
            st["skipped"][name] = f"{proto} is not supported"
            return
        if proto == "SSH" and paramiko is None:
            st["skipped"][name] = "SSH needs 'pip install paramiko'"
            return
        todo = []
        for p in pairs:
            try:
                todo.append((p, parse_pon_onu(vendor, p)))
            except ValueError as e:
                st["skipped"][f"{name}  [{p}]"] = str(e)
        if not todo:
            return
        autos = [(c, False) for c in prof["commands"] if c.get("auto")]
        sh = None
        try:
            status(f"{name}: connecting...")
            sh, prof = open_session(olt, user, pw)
            for p, d in todo:
                label = f"PON {d['pon']}  ONU {d['onu']}"
                status(f"{name}: {label}...")
                hit = {"olt": name, "group": olt.get("group", ""), "sn_input": label, "sn_device": label,
                       "frame": d["frame"], "slot": d["slot"], "pon": d["pon"], "onu": d["onu"],
                       "model": "", "loid": "", "status": "", "active": "", "vendor": vendor,
                       "olt_cfg": olt, "raw": "", "details": []}
                hit["details"].extend(run_in_context(sh, olt, prof, hit, autos))
                outs = [o for _t, _c, o in hit["details"]]
                if outs and all(looks_bad(o) for o in outs):
                    hit["status"] = "no data - check the PON/ONU number"
                else:
                    for o in outs:
                        m = re.search(r"Run state\s*:\s*(\S+)", o)
                        if m:
                            hit["status"] = m.group(1)
                            break
                with lock:
                    st["hits"].append(hit)
            st["done"].append(name)
        except Exception as e:
            st["errors"][name] = err_text(e)
        finally:
            if sh:
                sh.close()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for f in [ex.submit(work, o) for o in olts]:
            f.result()
    return st


def parse_pon(vendor, text):
    """BDCOM: '7' or '0/7'.  Huawei: '0/1/7' (frame/slot/port)."""
    t = str(text).strip().lower().replace("gpon", "").strip()
    if vendor == "huawei":
        m = re.fullmatch(r"(\d+)\s*/\s*(\d+)\s*/\s*(\d+)", t)
        if not m:
            raise ValueError("For Huawei enter F/S/P, for example 0/1/7")
        return {"frame": m.group(1), "slot": m.group(2), "pon": m.group(3)}
    m = re.fullmatch(r"(?:(\d+)\s*/\s*)?(\d+)", t)
    if not m:
        raise ValueError("For BDCOM enter a PON number, for example 7 or 0/7")
    return {"frame": "", "slot": m.group(1) or "0", "pon": m.group(2)}


def run_pon_status(olts, pons, title, user, pw, status=lambda s: None):
    """Runs the command for the given PON numbers on the selected OLTs. No ONU is needed."""
    state = {"rows": [], "skipped": {}, "errors": {}, "done": []}
    lock = threading.Lock()

    def work(olt):
        name = olt["name"]
        vendor = olt.get("vendor", "bdcom")
        prof = PROFILES.get(vendor)
        proto = str(olt.get("protocol") or "TELNET").upper()
        if not olt.get("host"):
            state["skipped"][name] = "no IP given"
            return
        if not prof:
            state["skipped"][name] = f"commands for vendor '{vendor}' are not added yet"
            return
        if proto == "SSH" and paramiko is None:
            state["skipped"][name] = "SSH needs 'pip install paramiko'"
            return
        c = next((c for c in prof["commands"] if c["title"] == title and c["scope"] in ("pon", "olt")), None)
        if not c:
            state["skipped"][name] = f"'{title}' command does not exist for this vendor ({PROFILES[vendor]['title']})"
            return
        needs_pon = "{pon}" in c["cmd"]
        sh = None
        try:
            status(f"{name}: connecting...")
            sh, prof = open_session(olt, user, pw)
            for p in (pons if needs_pon else [""]):
                row = {"olt": name, "group": olt.get("group", ""), "sn_input": f"PON {p}" if needs_pon else "(OLT level)",
                       "sn_device": f"PON {p}" if needs_pon else "(OLT level)", "frame": "", "slot": "0",
                       "pon": "", "onu": "", "model": "", "loid": "", "status": "", "active": "",
                       "vendor": olt.get("vendor", "bdcom"), "olt_cfg": olt, "raw": "", "details": [],
                       "pon_only": True}
                try:
                    if needs_pon:
                        row.update(parse_pon(row["vendor"], p))
                    status(f"{name}: {title} ({p or 'all'})...")
                    row["details"].extend(run_in_context(sh, olt, prof, row, [(c, False)]))
                except Exception as e:
                    row["details"].append((title, "-", f"(error: {err_text(e)})"))
                with lock:
                    state["rows"].append(row)
            state["done"].append(name)
        except Exception as e:
            state["errors"][name] = err_text(e)
        finally:
            if sh:
                sh.close()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for f in [ex.submit(work, o) for o in olts]:
            f.result()
    return state


# ---------------------------------------------------------------- PON monitor (LOSi / Offline / Online)
def classify_pon(vendor, text, pon_label):
    """Splits the ONU list of a PON (text) into groups. Each group is {key: line}.
       LOSi    = offline ONUs whose line has LOSi / LOS / LOBi.
       Offline = all offline ONUs (whatever the cause; LOSi and Dying Gasp ones are also here, and shown separately too).
       Dying   = ONUs whose cause says Dying Gasp.
       Online  = online ONUs (Huawei only; the BDCOM inactive list has no online ONUs).
       Inactive (internal, used for the diff) = LOSi + Offline.
       Key = the ONU's id, so refreshes can be compared."""
    inactive, losi, online, dying = {}, {}, {}, {}
    for raw in str(text).splitlines():
        line = raw.rstrip()
        low = line.lower()
        if not line.strip():
            continue
        if vendor == "huawei":
            m = HUAWEI_ROW.match(line)
            if m:
                key = f"{pon_label}:{m.group(4)}"
            elif ((LOSI_RE.search(line) or "offline" in low or "online" in low)
                  and "total" not in low and "---" not in line):
                key = re.sub(r"\s+", " ", line.strip())      # if the format does not match, the line itself is the key
            else:
                continue
            if re.search(r"\bonline\b", low):
                online[key] = line
                continue
        else:
            m = BDCOM_IF.search(line)
            if not m:
                continue
            key = f"{m.group(1)}/{m.group(2)}:{m.group(3)}"
        inactive[key] = line
        if LOSI_RE.search(line):
            losi[key] = line
        elif DYING_RE.search(line):
            dying[key] = line
    offline = dict(inactive)                 # all offline ONUs (LOSi / Dying Gasp / any other cause)
    return {"LOSi": losi, "Offline": offline, "Dying": dying, "Online": online, "Inactive": inactive,
            "has_online": vendor == "huawei", "causes": {}, "dg_checked": False}


def monitor_diff(cats, prev_cats):
    """Compares with the previous refresh. -> (new inactive, recovered) key sets."""
    if not prev_cats:
        return set(), set()
    cur, prev = set(cats["Inactive"]), set(prev_cats["Inactive"])
    return cur - prev, prev - cur


def extract_cause(text):
    """Returns the last 'down cause' / 'dying gasp' line from an ONU's detail output. '' if none."""
    lines = [l.strip() for l in str(text).splitlines() if l.strip()]
    hits = [l for l in lines if CAUSE_RE.search(l) or DYING_RE.search(l)]
    return hits[-1] if hits else ""


def apply_causes(cats, causes):
    """If a cause says Dying Gasp, move that ONU from Offline to the Dying group."""
    cats["causes"] = dict(causes)
    cats["dg_checked"] = True
    for k, cause in causes.items():
        if k in cats["Offline"] and DYING_RE.search(cause):
            cats["Dying"][k] = cats["Offline"][k]


def run_pon_monitor(olts, pons, user, pw, status=lambda s: None, check_dg=False):
    """Logs in once per OLT, runs one command for every PON, and splits into LOSi/Offline/Dying/Online.
    If check_dg=True, it checks the cause of the Offline ONUs (max DG_MAX) with a separate command to find Dying Gasp."""
    out = {"rows": [], "skipped": {}, "errors": {}, "done": []}
    lock = threading.Lock()

    def work(olt):
        name = olt["name"]
        vendor = olt.get("vendor", "bdcom")
        prof = PROFILES.get(vendor)
        proto = str(olt.get("protocol") or "TELNET").upper()
        if not olt.get("host"):
            out["skipped"][name] = "no IP given"
            return
        if not prof:
            out["skipped"][name] = f"commands for vendor '{vendor}' are not added yet"
            return
        if proto not in ("TELNET", "SSH"):
            out["skipped"][name] = f"{proto} is not supported"
            return
        if proto == "SSH" and paramiko is None:
            out["skipped"][name] = "SSH needs 'pip install paramiko'"
            return
        c = next((c for c in prof["commands"] if c["title"] == MONITOR_CMD_TITLE), None)
        if not c:
            out["skipped"][name] = f"'{MONITOR_CMD_TITLE}' command does not exist"
            return
        sh = None
        try:
            status(f"{name}: connecting...")
            sh, prof = open_session(olt, user, pw)
            for p in pons:
                row = {"olt": name, "olt_key": olt_key(olt), "vendor": vendor, "pon_in": p,
                       "cats": None, "error": "", "raw": ""}
                ctx = {"frame": "", "slot": "0", "pon": "", "onu": ""}
                try:
                    ctx.update(parse_pon(vendor, p))
                    label = (f"{ctx['frame']}/{ctx['slot']}/{ctx['pon']}" if ctx["frame"]
                             else f"{ctx['slot']}/{ctx['pon']}")
                    row["pon_label"] = label
                    status(f"{name}: checking PON {label}...")
                    text = run_in_context(sh, olt, prof, ctx, [(c, False)])[0][2]
                    row["raw"] = text
                    if text.startswith("(error:"):
                        row["error"] = text
                    else:
                        row["cats"] = classify_pon(vendor, text, label)
                        if check_dg:
                            cc = next((x for x in prof["commands"]
                                       if x["title"] == CAUSE_CMD_TITLE.get(vendor)), None)
                            todo = [k for k in sorted(row["cats"]["Offline"], key=natural_key)
                                    if k not in row["cats"]["LOSi"] and k not in row["cats"]["Dying"]
                                    and ":" in k and k.rsplit(":", 1)[-1].isdigit()][:DG_MAX]
                            causes = {}
                            for k in (todo if cc else []):
                                status(f"{name}: PON {label} checking the cause for ONU {k.rsplit(':', 1)[-1]}...")
                                octx = dict(ctx, onu=k.rsplit(":", 1)[-1])
                                try:
                                    causes[k] = extract_cause(run_in_context(sh, olt, prof, octx, [(cc, False)])[0][2])
                                except Exception:
                                    pass
                            apply_causes(row["cats"], causes)
                except Exception as e:
                    row["error"] = f"(error: {err_text(e)})"
                with lock:
                    out["rows"].append(row)
            out["done"].append(name)
        except Exception as e:
            out["errors"][name] = err_text(e)
        finally:
            if sh:
                sh.close()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for f in [ex.submit(work, o) for o in olts]:
            f.result()
    return out


def hit_iface(h):
    if h.get("pon_only"):
        if not h.get("pon"):
            return "(OLT level)"
        return f"{h['frame']}/{h['slot']}/{h['pon']}" if h.get("frame") else f"GPON{h['slot']}/{h['pon']}"
    if h.get("frame"):
        return f"{h['frame']}/{h['slot']}/{h['pon']}  ONT {h['onu']}"
    return f"GPON{h['slot']}/{h['pon']}:{h['onu']}"


def hit_text(h):
    lines = [f"Input     : {h['sn_input']}" + (f"  (device SN: {h['sn_device']})" if h["sn_device"] != h["sn_input"] else ""),
             f"OLT       : {h['olt']}  [{PROFILES[h['vendor']]['title']}]",
             f"Interface : {hit_iface(h)}",
             f"PON       : {h['pon'] or '-'}"]
    if not h.get("pon_only"):
        lines.append(f"ONU       : {h['onu']}")
    if h.get("model"):
        lines.append(f"Model     : {h['model']}")
    if h.get("loid"):
        lines.append(f"LOID      : {h['loid']}")
    if h.get("status"):
        lines.append(f"Status    : {h['status']}" + (f"   (active time: {h['active']})" if h.get("active") else ""))
    for title, cmd, out in h.get("details", []):
        lines += ["", f"--- {title}   ({cmd}) ---", out or "(no output)"]
    return "\n".join(lines)


# ---------------------------------------------------------------- settings
def load_settings():
    try:
        return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_settings(d):
    try:
        DATA_DIR.mkdir(exist_ok=True)
        SETTINGS_FILE.write_text(json.dumps(d, indent=2), encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------------- GUI
_Base = tk.Tk if tk else object

DEFAULT_HEADS = (("sn", "Input"), ("olt", "OLT"), ("intf", "Interface (PON:ONU)"),
                 ("model", "Model"), ("state", "Status"))
MONITOR_HEADS = (("sn", "PON"), ("olt", "OLT"), ("intf", "LOSi / Offline / Online"),
                 ("model", "Change"), ("state", "Updated"))


class App(_Base):
    def __init__(self):
        super().__init__()
        self.title("OLT ONU Finder")
        self.geometry("1150x740")
        self.settings = load_settings()
        self.q = queue.Queue()
        self.pw = None
        self.busy = False
        self.details = {}
        self.hit_by_item = {}
        self.act_btns = []
        self.mon_detail = {}      # colored detail of a monitor row
        self.snap = {}            # result of the previous refresh (for comparing)
        self.last_monitor = None
        self.auto_job = None
        self.matches = []         # matches of the find bar
        self.cur_match = -1
        self.maxed = False        # is 'Maximize output' on?
        self.tree_h = int(self.settings.get("tree_h", 190))
        self.olts = load_olts()
        if not self.olts:
            self.first_run()
        if apply_ip_fixes(self.olts):
            save_olts(self.olts)
        last = set(self.settings.get("selected", []))
        self.vars = {olt_key(o): tk.BooleanVar(value=olt_key(o) in last) for o in self.olts}
        self.build_ui()
        self.rebuild_list()
        self.bind("<Control-f>", self.open_find)
        self.bind("<Control-F>", self.open_find)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(100, self.poll)

    def first_run(self):
        olts = import_all(find_xshell_sessions())
        self.olts = olts or seed_olts()
        save_olts(self.olts)

    def on_close(self):
        try:
            self.settings["left_w"] = int(self.panes.sash_coord(0)[0])
        except Exception:
            pass
        try:
            if not self.maxed:
                self.settings["tree_h"] = int(self.vpanes.sash_coord(0)[1])
            else:
                self.settings["tree_h"] = int(self.tree_h)
        except Exception:
            pass
        save_settings(self.settings)
        self.cancel_auto()
        self.destroy()

    def build_ui(self):
        # a divider between left and right that you can drag (resize the panels as you like)
        self.panes = tk.PanedWindow(self, orient="horizontal", sashwidth=8, sashrelief="raised", bd=0)
        self.panes.pack(fill="both", expand=True)

        left = tk.Frame(self.panes, width=360)
        left.pack_propagate(False)
        self.panes.add(left, minsize=230, width=360, padx=8, pady=8)
        tk.Label(left, text="Select area / OLT", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.rebuild_list())
        tk.Entry(left, textvariable=self.filter_var).pack(fill="x", pady=4)
        btns = tk.Frame(left)
        btns.pack(fill="x")
        tk.Button(btns, text="Select all", command=lambda: self.set_all(True)).pack(side="left")
        tk.Button(btns, text="Clear", command=lambda: self.set_all(False)).pack(side="left", padx=4)
        tk.Button(btns, text="Edit list", command=self.edit_list).pack(side="left")
        tk.Button(btns, text="Edit OLT", command=self.edit_selected).pack(side="left", padx=4)
        btns2 = tk.Frame(left)
        btns2.pack(fill="x", pady=(2, 0))
        tk.Button(btns2, text="Import from Xshell (auto)", command=self.do_import).pack(side="left")
        tk.Button(btns2, text="Choose folder", command=self.import_folder).pack(side="left", padx=4)
        tk.Button(btns2, text="Default OLT list", command=self.load_defaults).pack(side="left")
        self.count_lbl = tk.Label(left, text="", anchor="w", fg="#555")
        self.count_lbl.pack(fill="x")

        wrap = tk.Frame(left, bd=1, relief="sunken")
        wrap.pack(fill="both", expand=True)
        self.canvas = tk.Canvas(wrap, highlightthickness=0)
        sb = tk.Scrollbar(wrap, command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.list_frame = tk.Frame(self.canvas)
        self.win = self.canvas.create_window((0, 0), window=self.list_frame, anchor="nw")
        self.list_frame.bind("<Configure>",
                             lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self.win, width=e.width))
        self.canvas.bind("<Enter>", lambda e: self.canvas.bind_all("<MouseWheel>", self.on_wheel))
        self.canvas.bind("<Leave>", lambda e: self.canvas.unbind_all("<MouseWheel>"))

        right = tk.Frame(self.panes)
        self.panes.add(right, minsize=560, stretch="always", padx=4, pady=8)

        # ---- upper part: mode, input, search button, status (hidden by Maximize)
        self.upper = tk.Frame(right)
        self.upper.pack(fill="x")
        up = self.upper
        modes = tk.Frame(up)
        modes.pack(anchor="w")
        self.mode_var = tk.StringVar(value="sn")
        for text, val in (("ONU MAC / SN", "sn"), ("Router MAC", "mac"),
                          ("PON status", "pon"), ("PON monitor (LOSi / Offline / Online)", "monitor"),
                          ("PON + ONU (manual)", "onu")):
            tk.Radiobutton(modes, text=text, variable=self.mode_var, value=val,
                           command=self.update_mode).pack(side="left", padx=(0, 10))
        self.input_lbl = tk.Label(up, text="", font=("Segoe UI", 11, "bold"))
        self.input_lbl.pack(anchor="w")
        self.sn_text = tk.Text(up, height=5, font=("Consolas", 11))
        self.sn_text.pack(fill="x", pady=4)

        self.pon_row = tk.Frame(up)
        tk.Label(self.pon_row, text="What to view:").pack(side="left")
        self.pon_cmd_var = tk.StringVar(value=PON_TITLES[0])
        ttk.Combobox(self.pon_row, textvariable=self.pon_cmd_var, values=PON_TITLES,
                     state="readonly", width=24).pack(side="left", padx=6)
        tk.Label(self.pon_row, text="(All PON Status does not need a PON number)", fg="#555").pack(side="left")

        self.mon_row = tk.Frame(up)
        self.auto_var = tk.BooleanVar(value=False)
        self.auto_sec = tk.StringVar(value="30")
        tk.Checkbutton(self.mon_row, text="Auto refresh, every", variable=self.auto_var,
                       command=self.schedule_auto).pack(side="left")
        tk.Spinbox(self.mon_row, from_=MIN_AUTO_SEC, to=600, increment=10, width=5,
                   textvariable=self.auto_sec).pack(side="left", padx=3)
        tk.Label(self.mon_row, text="sec").pack(side="left")
        tk.Button(self.mon_row, text="Reset baseline", command=self.reset_baseline).pack(side="left", padx=8)
        self.dg_var = tk.BooleanVar(value=False)
        tk.Checkbutton(self.mon_row, text="Dying Gasp check (slow)", variable=self.dg_var).pack(side="left")
        tk.Label(self.mon_row, text="Search = Refresh.  [NEW] newly inactive,  [BACK] recovered",
                 fg="#555").pack(side="left")

        row = tk.Frame(up)
        row.pack(fill="x")
        self.search_btn = tk.Button(row, text="Search", width=14, command=self.start_search,
                                    bg="#2563eb", fg="white")
        self.search_btn.pack(side="left")
        tk.Label(row, text="  User:").pack(side="left")
        self.user_var = tk.StringVar(value=self.settings.get("user", DEFAULT_USER))
        tk.Entry(row, textvariable=self.user_var, width=14).pack(side="left")
        tk.Button(row, text="Set password", command=self.set_password).pack(side="left", padx=6)
        tk.Button(row, text="Copy result", command=self.copy_result).pack(side="left")
        self.status = tk.Label(up, text="Ready.", anchor="w", fg="#555")
        self.status.pack(fill="x", pady=(6, 2))

        # ---- lower part: a draggable divider (top = table + action buttons, bottom = output)
        self.vpanes = tk.PanedWindow(right, orient="vertical", sashwidth=8, sashrelief="raised", bd=0)
        self.vpanes.pack(fill="both", expand=True)

        self.tree_frame = tk.Frame(self.vpanes)
        self.act_frame = tk.Frame(self.tree_frame)
        self.act_frame.pack(side="bottom", fill="x")
        cols = tuple(c for c, _ in DEFAULT_HEADS)
        self.tree = ttk.Treeview(self.tree_frame, columns=cols, show="headings", height=4)
        for c, t in DEFAULT_HEADS:
            self.tree.heading(c, text=t)
        for c, w in (("sn", 150), ("olt", 220), ("intf", 150), ("model", 100), ("state", 140)):
            self.tree.column(c, width=w)
        self.tree.tag_configure("changed", background="#fde68a")
        self.tree.tag_configure("err", foreground="#b91c1c")
        tsb = tk.Scrollbar(self.tree_frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tsb.set)
        tsb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True, pady=(0, 4))
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        self.vpanes.add(self.tree_frame, minsize=60, height=self.tree_h)

        self.out_frame = tk.Frame(self.vpanes)
        head = tk.Frame(self.out_frame)
        head.pack(fill="x")
        tk.Button(head, text="Find (Ctrl+F)", command=self.open_find).pack(side="left")
        self.max_btn = tk.Button(head, text="Maximize output", command=self.toggle_max)
        self.max_btn.pack(side="left", padx=6)
        tk.Label(head, text="   Highlight date:").pack(side="left")
        self.hl_var = tk.StringVar(value=date.today().strftime("%d/%m/%Y"))
        tk.Entry(head, textvariable=self.hl_var, width=12).pack(side="left")
        self.hl_var.trace_add("write", lambda *_: self.refresh_find())
        tk.Button(head, text="Today", command=self.find_today).pack(side="left", padx=4)
        self.hl_count = tk.Label(head, text="", fg="#555")
        self.hl_count.pack(side="left", padx=4)

        # find bar (shown with Ctrl+F)
        self.find_bar = tk.Frame(self.out_frame, bg="#f3f4f6")
        self.find_var = tk.StringVar()
        tk.Label(self.find_bar, text="Find:", bg="#f3f4f6").pack(side="left", padx=(4, 2))
        self.find_entry = tk.Entry(self.find_bar, textvariable=self.find_var, width=28)
        self.find_entry.pack(side="left")
        self.find_entry.bind("<Return>", lambda e: self.find_next(step=1))
        self.find_entry.bind("<Shift-Return>", lambda e: self.find_next(step=-1))
        self.find_entry.bind("<Escape>", self.close_find)
        self.find_var.trace_add("write", lambda *_: self.refresh_find())
        tk.Button(self.find_bar, text="Prev", command=lambda: self.find_next(step=-1)).pack(side="left", padx=(6, 0))
        tk.Button(self.find_bar, text="Next", command=lambda: self.find_next(step=1)).pack(side="left")
        tk.Button(self.find_bar, text="Today", command=self.find_today).pack(side="left", padx=6)
        self.find_count = tk.Label(self.find_bar, text="", bg="#f3f4f6", fg="#555")
        self.find_count.pack(side="left", padx=4)
        tk.Button(self.find_bar, text="X", command=self.close_find).pack(side="right", padx=4)

        self.outf = tk.Frame(self.out_frame)
        self.outf.pack(fill="both", expand=True)
        self.out = tk.Text(self.outf, font=("Consolas", 10), bg="#111", fg="#e6e6e6", wrap="none")
        ys = tk.Scrollbar(self.outf, command=self.out.yview)
        xs = tk.Scrollbar(self.outf, orient="horizontal", command=self.out.xview)
        self.out.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.outf.rowconfigure(0, weight=1)
        self.outf.columnconfigure(0, weight=1)
        self.out.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        self.out.tag_config("head", foreground="#93c5fd")
        self.out.tag_config("new", foreground="#fde047", background="#422006")
        self.out.tag_config("back", foreground="#86efac")
        self.out.tag_config("ok", foreground="#86efac")
        self.out.tag_config("err", foreground="#f87171")
        # the find tags are created last, so they stay on top of all other tags
        self.out.tag_config("find", background="#facc15", foreground="#000000")
        self.out.tag_config("findcur", background="#fb923c", foreground="#000000")
        self.vpanes.add(self.out_frame, minsize=120, stretch="always")

        self.update_mode()
        w = self.settings.get("left_w")
        if w:
            self.after(200, lambda: self.place_sash(w))

    def place_sash(self, x):
        try:
            self.panes.sash_place(0, int(x), 0)
        except Exception:
            pass

    # ----- output: find / highlight / maximize
    def open_find(self, _=None):
        if not self.find_bar.winfo_ismapped():
            self.find_bar.pack(fill="x", before=self.outf)
        self.find_entry.focus_set()
        self.find_entry.select_range(0, "end")
        self.refresh_find()
        return "break"

    def close_find(self, _=None):
        self.find_var.set("")
        self.find_bar.pack_forget()
        self.refresh_find()
        return "break"

    def find_today(self):
        self.find_var.set("")
        self.hl_var.set(date.today().strftime("%d/%m/%Y"))
        self.refresh_find()

    def refresh_find(self):
        """Highlights in the output. If the Find box has text, that is used; otherwise today's date (auto)."""
        out = self.out
        out.tag_remove("find", "1.0", "end")
        out.tag_remove("findcur", "1.0", "end")
        q = self.find_var.get().strip()
        hl = self.hl_var.get().strip()
        if q:
            pats = date_variants(q) or [q]
        else:
            pats = (date_variants(hl) or [hl]) if hl else []
        found = []
        cnt = tk.IntVar()
        for p in pats:
            start = "1.0"
            while True:
                idx = out.search(p, start, stopindex="end", nocase=True, count=cnt)
                if not idx or cnt.get() <= 0:
                    break
                end = f"{idx}+{cnt.get()}c"
                out.tag_add("find", idx, end)
                found.append((idx, end))
                start = end
        found.sort(key=lambda m: tuple(int(x) for x in m[0].split(".")))
        self.matches = found
        self.cur_match = -1
        if q:
            self.find_count.config(text=f"{len(found)} found" if found else "not found")
            self.hl_count.config(text="(highlighting the text in the Find box)")
            if found:
                self.goto_match(0)
        else:
            msg = f"{len(found)} found" if found else ("not found" if hl else "")
            self.find_count.config(text=f"Highlight date: {msg}" if hl else "")
            self.hl_count.config(text=msg)

    def goto_match(self, i):
        if not self.matches:
            return
        i %= len(self.matches)
        self.cur_match = i
        self.out.tag_remove("findcur", "1.0", "end")
        a, b = self.matches[i]
        self.out.tag_add("findcur", a, b)
        self.out.see(a)
        self.find_count.config(text=f"{i + 1} / {len(self.matches)}")

    def find_next(self, step=1):
        if self.matches:
            self.goto_match(self.cur_match + step)
        return "break"

    def toggle_max(self):
        if not self.maxed:
            try:
                self.tree_h = int(self.vpanes.sash_coord(0)[1])
            except Exception:
                pass
            self.vpanes.forget(self.tree_frame)
            self.upper.pack_forget()
            self.max_btn.config(text="Restore")
            self.maxed = True
        else:
            self.upper.pack(fill="x", before=self.vpanes)
            self.vpanes.add(self.tree_frame, before=self.out_frame, minsize=60, height=self.tree_h)
            self.max_btn.config(text="Maximize output")
            self.maxed = False

    def update_mode(self):
        mode = self.mode_var.get()
        texts = {
            "sn": "ONU MAC / SN (one per line)",
            "mac": "Router MAC (one per line, any format)",
            "pon": "PON number (one per line).  BDCOM: 7 or 0/7   Huawei: 0/1/7",
            "monitor": "PON number (one per line).  BDCOM: 7 or 0/7   Huawei: 0/1/7",
            "onu": "PON and ONU (one pair per line).  BDCOM: 7 48 or 0/7:48   Huawei: 0/1/7 12 or 0/1/7:12",
        }
        self.input_lbl.config(text=texts[mode])
        for fr in (self.pon_row, self.mon_row):
            fr.pack_forget()
        if mode == "pon":
            self.pon_row.pack(fill="x", after=self.sn_text)
        elif mode == "monitor":
            self.mon_row.pack(fill="x", after=self.sn_text)
        else:
            self.cancel_auto()
        if hasattr(self, "search_btn"):
            self.search_btn.config(text="Search / Refresh" if mode == "monitor" else "Search")
        if hasattr(self, "tree"):
            for c, t in (MONITOR_HEADS if mode == "monitor" else DEFAULT_HEADS):
                self.tree.heading(c, text=t)
            self.tree.column("intf", width=250 if mode == "monitor" else 150)

    def on_wheel(self, e):
        self.canvas.yview_scroll(int(-e.delta / 120), "units")

    # ----- area list
    def rebuild_list(self):
        for w in self.list_frame.winfo_children():
            w.destroy()
        q = self.filter_var.get().strip().lower()
        groups = {}
        for o in self.olts:
            if q and q not in f"{o['name']} {o.get('group', '')}".lower():
                continue
            groups.setdefault(o.get("group", ""), []).append(o)
        for g, items in groups.items():
            gv = tk.BooleanVar(value=all(self.vars[olt_key(o)].get() for o in items))
            tk.Checkbutton(self.list_frame, text=f"{g}  ({len(items)})", variable=gv, anchor="w",
                           font=("Segoe UI", 10, "bold"),
                           command=lambda items=items, gv=gv: self.toggle_group(items, gv)
                           ).pack(fill="x", anchor="w")
            for o in items:
                note = ""
                if not o.get("host"):
                    note = "   (no IP)"
                elif o.get("vendor") not in PROFILES:
                    note = f"   ({o.get('vendor')}: not supported yet)"
                tk.Checkbutton(self.list_frame, text=o["name"] + note, variable=self.vars[olt_key(o)],
                               anchor="w", command=self.update_count).pack(fill="x", anchor="w", padx=(20, 0))
        self.update_count()

    def toggle_group(self, items, gv):
        for o in items:
            self.vars[olt_key(o)].set(gv.get())
        self.update_count()

    def set_all(self, val):
        q = self.filter_var.get().strip().lower()
        for o in self.olts:
            if not q or q in f"{o['name']} {o.get('group', '')}".lower():
                self.vars[olt_key(o)].set(val)
        self.rebuild_list()

    def selected_olts(self):
        return [o for o in self.olts if self.vars[olt_key(o)].get()]

    def update_count(self):
        self.count_lbl.config(text=f"Selected: {len(self.selected_olts())} / {len(self.olts)} OLT")

    def apply_new(self, new, label):
        self.olts = merge_olts(self.olts, new)
        save_olts(self.olts)
        old = {k: v.get() for k, v in self.vars.items()}
        self.vars = {olt_key(o): tk.BooleanVar(value=old.get(olt_key(o), False)) for o in self.olts}
        self.rebuild_list()
        self.set_status(f"{label}: {len(new)} added/updated. Total {len(self.olts)}.")

    def do_import(self):
        folders = find_xshell_sessions()
        if not folders:
            messagebox.showinfo(
                "Xshell import",
                "Could not find the Xshell session folder automatically.\n\n"
                "In Xshell: File > Open Session Folder. Then give the path of the folder that opens using 'Choose folder'.")
            return
        new = import_all(folders)
        if not new:
            messagebox.showwarning("Import", "Could not find any .xsh sessions in:\n" + "\n".join(map(str, folders)))
            return
        self.apply_new(new, "Xshell import (" + ", ".join(p.parts[-3] for p in folders) + ")")

    def import_folder(self):
        d = filedialog.askdirectory(title="Select the Xshell Sessions folder")
        if not d:
            return
        new = import_xshell(d)
        if not new:
            messagebox.showwarning("Import", f"Could not find any .xsh sessions in:\n{d}")
            return
        self.apply_new(new, "Folder import")

    def load_defaults(self):
        self.apply_new(seed_olts(), "Default OLT list")

    def edit_list(self):
        save_olts(self.olts)
        messagebox.showinfo("Edit list",
                            f"The file will open. Edit it and save, then restart the app.\n\n{OLT_FILE}\n\n"
                            f"vendor: bdcom / huawei,  protocol: TELNET / SSH,  put the IP in host.")
        try:
            os.startfile(OLT_FILE)
        except Exception:
            pass

    def edit_selected(self):
        """Tick one OLT to change its IP / port / protocol / vendor inside the app."""
        sel = self.selected_olts()
        if len(sel) != 1:
            messagebox.showinfo("Edit OLT", "Tick exactly one OLT, then click 'Edit OLT'.")
            return
        o = sel[0]
        win = tk.Toplevel(self)
        win.title(f"Edit: {o['name']}")
        win.transient(self)
        win.grab_set()
        tk.Label(win, text=o["name"], font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", padx=8, pady=(8, 4))
        host_v = tk.StringVar(value=str(o.get("host", "")))
        port_v = tk.StringVar(value=str(o.get("port", "")))
        proto_v = tk.StringVar(value=str(o.get("protocol") or "TELNET").upper())
        vend_v = tk.StringVar(value=str(o.get("vendor", "bdcom")))
        tk.Label(win, text="Host / IP").grid(row=1, column=0, sticky="w", padx=8, pady=3)
        tk.Entry(win, textvariable=host_v, width=28).grid(row=1, column=1, padx=8)
        tk.Label(win, text="Port").grid(row=2, column=0, sticky="w", padx=8, pady=3)
        tk.Entry(win, textvariable=port_v, width=28).grid(row=2, column=1, padx=8)
        tk.Label(win, text="Protocol").grid(row=3, column=0, sticky="w", padx=8, pady=3)
        ttk.Combobox(win, textvariable=proto_v, values=("TELNET", "SSH"), state="readonly",
                     width=26).grid(row=3, column=1, padx=8)
        tk.Label(win, text="Vendor").grid(row=4, column=0, sticky="w", padx=8, pady=3)
        ttk.Combobox(win, textvariable=vend_v, values=("bdcom", "huawei", "vsol", "epon", "other"),
                     state="readonly", width=26).grid(row=4, column=1, padx=8)

        def save():
            port = port_v.get().strip()
            if not port.isdigit():
                messagebox.showwarning("Port", "Enter only a number for the port (for example 22 or 23).", parent=win)
                return
            o.update({"host": host_v.get().strip(), "port": int(port),
                      "protocol": proto_v.get(), "vendor": vend_v.get()})
            save_olts(self.olts)
            self.rebuild_list()
            self.set_status(f"{o['name']}: {o['host']}:{o['port']} ({o['protocol']}) saved.")
            win.destroy()

        tk.Button(win, text="Save", width=10, command=save).grid(row=5, column=1, sticky="e", padx=8, pady=8)

    # ----- password
    def set_password(self):
        user = self.user_var.get().strip() or DEFAULT_USER
        pw = simpledialog.askstring("Password", f"Password for '{user}':", show="*", parent=self)
        if not pw:
            return False
        self.pw = pw
        if keyring and messagebox.askyesno("Save?", "Save in Windows Credential Manager? (so you do not need to enter it next time)"):
            try:
                keyring.set_password(KEYRING_SERVICE, user, pw)
            except Exception:
                pass
        return True

    def get_password(self):
        if self.pw:
            return self.pw
        user = self.user_var.get().strip() or DEFAULT_USER
        if keyring:
            try:
                saved = keyring.get_password(KEYRING_SERVICE, user)
                if saved:
                    self.pw = saved
                    return saved
            except Exception:
                pass
        return self.pw if self.set_password() else None

    # ----- search
    def set_status(self, text):
        self.status.config(text=text)

    def post(self, fn, *args):
        self.q.put((fn, args))

    def poll(self):
        try:
            while True:
                fn, args = self.q.get_nowait()
                fn(*args)
        except queue.Empty:
            pass
        self.after(100, self.poll)

    def start_search(self):
        if self.busy:
            return
        olts = self.selected_olts()
        if not olts:
            messagebox.showinfo("Area", "Select at least one area/OLT.")
            return
        mode = self.mode_var.get()
        pon_like = mode in ("pon", "monitor")
        keys = []
        for line in self.sn_text.get("1.0", "end").splitlines():
            line = olt_clean(line)
            if not line:
                continue
            if mode == "sn" and not SN_RE.match(line):
                messagebox.showwarning("ONU SN", f"This SN is not valid: {line!r}\n(only letters/numbers and : - _ . are allowed)")
                return
            if pon_like and not re.fullmatch(r"(?i)(?:gpon\s*)?\d+(?:\s*/\s*\d+){0,2}", line):
                messagebox.showwarning("PON", f"This PON is not valid: {line!r}\n(for example 7, 0/7, or 0/1/7 for Huawei)")
                return
            if mode == "onu" and not re.fullmatch(
                    r"(?i)(?:gpon\s*)?\d+(?:\s*/\s*\d+){0,2}\s*(?:onu|ont)?\s*[\s:,]\s*\d+", line):
                messagebox.showwarning("PON + ONU", f"This is not valid: {line!r}\n"
                                       "(BDCOM: 7 48 or 0/7:48     Huawei: 0/1/7 12 or 0/1/7:12)")
                return
            if mode == "mac" and len(hex12(line)) != 12:
                messagebox.showwarning("Router MAC", f"This MAC is not valid: {line!r}\n(it needs 12 hex digits)")
                return
            if line not in keys:
                keys.append(line)
        pon_title = self.pon_cmd_var.get()
        olt_level = mode == "pon" and any(c["title"] == pon_title and c["scope"] == "olt"
                                          for pr in PROFILES.values() for c in pr["commands"])
        if not keys and not olt_level:
            messagebox.showinfo("Input", "Enter a PON number." if pon_like else
                                "Enter a PON and an ONU number." if mode == "onu" else "Enter an ONU SN / MAC.")
            return
        pw = self.get_password()
        if not pw:
            return
        user = self.user_var.get().strip() or DEFAULT_USER
        self.settings.update({"user": user, "selected": [olt_key(o) for o in olts]})
        save_settings(self.settings)

        if mode == "monitor":
            self.last_monitor = (olts, keys, user)
            self.run_monitor(*self.last_monitor)
            return

        self.busy = True
        self.search_btn.config(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.details.clear()
        self.hit_by_item.clear()
        self.mon_detail.clear()
        self.refresh_actions(None)
        self.out.delete("1.0", "end")
        self.refresh_find()
        self.set_status(f"Searching on {len(olts)} OLT(s)...")

        def worker():
            try:
                if mode == "pon":
                    pstate = run_pon_status(olts, keys, pon_title, user, pw, lambda s: self.post(self.set_status, s))
                    self.post(self.show_pon_results, pstate, len(olts))
                    return
                if mode == "onu":
                    mstate = run_manual_onu(olts, keys, user, pw, lambda s: self.post(self.set_status, s))
                    self.post(self.show_manual_results, mstate, len(olts))
                    return
                state = run_search(olts, keys, user, pw, lambda s: self.post(self.set_status, s), mode)
                self.post(self.show_results, state, keys, len(olts))
            except Exception as e:
                self.post(self.search_failed, err_text(e))

        threading.Thread(target=worker, daemon=True).start()

    def search_failed(self, msg):
        self.busy = False
        self.search_btn.config(state="normal")
        self.set_status(f"Error: {msg}")

    def show_results(self, state, keys, n_olts):
        self.busy = False
        self.search_btn.config(state="normal")
        summary = [f"{n_olts} OLT(s) were selected; searched {len(state.searched)} of them successfully."]
        if state.skipped:
            summary += ["", "Skipped:"] + [f"  - {k}: {v}" for k, v in state.skipped.items()]
        if state.errors:
            summary += ["", "Errors:"] + [f"  - {k}: {v}" for k, v in state.errors.items()]
        summary_text = "\n".join(summary)

        for h in state.hits:
            item = self.tree.insert("", "end", values=(
                h["sn_input"], h["olt"], f"PON {h['pon']} : ONU {h['onu']}", h["model"],
                "Found" + (f" ({h['status']})" if h.get("status") else "")))
            self.details[item] = hit_text(h)
            self.hit_by_item[item] = h
        for key in state.remaining():
            item = self.tree.insert("", "end", values=(key, "-", "-", "-", "Not found"))
            self.details[item] = f"'{key}' was not found on any of the selected OLTs.\n\n{summary_text}"
        self.out.delete("1.0", "end")
        self.out.insert("end", summary_text)
        self.refresh_find()
        self.set_status(f"Done. Found: {len(state.hits)} / {len(keys)}")
        kids = self.tree.get_children()
        if kids:
            self.tree.selection_set(kids[0])

    def show_pon_results(self, st, n_olts):
        self.busy = False
        self.search_btn.config(state="normal")
        summary = [f"{n_olts} OLT(s) were selected; logged in to {len(st['done'])} of them."]
        if st["skipped"]:
            summary += ["", "Skipped:"] + [f"  - {k}: {v}" for k, v in st["skipped"].items()]
        if st["errors"]:
            summary += ["", "Errors:"] + [f"  - {k}: {v}" for k, v in st["errors"].items()]
        summary_text = "\n".join(summary)
        for h in st["rows"]:
            failed = any(o.startswith("(error:") for _, _, o in h["details"])
            item = self.tree.insert("", "end", values=(
                h["sn_input"], h["olt"], h["pon"] and f"PON {h['pon']}" or "-", "", "Error" if failed else "OK"))
            self.details[item] = hit_text(h)
            self.hit_by_item[item] = h
        self.out.delete("1.0", "end")
        self.out.insert("end", summary_text)
        self.refresh_find()
        self.set_status(f"Done. {len(st['rows'])} result(s).")
        kids = self.tree.get_children()
        if kids:
            self.tree.selection_set(kids[0])

    def show_manual_results(self, st, n_olts):
        self.busy = False
        self.search_btn.config(state="normal")
        summary = [f"{n_olts} OLT(s) were selected; logged in to {len(st['done'])} of them."]
        if st["skipped"]:
            summary += ["", "Skipped:"] + [f"  - {k}: {v}" for k, v in st["skipped"].items()]
        if st["errors"]:
            summary += ["", "Errors:"] + [f"  - {k}: {v}" for k, v in st["errors"].items()]
        summary_text = "\n".join(summary)
        hits = sorted(st["hits"], key=lambda h: (h["olt"], natural_key(f"{h['frame']}/{h['slot']}/{h['pon']}"),
                                                int(h["onu"])))
        for h in hits:
            item = self.tree.insert("", "end", values=(
                h["sn_input"], h["olt"], f"PON {h['pon']} : ONU {h['onu']}", h["model"],
                h["status"] or "Details"))
            self.details[item] = hit_text(h)
            self.hit_by_item[item] = h
        self.out.delete("1.0", "end")
        self.out.insert("end", summary_text)
        self.refresh_find()
        self.set_status(f"Done. {len(hits)} ONU(s) shown.")
        kids = self.tree.get_children()
        if kids:
            self.tree.selection_set(kids[0])

    # ----- PON monitor
    def run_monitor(self, olts, pons, user):
        if self.busy:
            return
        self.busy = True
        self.search_btn.config(state="disabled")
        self.set_status(f"Running PON monitor on {len(olts)} OLT(s)...")
        pw = self.pw
        check_dg = self.dg_var.get()

        def worker():
            try:
                st = run_pon_monitor(olts, pons, user, pw, lambda s: self.post(self.set_status, s),
                                     check_dg=check_dg)
                self.post(self.show_monitor_results, st, len(olts))
            except Exception as e:
                self.post(self.search_failed, err_text(e))

        threading.Thread(target=worker, daemon=True).start()

    def show_monitor_results(self, st, n_olts):
        self.busy = False
        self.search_btn.config(state="normal")
        now = datetime.now()
        stamp = now.strftime("%H:%M:%S")
        before = self.tree.selection()
        self.tree.delete(*self.tree.get_children())
        self.details.clear()
        self.hit_by_item.clear()
        self.mon_detail.clear()
        self.refresh_actions(None)

        tot_new = tot_back = 0
        rows = sorted(st["rows"], key=lambda r: (r["olt"], natural_key(r.get("pon_label", r["pon_in"]))))
        for r in rows:
            iid = f"{r['olt_key']}|{r['pon_in']}"
            label = r.get("pon_label", r["pon_in"])
            if r["error"] or not r["cats"]:
                item = self.tree.insert("", "end", iid=iid, tags=("err",),
                                        values=(label, r["olt"], "-", "-", "Error"))
                self.mon_detail[item] = [(r["error"] or "(no data)", "err")]
                continue
            cats = r["cats"]
            prev = self.snap.get(iid)
            new_keys, back_keys = monitor_diff(cats, prev["cats"] if prev else None)

            when = f"updated {stamp}, " + (f"previous {prev['time']:%H:%M:%S}" if prev else "baseline (first run)")
            detail = [(f"{r['olt']}    PON {label}    ({when})", "head"), ("", "")]
            for cat, title in (("LOSi", "LOSi / LOS / LOBi"), ("Offline", "Offline (all, including LOSi/DG)"),
                               ("Dying", "Dying Gasp"), ("Online", "Online")):
                if cat == "Online" and not cats["has_online"]:
                    detail.append(("=== Online: the BDCOM inactive list does not show online ONUs ===", "head"))
                    detail.append(("", ""))
                    continue
                items = cats[cat]
                detail.append((f"=== {title} ({len(items)}) ===", "head"))
                if not items:
                    if cat == "Dying" and not cats.get("dg_checked"):
                        detail.append(("  (no ONUs. The summary does not include causes; tick 'Dying Gasp check' "
                                       "to see the cause of the Offline ONUs)", "ok"))
                    else:
                        detail.append(("  (no ONUs)", "ok"))
                for key in sorted(items, key=natural_key):
                    is_new = bool(prev) and cat != "Online" and key not in prev["cats"].get(cat, {})
                    cause = cats.get("causes", {}).get(key)
                    txt = items[key].strip() + (f"    <- cause: {cause}" if cause else "")
                    detail.append((("[NEW] " if is_new else "      ") + txt,
                                   "new" if is_new else ""))
                detail.append(("", ""))
            if back_keys:
                detail.append((f"=== BACK / recovered, no longer in the list ({len(back_keys)}) ===", "head"))
                for key in sorted(back_keys, key=natural_key):
                    detail.append(("[BACK] " + prev["cats"]["Inactive"][key].strip(), "back"))
                detail.append(("", ""))
            detail.append(("=== Raw device data ===", "head"))
            detail.append((r.get("raw") or "(nothing)", ""))

            online_txt = str(len(cats["Online"])) if cats["has_online"] else "-"
            counts = (f"LOSi {len(cats['LOSi'])} | Offline {len(cats['Offline'])} "
                      f"| DG {len(cats['Dying'])} | Online {online_txt}")
            change = f"+{len(new_keys)} / -{len(back_keys)}" if prev else "baseline"
            tags = ("changed",) if (new_keys or back_keys) else ()
            item = self.tree.insert("", "end", iid=iid, tags=tags,
                                    values=(label, r["olt"], counts, change, stamp))
            self.mon_detail[item] = detail
            self.snap[iid] = {"cats": cats, "time": now}
            tot_new += len(new_keys)
            tot_back += len(back_keys)

        summary = [f"{n_olts} OLT(s) were selected; logged in to {len(st['done'])} of them."]
        if st["skipped"]:
            summary += ["", "Skipped:"] + [f"  - {k}: {v}" for k, v in st["skipped"].items()]
        if st["errors"]:
            summary += ["", "Errors:"] + [f"  - {k}: {v}" for k, v in st["errors"].items()]
        kids = self.tree.get_children()
        if kids:
            pick = next((i for i in before if i in kids), kids[0])
            self.tree.selection_set(pick)
        else:
            self.out.delete("1.0", "end")
            self.out.insert("end", "\n".join(summary))
            self.refresh_find()

        note = ""
        if st["errors"] and not st["rows"]:
            self.auto_var.set(False)            # login failed on every OLT -> stop retrying so accounts do not get locked
            note = "  (login failed, auto refresh turned off)"
        elif any("login failed" in v for v in st["errors"].values()):
            self.auto_var.set(False)
            note = "  (wrong password, auto refresh turned off)"
        self.set_status(f"Refresh {stamp}: {len(rows)} PON(s).  New inactive +{tot_new},  recovered -{tot_back}"
                        f"  |  errors {len(st['errors'])}, skipped {len(st['skipped'])}{note}")
        self.schedule_auto()

    def reset_baseline(self):
        self.snap.clear()
        self.set_status("Baseline reset. The next refresh will become the new baseline.")

    def cancel_auto(self):
        if self.auto_job:
            try:
                self.after_cancel(self.auto_job)
            except Exception:
                pass
            self.auto_job = None

    def schedule_auto(self):
        self.cancel_auto()
        if self.mode_var.get() == "monitor" and self.auto_var.get() and self.last_monitor:
            try:
                sec = max(MIN_AUTO_SEC, int(self.auto_sec.get()))
            except ValueError:
                sec = 30
            self.auto_job = self.after(sec * 1000, self.auto_tick)

    def auto_tick(self):
        self.auto_job = None
        if not (self.auto_var.get() and self.mode_var.get() == "monitor" and self.last_monitor):
            return
        if self.busy:
            self.schedule_auto()
            return
        self.run_monitor(*self.last_monitor)

    # ----- per-ONU action buttons (depend on the vendor)
    def refresh_actions(self, h):
        for b in self.act_btns:
            b.destroy()
        self.act_btns = []
        if not h:
            return
        for c in PROFILES[h["vendor"]]["commands"]:
            if c.get("auto"):
                continue
            if h.get("pon_only") and c["scope"] == "onu":
                continue
            b = tk.Button(self.act_frame, text=c["title"], state="disabled" if self.busy else "normal",
                          fg="#b91c1c" if c.get("danger") else "black",
                          command=lambda c=c: self.run_action(c))
            b.pack(side="left", padx=2, pady=2)
            self.act_btns.append(b)

    def set_actions(self, enabled):
        for b in self.act_btns:
            b.config(state="normal" if enabled else "disabled")

    def on_select(self, _):
        sel = self.tree.selection()
        if not sel:
            return
        self.out.delete("1.0", "end")
        if sel[0] in self.mon_detail:
            for text, tag in self.mon_detail[sel[0]]:
                self.out.insert("end", text + "\n", (tag,) if tag else ())
            self.refresh_actions(None)
            self.refresh_find()
            return
        self.out.insert("end", self.details.get(sel[0], ""))
        self.refresh_actions(self.hit_by_item.get(sel[0]))
        self.refresh_find()

    def run_action(self, c):
        sel = self.tree.selection()
        h = self.hit_by_item.get(sel[0]) if sel else None
        if not h or self.busy:
            messagebox.showinfo("ONU", "First select a 'Found' ONU row.")
            return
        if c.get("danger"):
            ok = messagebox.askyesno(
                c["title"],
                f"Do you want to run {c['title']}?\n\nInput : {h['sn_input']}\nOLT   : {h['olt']}\n"
                f"Port  : {hit_iface(h)}\n\nThe customer's internet will be down for a while.",
                icon="warning", default="no")
            if not ok:
                return
        pw = self.get_password()
        if not pw:
            return
        user = self.user_var.get().strip() or DEFAULT_USER
        item = sel[0]
        self.busy = True
        self.set_actions(False)
        self.set_status(f"Running {c['title']} ({h['olt']})...")

        def worker():
            try:
                cmd, out = run_for_hit(h, c, user, pw)
            except Exception as e:
                cmd, out = fill(c, h), f"(error: {err_text(e)})"
            self.post(self.action_done, item, h, c, cmd, out)

        threading.Thread(target=worker, daemon=True).start()

    def action_done(self, item, h, c, cmd, out):
        self.busy = False
        h["details"].append((c["title"], cmd, out))
        self.details[item] = hit_text(h)
        self.set_status(f"{c['title']} finished.")
        self.set_actions(True)
        if self.tree.selection() and self.tree.selection()[0] == item:
            self.out.delete("1.0", "end")
            self.out.insert("end", self.details[item])
            self.refresh_find()
            self.out.see("end")

    def copy_result(self):
        text = self.out.get("1.0", "end").strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.set_status("Copied.")


# ======================================================================================
# PART 2.  Today Losi + AI Analyze + fixes (uses the base app above)
# ======================================================================================
import os
import re
import sys
import json
import time
import threading
import urllib.request
import urllib.error
from datetime import datetime, date
from concurrent.futures import ThreadPoolExecutor

F = sys.modules[__name__]        # the base app is in this same file

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog
except ImportError:            # headless / tests
    tk = None

_NEED = ("App", "PROFILES", "Shell", "open_session", "run_ctl", "run_show", "olt_key", "err_text",
         "keyring", "KEYRING_SERVICE", "load_settings", "save_settings", "paramiko",
         "MAX_WORKERS", "DEFAULT_USER")
_missing = [n for n in _NEED if not hasattr(F, n)]
if _missing:
    raise SystemExit("olt_finder.py is missing: " + ", ".join(_missing) +
                     "\nPut your latest olt_finder.py in the same folder as olt_app.py.")

WATCH_PONS = range(0, 26)               # PON 0 to 25
REFRESH_MS = 15 * 60 * 1000             # 15 minutes
POWER_MIN, POWER_MAX = -24.0, -12.0     # Rx power must be between these (dBm)
GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"
GEMINI_KEY_NAME = "gemini_api_key"

LOSI_RE = re.compile(r"\b(?:losi?|lobi)\b", re.I)
DYING_RE = re.compile(r"dying[\s_-]*gasp", re.I)
HW_DT = r"(?:\d{2}-\d{2}-\d{4}|\d{4}-\d{2}-\d{2})\s+\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2})?"
# Huawei 'display ont info summary' 2nd table:  ONT-ID  state  last up time  last down time  last down cause
HW_STATE_ROW = re.compile(r"^\s*(?P<id>\d{1,3})\s+(?P<state>online|offline)\s+(?P<up>" + HW_DT +
                          r"|-)\s+(?P<down>" + HW_DT + r"|-)\s*(?P<cause>.*?)\s*$", re.I)
HW_SN_ROW = re.compile(r"^\s*(?P<id>\d{1,3})\s+(?P<sn>[0-9A-Fa-f]{8,16})\s+\S+")
# BDCOM 'show gpon inactive-onu interface gpon 0/4' row
BD_ROW = re.compile(r"GPON(?P<slot>\d+)/(?P<pon>\d+):(?P<onu>\d+)\s+(?P<sn>\S+)\s+(?P<loid>\S+)\s+"
                    r"(?P<state>\S+)\s+(?P<dt>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s*(?P<cause>.*?)\s*$", re.I)


# ======================================================================================
# Part A.  Fixes for olt_finder.py (applied when this file starts)
# ======================================================================================
def parse_dt(text):
    t = re.sub(r"[+-]\d{2}:\d{2}$", "", str(text).strip())
    for fmt in ("%d-%m-%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(t, fmt)
        except ValueError:
            pass
    return None


def parse_bdcom_inactive(text):
    out = []
    for line in str(text).splitlines():
        m = BD_ROW.search(line)
        if not m:
            continue
        out.append({"key": f"{m['slot']}/{m['pon']}:{m['onu']}", "pon_label": f"{m['slot']}/{m['pon']}",
                    "onu": m["onu"], "sn": m["sn"], "state": "offline", "down": parse_dt(m["dt"]),
                    "cause": m["cause"].strip(), "line": line.rstrip()})
    return out


def parse_huawei_summary(text, label):
    """Reads only the second table (the one that says online / offline)."""
    lines = str(text).splitlines()
    sn_map = {}
    for line in lines:
        m = HW_SN_ROW.match(line)
        if m:
            sn_map[m["id"]] = m["sn"]
    out = []
    for line in lines:
        m = HW_STATE_ROW.match(line)
        if not m:
            continue
        cause = m["cause"].strip()
        if cause in ("-", "--"):
            cause = ""
        out.append({"key": f"{label}:{m['id']}", "pon_label": label, "onu": m["id"],
                    "sn": sn_map.get(m["id"], ""), "state": m["state"].lower(),
                    "down": parse_dt(m["down"]), "cause": cause, "line": line.rstrip()})
    return out


def is_dying(e):
    return bool(DYING_RE.search(e["cause"]) or DYING_RE.search(e["line"]))


def is_counted(e, today):
    """Down now, went down today, and not Dying Gasp."""
    return (e["state"] == "offline" and e["down"] is not None
            and e["down"].date() == today and not is_dying(e))


def classify_huawei(text, label):
    """Same result shape as olt_finder.classify_pon, but correct for Huawei."""
    inactive, losi, online, dying = {}, {}, {}, {}
    for e in parse_huawei_summary(text, label):
        if e["state"] == "online":
            online[e["key"]] = e["line"]
            continue
        inactive[e["key"]] = e["line"]
        if LOSI_RE.search(e["cause"]):
            losi[e["key"]] = e["line"]
        elif is_dying(e):
            dying[e["key"]] = e["line"]
    return {"LOSi": losi, "Offline": dict(inactive), "Dying": dying, "Online": online,
            "Inactive": inactive, "has_online": True, "causes": {}, "dg_checked": True}


_JUNK = re.compile(r"^\s*\{\s*<cr>[^}]*\}\s*:\s*$")
_PROMPT_LINE = re.compile(r"^[\w\-.()/]+[#>]\s*$")


def install_patches():
    # 1. cleaner output
    orig_run = F.Shell.run
    if not getattr(orig_run, "_cleaned", False):
        def run(self, cmd, *a, **k):
            out = orig_run(self, cmd, *a, **k)
            lines = [l for l in out.split("\n") if not _JUNK.match(l)]
            while lines and (not lines[-1].strip() or _PROMPT_LINE.match(lines[-1].strip())):
                lines.pop()
            return "\n".join(lines).strip()
        run._cleaned = True
        F.Shell.run = run

    # 2. Huawei online / offline count
    orig_classify = getattr(F, "classify_pon", None)
    if orig_classify is not None and not getattr(orig_classify, "_fixed", False):
        def classify(vendor, text, pon_label):
            if vendor == "huawei":
                return classify_huawei(text, pon_label)
            return orig_classify(vendor, text, pon_label)
        classify._fixed = True
        F.classify_pon = classify

    hw = F.PROFILES.get("huawei")
    if hw:
        # 3. Huawei Port Check runs by itself
        for c in hw["commands"]:
            if c["title"] == "Port Check":
                c["auto"] = True
        # 4. warn when a short SN matches more than one ONU
        orig_parse = hw["parse_sn"]
        if not getattr(orig_parse, "_multi", False):
            def parse(out):
                d = orig_parse(out)
                if d:
                    n = len(re.findall(r"F/S/P\s*:", out))
                    if n > 1:
                        d["status"] = f"{d.get('status') or 'found'} - {n} matches, using the first"
                return d
            parse._multi = True
            hw["parse_sn"] = parse


# ======================================================================================
# Part B.  Today Losi: collect, count, box state
# ======================================================================================
def eligible_olts(olts):
    out = []
    for o in olts:
        if not o.get("host") or o.get("vendor") not in ("bdcom", "huawei"):
            continue
        proto = str(o.get("protocol") or "TELNET").upper()
        if proto == "SSH" and F.paramiko is None:
            continue
        if proto not in ("TELNET", "SSH"):
            continue
        out.append(o)
    return out


def scan_olt(olt, user, pw, pons=WATCH_PONS):
    """Logs in once, reads the inactive ONU list of every PON. Returns a result dict."""
    vendor = olt.get("vendor", "bdcom")
    res = {"name": olt["name"], "key": F.olt_key(olt), "vendor": vendor, "entries": [],
           "error": "", "pon_errors": 0}
    cmd_t = next((c["cmd"] for c in F.PROFILES[vendor]["commands"] if c["title"] == "PON Inactive ONU"), None)
    if not cmd_t:
        res["error"] = "no 'PON Inactive ONU' command for this vendor"
        return res
    sh, entered, fails = None, False, 0
    try:
        sh, _prof = F.open_session(olt, user, pw)
        if vendor == "huawei":
            F.run_ctl(sh, olt, "interface gpon 0/1")      # frame 0, slot 1 always
            entered = True
        for pon in pons:
            cmd = cmd_t.format(frame="0", slot="1" if vendor == "huawei" else "0", pon=pon, onu="")
            try:
                text = F.run_show(sh, olt, cmd)
                fails = 0
            except Exception:
                res["pon_errors"] += 1
                fails += 1
                if fails >= 3:                              # the connection is probably dead
                    break
                continue
            if vendor == "huawei":
                found = parse_huawei_summary(text, f"0/1/{pon}")
            else:
                found = parse_bdcom_inactive(text)
            if vendor == "huawei":
                seen = len(re.findall(r"(?im)^\s*\d{1,3}\s+(?:online|offline)\b", text))
            else:
                seen = sum(1 for ln in text.splitlines() if re.search(r"GPON\d+/\d+:\d+", ln, re.I))
            if seen > len(found):                       # some rows were not understood by the parser
                res["pon_errors"] += 1
            for e in found:
                e["pon"] = pon
            res["entries"].extend(found)
        if entered:
            try:
                F.run_ctl(sh, olt, "quit")
            except Exception:
                pass
    except Exception as e:
        res["error"] = F.err_text(e)
    finally:
        if sh:
            sh.close()
    return res


def run_round(olts, user, pw, status=lambda s: None, today=None):
    """Checks all OLTs (a few at a time). Returns the counted result."""
    t0 = time.time()
    today = today or date.today()
    results, done = [], [0]
    lock = threading.Lock()

    stop = threading.Event()                    # set when a login fails, so other OLTs are not tried

    def work(o):
        if stop.is_set():
            r = {"name": o["name"], "key": F.olt_key(o), "vendor": o.get("vendor", ""), "entries": [],
                 "error": "skipped (login failed on another OLT)", "pon_errors": 0}
        else:
            r = scan_olt(o, user, pw)
            if "login failed" in r["error"]:
                stop.set()
        with lock:
            done[0] += 1
            status(f"Checking OLTs... {done[0]} of {len(olts)}")
        return r

    with ThreadPoolExecutor(max_workers=F.MAX_WORKERS) as ex:
        results = list(ex.map(work, olts))

    return summarize(results, today, time.time() - t0, len(olts))


def summarize(results, today, seconds, n_olts, when=None):
    """Counts the scan results for one date. The raw results are kept, so the date can be
    changed later without logging in to the OLTs again."""
    out_olts, total, dg, checked, partial, failed = [], 0, 0, 0, 0, []
    for r in results:
        if r["error"]:
            failed.append((r["name"], r["error"]))
            out_olts.append({"name": r["name"], "count": 0, "pons": {}, "error": r["error"]})
            continue
        checked += 1
        if r["pon_errors"]:
            partial += 1
        pons = {}
        for e in r["entries"]:
            if is_counted(e, today):
                pons.setdefault(e["pon_label"], []).append(e)
            elif e["state"] == "offline" and e["down"] and e["down"].date() == today and is_dying(e):
                dg += 1
        n = sum(len(v) for v in pons.values())
        total += n
        out_olts.append({"name": r["name"], "count": n, "pons": pons, "error": "",
                         "partial": bool(r["pon_errors"])})
    wrong_pw = any("login failed" in err for _, err in failed)
    return {"today": today, "time": when or datetime.now(), "seconds": seconds, "total": total,
            "dg": dg, "checked": checked, "partial": partial, "failed": failed, "olts": out_olts,
            "wrong_pw": wrong_pw, "n_olts": n_olts, "raw": results}


def parse_user_date(text):
    """dd/mm/yyyy, dd-mm-yyyy, dd.mm.yyyy or yyyy-mm-dd -> date, or None."""
    t = str(text).strip()
    for fmt in ("%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%Y-%m-%d", "%Y/%m/%d"):
        try:
            return datetime.strptime(t, fmt).date()
        except ValueError:
            pass
    return None


def box_state(res):
    """-> (color, main text, small text). Green only means: I checked and found zero."""
    if res is None:
        return "grey", "Today Losi : -", "Not updated yet"
    if res["wrong_pw"]:
        return "grey", "Today Losi : -", "Wrong password. Auto update stopped."
    stamp = res["time"].strftime("%H:%M")
    if res["today"] != date.today():
        stamp = "still down now. Updated " + stamp
    bad = len(res["failed"]) + res["partial"]
    if res["checked"] == 0:
        return "grey", "Today Losi : -", f"No OLT could be checked ({len(res['failed'])} failed)"
    if res["total"] > 0:
        return "red", f"Today Losi : {res['total']}", f"{stamp[0].upper() + stamp[1:] if stamp.startswith('still') else 'Updated ' + stamp}" + (f" | {bad} OLT problem" if bad else "")
    if bad:
        return "grey", "Today Losi : 0", f"Not sure: {bad} OLT problem. {stamp if stamp.startswith('still') else 'Updated ' + stamp}"
    return "green", "Today Losi : 0", (stamp[0].upper() + stamp[1:] if stamp.startswith("still") else f"Updated {stamp}")


def fmt_secs(sec):
    sec = int(sec)
    return f"{sec // 60}m {sec % 60}s" if sec >= 60 else f"{sec}s"


# ======================================================================================
# Part C.  AI Analyze: facts, rules, Gemini
# ======================================================================================
_SECRET_RE = re.compile(r"(?i)\b(password|passwd|secret|psk)\b(\s*[=:]\s*)(\"[^\"]*\"|\S+)")


def _clip(text, n):
    text = _SECRET_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}[removed]", str(text or "")).strip()
    return text if len(text) <= n else text[:n] + "\n...(cut)"


def find_detail(hit, *titles):
    for title, _cmd, out in hit.get("details", []):
        if title in titles:
            return out
    return ""


def parse_power(vendor, text):
    """Returns Rx power in dBm (float) or None."""
    text = str(text or "")
    if vendor == "huawei":
        m = re.search(r"Rx optical power\(dBm\)\s*:\s*(-?\d+(?:\.\d+)?)", text, re.I)
        return float(m.group(1)) if m else None
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if re.search(r"rx\s*power", line, re.I):
            cols = line.split()
            idx = next((j for j, c in enumerate(cols) if re.search(r"rxpower", c, re.I)), None)
            for row in lines[i + 1:]:
                if re.match(r"\s*gpon", row, re.I):
                    vals = row.split()
                    if idx is not None and idx < len(vals):
                        try:
                            return float(vals[idx])
                        except ValueError:
                            return None
                    break
    return None


def parse_port(vendor, text):
    """Returns a list of ports: {port, link, speed, duplex}."""
    text = str(text or "")
    ports = []
    if vendor == "huawei":
        for line in text.splitlines():
            m = re.match(r"^\s*\d+\s+(\d+)\s+(\S+)\s+(\d+|-)\s+(full|half|-)\s+(up|down)\b", line, re.I)
            if m:
                ports.append({"port": m.group(1), "link": m.group(5).lower(),
                              "speed": m.group(3), "duplex": m.group(4).lower()})
        return ports
    m = re.search(r"uni-port\s+(\d+)\s+(up|down)", text, re.I)
    if m:
        sp = re.search(r"(\d+)\s*Mbps\s*(Full|Half)", text, re.I)
        ports.append({"port": m.group(1), "link": m.group(2).lower(),
                      "speed": sp.group(1) if sp else "", "duplex": sp.group(2).lower() if sp else ""})
    return ports


def parse_macs(text):
    """BDCOM: xxxx.xxxx.xxxx   Huawei: xxxx-xxxx-xxxx   (also xx:xx:xx:xx:xx:xx)"""
    t = str(text or "")
    return (re.findall(r"\b[0-9a-f]{4}[.\-][0-9a-f]{4}[.\-][0-9a-f]{4}\b", t, re.I)
            + re.findall(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", t, re.I))


def check_power(v):
    if v is None:
        return {"status": "unknown", "text": "Rx power: not found in the output."}
    if v < POWER_MIN:
        return {"status": "bad", "text": f"Rx power {v} dBm is too weak (it must be -12 to -24)."}
    if v > POWER_MAX:
        return {"status": "bad", "text": f"Rx power {v} dBm is too strong (it must be -12 to -24)."}
    return {"status": "ok", "text": f"Rx power {v} dBm is OK (-12 to -24)."}


def check_port(vendor, ports):
    if not ports:
        return {"status": "unknown", "text": "Port state: not found in the output.", "warn": []}
    warn = []
    for p in ports:
        if p["speed"].isdigit() and int(p["speed"]) < 100:
            warn.append(f"Port {p['port']} speed is only {p['speed']} Mbps. Check the cable.")
        if p["duplex"] == "half":
            warn.append(f"Port {p['port']} is half duplex. Check the cable.")
    if vendor == "huawei":
        ups = [p for p in ports if p["link"] == "up"]
        if ups:
            p = ups[0]
            return {"status": "ok", "warn": warn,
                    "text": f"Port {p['port']} is up ({p['speed']} Mbps, {p['duplex']})."}
        return {"status": "bad", "warn": warn, "text": "All ports are down."}
    p = next((x for x in ports if x["port"] == "1"), ports[0])
    if p["link"] == "up":
        return {"status": "ok", "warn": warn, "text": f"Port {p['port']} is up ({p['speed']} Mbps, {p['duplex']})."}
    return {"status": "bad", "warn": warn, "text": f"Port {p['port']} is down."}


def gather_facts(hit):
    v = hit["vendor"]
    power = parse_power(v, find_detail(hit, "ONU Power"))
    ports = parse_port(v, find_detail(hit, "Check Port", "Port Check"))
    mac_out = find_detail(hit, "MAC Address")
    if v == "bdcom":
        macs = parse_macs(mac_out)
    else:                                   # Huawei: if the command failed or gave nothing, it was not collected
        macs = None if looks_bad(mac_out) else parse_macs(mac_out)
    iface = F.hit_iface(hit) if hasattr(F, "hit_iface") else ""
    return {"vendor": v, "olt": hit["olt"], "iface": iface,
            "sn": hit.get("sn_device") or hit.get("sn_input", ""), "status": hit.get("status", ""),
            "model": hit.get("model", ""), "power": power, "power_check": check_power(power),
            "ports": ports, "port_check": check_port(v, ports), "macs": macs,
            "info": _clip(find_detail(hit, "ONU Info"), 1200),
            "register": _clip(find_detail(hit, "10 time basic-info"), 1200)}


def rule_lines(f):
    """[(tag, text)] tag: ok / bad / warn / info"""
    out = [(f["power_check"]["status"], f["power_check"]["text"]),
           (f["port_check"]["status"], f["port_check"]["text"])]
    out += [("warn", w) for w in f["port_check"].get("warn", [])]
    if f["macs"] is None:
        out.append(("info", "MAC table: not collected (the command gave no data)."))
    elif f["macs"]:
        out.append(("info", f"MAC table: {len(f['macs'])} MAC learned on this ONU."))
    else:
        out.append(("warn", "MAC table: no MAC learned on this ONU."))
    if f["status"]:
        out.append(("info", f"ONU status: {f['status']}"))
    return out


PROMPT_HEAD = """You help a support agent of an internet service provider.
Use very simple English. Do not invent data. If something is missing, say what is missing.
You can only suggest. You cannot run commands or reboot anything.

Company rules:
- ONU Rx power must be between -12 and -24 dBm.
- The ONU port must be up.
- MikroTik PPP: 0% packet loss means OK. Any other packet loss means NOT OK.
- MikroTik bandwidth: if the text says "using", it is OK.
"""

PROMPT_TAIL = """
Answer in this exact format (max 10 short lines):
Result: OK or PROBLEM
Likely problem: one short sentence
What to do next: 2 to 5 short steps, in order (cheapest check first)
Missing data: list, or "none"
"""


def build_prompt(f, erp, bandwidth, ppp):
    lines = [PROMPT_HEAD, "Data collected from the OLT:",
             f"- OLT: {f['olt']} ({f['vendor']})", f"- ONU: {f['iface']}  SN: {f['sn']}  Model: {f['model']}",
             f"- ONU status: {f['status'] or 'unknown'}"]
    lines += [f"- Rule check: {t}" for _tag, t in rule_lines(f)]
    if f["info"]:
        lines += ["", "ONU info (OLT output):", f["info"]]
    if f["register"]:
        lines += ["", "Register info (OLT output):", f["register"]]
    lines += ["", "Text from the agent:",
              f"ERP login status: {_clip(erp, 1500) or '(not given)'}",
              f"MikroTik bandwidth: {_clip(bandwidth, 1500) or '(not given)'}",
              f"MikroTik PPP: {_clip(ppp, 1500) or '(not given)'}", PROMPT_TAIL]
    return "\n".join(lines)


class GeminiError(Exception):
    pass


def gemini_request(path, key, body=None, timeout=60):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(f"{GEMINI_BASE}/{path}", data=data,
                                 method="POST" if body is not None else "GET",
                                 headers={"x-goog-api-key": key, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            msg = json.loads(raw)["error"]["message"]
        except Exception:
            msg = raw
        raise GeminiError(f"HTTP {e.code}: {msg[:300]}")
    except urllib.error.URLError as e:
        raise GeminiError(f"Cannot reach Google: {e.reason}")


def pick_model(models):
    """Picks a current Flash model from the list that Google returns for this key."""
    bad = ("tts", "image", "live", "embed", "vision", "audio", "robot", "computer", "exp", "learnlm",
           "aqa", "native", "thinking")
    best, best_score = None, None
    for m in models:
        name = str(m.get("name", "")).split("/")[-1]
        low = name.lower()
        if "generateContent" not in m.get("supportedGenerationMethods", []):
            continue
        if not low.startswith("gemini-") or any(b in low for b in bad):
            continue
        ver = re.search(r"gemini-(\d+(?:\.\d+)?)", low)
        score = ("flash" in low and "lite" not in low, "preview" not in low,
                 float(ver.group(1)) if ver else 0.0, "lite" not in low, name)
        if best_score is None or score > best_score:
            best, best_score = name, score
    return best


def ask_gemini(key, prompt, settings=None, cache={}):
    settings = settings or {}
    model = settings.get("gemini_model") or cache.get("model")
    forced = bool(settings.get("gemini_model"))
    body = {"contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 4096}}
    for attempt in (1, 2):
        if not model:
            model = pick_model(gemini_request("models?pageSize=200", key).get("models", []))
            if not model:
                raise GeminiError("No Gemini model that supports generateContent was found for this key.")
            cache["model"] = model
        try:
            resp = gemini_request(f"models/{model}:generateContent", key, body)
            break
        except GeminiError as e:
            if attempt == 1 and "404" in str(e) and not forced:
                cache.pop("model", None)
                model = None
                continue
            raise
    cands = resp.get("candidates") or []
    parts = cands[0].get("content", {}).get("parts", []) if cands else []
    text = "".join(p.get("text", "") for p in parts).strip()
    if not text:
        why = (resp.get("promptFeedback") or {}).get("blockReason") or (cands[0].get("finishReason") if cands else "")
        raise GeminiError(f"Gemini returned no text ({why or 'unknown reason'}).")
    return text, model


def get_gemini_key(app, ask=True, force=False):
    if not force:
        key = getattr(app, "_gemini_key", "") or os.environ.get("GEMINI_API_KEY", "").strip()
        if not key and F.keyring:
            try:
                key = F.keyring.get_password(F.KEYRING_SERVICE, GEMINI_KEY_NAME) or ""
            except Exception:
                key = ""
        if key:
            app._gemini_key = key
            return key
    if not ask:
        return ""
    key = (simpledialog.askstring("Gemini API key", "Paste your Gemini API key:", show="*", parent=app) or "").strip()
    if key:
        app._gemini_key = key
        if F.keyring and messagebox.askyesno("Save?", "Save the key in Windows Credential Manager?\n(Not in the code or in a file.)"):
            try:
                F.keyring.set_password(F.KEYRING_SERVICE, GEMINI_KEY_NAME, key)
            except Exception:
                pass
    return key


# ======================================================================================
# Part D.  Screens
# ======================================================================================
GREY, RED, GREEN = "#6b7280", "#dc2626", "#16a34a"
COLORS = {"grey": GREY, "red": RED, "green": GREEN}


from datetime import timedelta


class TodayBox:
    """Small box in the top right corner."""

    def __init__(self, app):
        self.app = app
        self.result = None
        self.running = False
        self.job = None
        self.win = None
        self.tree = None
        self.day = None                         # None = today (follows the real date), or a chosen date
        self.date_var = tk.StringVar(app, value=f"{date.today():%d/%m/%Y}")
        self.frame = tk.Frame(app, bd=2, relief="ridge", width=150, height=108, bg=GREY)
        self.frame.pack_propagate(False)
        self.daybar = tk.Frame(self.frame, bg=GREY)
        self.prev = tk.Label(self.daybar, text="\u25c0", bg=GREY, fg="white")
        self.title = tk.Label(self.daybar, bg=GREY, fg="white")
        self.next = tk.Label(self.daybar, text="\u25b6", bg=GREY, fg="white")
        self.main = tk.Label(self.frame, bg=GREY, fg="white")
        self.sub = tk.Label(self.frame, bg=GREY, fg="white")
        self.btn = tk.Button(self.frame, text="Refresh", command=self.refresh)
        self.prev.pack(side="left", padx=(0, 4))
        self.title.pack(side="left")
        self.next.pack(side="left", padx=(4, 0))
        self.daybar.pack(pady=(6, 0))
        self.main.pack(pady=(4, 0))
        self.sub.pack()
        self.btn.pack(side="bottom", pady=4)
        # small grip in the bottom-left corner: drag it to make the box bigger or smaller
        self.grip = tk.Label(self.frame, text="\u25e3", bg=GREY, fg="white")
        for cur in ("size_ne_sw", "bottom_left_corner", "fleur", "hand2"):     # first one this PC accepts
            try:
                self.grip.config(cursor=cur)
                break
            except tk.TclError:
                continue
        self.grip.place(relx=0.0, rely=1.0, anchor="sw")
        self.grip.bind("<ButtonPress-1>", self._grip_press)
        self.grip.bind("<B1-Motion>", self._grip_drag)
        self.grip.bind("<ButtonRelease-1>", self._grip_release)
        for w in (self.frame, self.main, self.sub, self.daybar):
            w.bind("<Button-1>", self.open_window)
            w.config(cursor="hand2")
        self.prev.bind("<Button-1>", lambda e: self.shift(-1))      # one day back
        self.next.bind("<Button-1>", lambda e: self.shift(1))       # one day forward
        self.title.bind("<Button-1>", self.ask_date)                # click the date to type one
        for w in (self.prev, self.next, self.title):
            w.config(cursor="hand2")
        try:
            w0, h0 = int(app.settings.get("box_w", 150)), int(app.settings.get("box_h", 108))
        except (TypeError, ValueError):
            w0, h0 = 150, 108
        self.set_size(w0, h0)
        self.frame.place(relx=1.0, x=-14, y=8, anchor="ne")
        self.frame.lift()
        self.paint("grey", "Today Losi : -", "Not updated yet")

    # ---- size (drag the corner grip)
    MIN_W, MIN_H, MAX_W, MAX_H = 130, 96, 560, 420

    def set_size(self, w, h, limit=False):
        max_w = self.MAX_W
        if limit and self.app.winfo_width() > 300:
            max_w = min(self.MAX_W, self.app.winfo_width() - 40)
        w = int(min(max(w, self.MIN_W), max_w))
        h = int(min(max(h, self.MIN_H), self.MAX_H))
        self.w, self.h = w, h
        self.frame.config(width=w, height=h)
        s = min(3.0, max(0.85, min(w / 150, h / 108)))        # text grows with the box
        self.prev.config(font=("Segoe UI", max(8, int(9 * s))))
        self.next.config(font=("Segoe UI", max(8, int(9 * s))))
        self.title.config(font=("Segoe UI", max(8, int(9 * s))))
        self.main.config(font=("Segoe UI", max(10, int(12 * s)), "bold"), wraplength=w - 14)
        self.sub.config(font=("Segoe UI", max(7, int(8 * s))), wraplength=w - 14)
        self.btn.config(font=("Segoe UI", max(8, int(8 * s))))
        self.grip.config(font=("Segoe UI", max(8, int(9 * s))))

    def _grip_press(self, e):
        self._rs = (e.x_root, e.y_root, self.w, self.h)

    def _grip_drag(self, e):
        x0, y0, w0, h0 = self._rs
        self.set_size(w0 - (e.x_root - x0), h0 + (e.y_root - y0), limit=True)   # left = wider, down = taller

    def _grip_release(self, _e):
        self.app.settings["box_w"], self.app.settings["box_h"] = self.w, self.h
        F.save_settings(self.app.settings)

    # ---- date (None = today)
    def cur_day(self):
        return self.day or date.today()

    def set_day(self, d):
        if d > date.today():
            messagebox.showinfo("Date", "This date is in the future. Choose today or an older date.")
            return False
        self.day = None if d == date.today() else d
        self.date_var.set(f"{d:%d/%m/%Y}")
        if self.result and self.result.get("raw") is not None:      # count again from the last scan (no login)
            self.result = summarize(self.result["raw"], self.cur_day(), self.result["seconds"],
                                    self.result["n_olts"], self.result["time"])
            self.paint(*box_state(self.result))
            self.fill_window()
        else:
            self.paint("grey", "Today Losi : -", "Not updated yet")
        return True

    def shift(self, days):
        self.set_day(self.cur_day() + timedelta(days=days))

    def ask_date(self, _=None):
        s = simpledialog.askstring("Date", "Type a date (dd/mm/yyyy):",
                                   initialvalue=f"{self.cur_day():%d/%m/%Y}", parent=self.app)
        if s:
            self.go_date(s)

    def go_date(self, text=None):
        d = parse_user_date(self.date_var.get() if text is None else text)
        if d is None:
            messagebox.showwarning("Date", "I could not read this date.\nUse dd/mm/yyyy, for example 25/10/2026.")
            return
        self.set_day(d)

    def paint(self, color, main, sub):
        c = COLORS[color]
        if self.day:
            main = main.replace("Today Losi", "Losi")
        for w in (self.frame, self.daybar, self.prev, self.next, self.title, self.main, self.sub, self.grip):
            w.config(bg=c)
        self.title.config(text=("Date  " if self.day else "Today  ") + f"{self.cur_day():%d/%m/%Y}")
        self.main.config(text=main)
        self.sub.config(text=sub)

    # ---- running
    def watch_list(self):
        elig = eligible_olts(self.app.olts)
        keys = self.app.settings.get("watch")
        if keys is None:
            return elig
        keys = set(keys)
        return [o for o in elig if F.olt_key(o) in keys]

    def start(self):
        if not (self.app.pw or self.app.get_password()):
            self.paint("grey", "Today Losi : -", "Set the password, then click Refresh")
            return
        self.refresh()

    def stop(self):
        if self.job:
            try:
                self.app.after_cancel(self.job)
            except Exception:
                pass
            self.job = None

    def refresh(self):
        if self.running:
            return
        pw = self.app.pw or self.app.get_password()
        if not pw:
            self.paint("grey", "Today Losi : -", "Password needed. Click Refresh.")
            return
        olts = self.watch_list()
        if not olts:
            self.paint("grey", "Today Losi : -", "No OLT to check. Use 'Choose OLTs'.")
            return
        user = self.app.user_var.get().strip() or F.DEFAULT_USER
        self.stop()
        self.running = True
        self.btn.config(state="disabled")
        self.sub.config(text=f"Checking {len(olts)} OLT(s)...")

        def work():
            try:
                res = run_round(olts, user, pw, lambda s: self.app.post(lambda: self.sub.config(text=s)),
                                today=self.day)
            except Exception as e:
                res = None
                self.app.post(self.failed, F.err_text(e))
                return
            self.app.post(self.done, res)

        threading.Thread(target=work, daemon=True).start()

    def failed(self, msg):
        self.running = False
        self.btn.config(state="normal")
        self.paint("grey", "Today Losi : -", f"Error: {msg}"[:60])
        self.job = self.app.after(REFRESH_MS, self.refresh)

    def done(self, res):
        self.running = False
        self.btn.config(state="normal")
        if res["today"] != self.cur_day():                  # the date was changed while the scan was running
            res = summarize(res["raw"], self.cur_day(), res["seconds"], res["n_olts"], res["time"])
        self.result = res
        self.paint(*box_state(res))
        self.fill_window()
        if res["wrong_pw"]:
            self.app.pw = None                      # stop. Do not try again with a wrong password.
        else:
            self.job = self.app.after(REFRESH_MS, self.refresh)

    # ---- details window
    def open_window(self, _=None):
        if self.win is not None and self.win.winfo_exists():
            self.win.lift()
            self.fill_window()
            return
        win = self.win = tk.Toplevel(self.app)
        win.title("Today Losi")
        win.geometry("880x560")
        self.head_var = tk.StringVar()
        tk.Label(win, textvariable=self.head_var, justify="left", anchor="w",
                 font=("Segoe UI", 10)).pack(fill="x", padx=10, pady=(10, 4))
        bar = tk.Frame(win)
        bar.pack(fill="x", padx=10)
        tk.Button(bar, text="Refresh", command=self.refresh).pack(side="left")
        tk.Button(bar, text="Choose OLTs", command=self.choose_olts).pack(side="left", padx=6)
        tk.Button(bar, text="Expand all", command=lambda: self.expand(True)).pack(side="left")
        tk.Button(bar, text="Collapse all", command=lambda: self.expand(False)).pack(side="left", padx=6)
        tk.Label(bar, text="    Date:").pack(side="left")
        de = tk.Entry(bar, textvariable=self.date_var, width=11)
        de.pack(side="left")
        de.bind("<Return>", lambda _e: self.go_date())
        tk.Button(bar, text="Go", command=self.go_date).pack(side="left", padx=3)
        tk.Button(bar, text="Today", command=lambda: self.set_day(date.today())).pack(side="left")
        wrap = tk.Frame(win)
        wrap.pack(fill="both", expand=True, padx=10, pady=8)
        t = self.tree = ttk.Treeview(wrap, columns=("count", "time", "reason", "sn"), show="tree headings")
        t.heading("#0", text="Area (OLT) / PON / ONU")
        t.heading("count", text="Count")
        t.heading("time", text="Down time")
        t.heading("reason", text="Reason")
        t.heading("sn", text="SN")
        t.column("#0", width=300)
        t.column("count", width=70, anchor="center")
        t.column("time", width=100)
        t.column("reason", width=200)
        t.column("sn", width=150)
        t.tag_configure("olt", background="#fee2e2")
        t.tag_configure("err", foreground="#b91c1c")
        sb = tk.Scrollbar(wrap, command=t.yview)
        t.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        t.pack(fill="both", expand=True)
        self.fill_window()

    def fill_window(self):
        if not (self.win is not None and self.win.winfo_exists()):
            return
        t, res = self.tree, self.result
        t.delete(*t.get_children())
        if not res:
            self.head_var.set("No data yet. Click Refresh.")
            return
        past = res["today"] != date.today()
        self.head_var.set(
            f"Date: {res['today']:%d/%m/%Y}      {'Losi' if past else 'Today Losi'}: {res['total']}      "
            f"(Dying Gasp that day, not counted: {res['dg']})\n"
            + ("Past date: shows ONUs that went down on this date and are still down now.\n" if past else "") +
            f"Updated {res['time']:%H:%M:%S}, took {fmt_secs(res['seconds'])}.      "
            f"OLTs checked: {res['checked']}   failed: {len(res['failed'])}   partly checked: {res['partial']}")
        for o in sorted(res["olts"], key=lambda x: (-x["count"], x["name"])):
            if o["error"]:
                t.insert("", "end", text=o["name"], values=("failed", "", o["error"], ""), tags=("err",))
                continue
            if o["count"] == 0:
                continue
            top = t.insert("", "end", text=o["name"], values=(o["count"], "", "", ""), tags=("olt",))
            for label in sorted(o["pons"], key=F.natural_key if hasattr(F, "natural_key") else str):
                es = o["pons"][label]
                pon = t.insert(top, "end", text=f"PON {label}", values=(len(es), "", "", ""))
                for e in sorted(es, key=lambda x: int(x["onu"])):
                    t.insert(pon, "end", text=f"ONU {e['onu']}",
                             values=("", e["down"].strftime("%H:%M:%S"), e["cause"] or "-", e["sn"]))
        if not t.get_children():
            t.insert("", "end", text="No ONU is down on this date.", values=("", "", "", ""))

    def expand(self, flag):
        def walk(item):
            self.tree.item(item, open=flag)
            for c in self.tree.get_children(item):
                walk(c)
        for i in self.tree.get_children():
            walk(i)

    def choose_olts(self):
        elig = eligible_olts(self.app.olts)
        cur = self.app.settings.get("watch")
        cur = set(cur) if cur is not None else {F.olt_key(o) for o in elig}
        win = tk.Toplevel(self.app)
        win.title("OLTs to check")
        win.geometry("420x560")
        win.transient(self.app)
        wrap = tk.Frame(win)
        wrap.pack(fill="both", expand=True, padx=8, pady=8)
        cv = tk.Canvas(wrap, highlightthickness=0)
        sb = tk.Scrollbar(wrap, command=cv.yview)
        cv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        cv.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(cv)
        cv.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        vars_ = {}
        for o in elig:
            k = F.olt_key(o)
            vars_[k] = tk.BooleanVar(value=k in cur)
            tk.Checkbutton(inner, text=f"{o['name']}   ({o['vendor']})", variable=vars_[k], anchor="w").pack(fill="x", anchor="w")
        bar = tk.Frame(win)
        bar.pack(fill="x", padx=8, pady=(0, 8))
        tk.Button(bar, text="Select all", command=lambda: [v.set(True) for v in vars_.values()]).pack(side="left")
        tk.Button(bar, text="Clear", command=lambda: [v.set(False) for v in vars_.values()]).pack(side="left", padx=6)

        def save():
            self.app.settings["watch"] = [k for k, v in vars_.items() if v.get()]
            F.save_settings(self.app.settings)
            win.destroy()
            self.refresh()
        tk.Button(bar, text="Save and refresh", command=save).pack(side="right")


class AIPanel:
    TAGS = {"ok": "#16a34a", "bad": "#dc2626", "warn": "#d97706", "unknown": "#d97706", "info": "#374151"}

    def __init__(self, app, hit):
        self.app, self.hit = app, hit
        self.facts = gather_facts(hit)
        win = self.win = tk.Toplevel(app)
        win.title("AI Analyze")
        win.geometry("780x760")
        tk.Label(win, text=f"{hit['olt']}    {self.facts['iface']}    SN {self.facts['sn']}",
                 font=("Segoe UI", 10, "bold"), anchor="w").pack(fill="x", padx=10, pady=(10, 2))
        tk.Label(win, text="Collected by the app (rule check)", anchor="w").pack(fill="x", padx=10)
        self.rules = tk.Text(win, height=6, font=("Segoe UI", 10), wrap="word")
        self.rules.pack(fill="x", padx=10, pady=(0, 6))
        self.inputs = {}
        for label, hint in (("ERP login status", "Paste the ERP text here"),
                            ("MikroTik bandwidth", "Paste the bandwidth text here"),
                            ("MikroTik PPP", "Paste the PPP text here")):
            tk.Label(win, text=f"{label}   ({hint})", anchor="w").pack(fill="x", padx=10)
            t = tk.Text(win, height=3, font=("Consolas", 10))
            t.pack(fill="x", padx=10, pady=(0, 6))
            self.inputs[label] = t
        bar = tk.Frame(win)
        bar.pack(fill="x", padx=10)
        self.btn = tk.Button(bar, text="Analyze", width=14, bg="#7c3aed", fg="white", command=self.analyze)
        self.btn.pack(side="left")
        tk.Button(bar, text="Set Gemini key", command=lambda: get_gemini_key(app, force=True)).pack(side="left", padx=6)
        tk.Label(bar, text="Gemini only gives advice. It cannot run commands.", fg="#555").pack(side="left", padx=6)
        tk.Label(win, text="Result", anchor="w", font=("Segoe UI", 10, "bold")).pack(fill="x", padx=10, pady=(8, 0))
        self.result = tk.Text(win, font=("Segoe UI", 10), wrap="word")
        self.result.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        for tag, color in self.TAGS.items():
            self.rules.tag_config(tag, foreground=color)
            self.result.tag_config(tag, foreground=color)
        self.result.tag_config("head", font=("Segoe UI", 10, "bold"))
        for tag, text in rule_lines(self.facts):
            self.rules.insert("end", ("OK   " if tag == "ok" else "NOT OK   " if tag == "bad" else "") + text + "\n", tag)
        self.rules.config(state="disabled")

    def analyze(self):
        key = get_gemini_key(self.app)
        if not key:
            return
        prompt = build_prompt(self.facts, *(self.inputs[k].get("1.0", "end").strip() for k in
                                            ("ERP login status", "MikroTik bandwidth", "MikroTik PPP")))
        self.btn.config(state="disabled")
        self.result.delete("1.0", "end")
        self.result.insert("end", "Asking Gemini...")
        settings = self.app.settings

        def work():
            try:
                text, model = ask_gemini(key, prompt, settings)
                out = (text, f"Model: {model}")
            except Exception as e:
                out = (f"AI error: {e}", "")
            self.app.post(self.show, *out)

        threading.Thread(target=work, daemon=True).start()

    def show(self, text, note):
        if not self.win.winfo_exists():
            return
        self.btn.config(state="normal")
        r = self.result
        r.delete("1.0", "end")
        r.insert("end", "RULE CHECK (by the app)\n", "head")
        for tag, t in rule_lines(self.facts):
            r.insert("end", ("OK   " if tag == "ok" else "NOT OK   " if tag == "bad" else "") + t + "\n", tag)
        r.insert("end", "\nAI CONCLUSION (Gemini)\n", "head")
        r.insert("end", text + "\n")
        if note:
            r.insert("end", "\n" + note, "info")


_Base = F.App if tk else object


class App2(_Base):
    """Your app + the Today Losi box + the AI Analyze button."""

    def build_ui(self):
        super().build_ui()
        self.box = TodayBox(self)
        self.ai_btn = tk.Button(self.act_frame, text="AI Analyze", bg="#7c3aed", fg="white", command=self.open_ai)
        self.ai_btn.pack(side="right", padx=4, pady=2)
        self.after(1500, self.box.start)

    def open_ai(self):
        sel = self.tree.selection()
        h = self.hit_by_item.get(sel[0]) if sel else None
        if not h or h.get("pon_only"):
            messagebox.showinfo("AI Analyze", "First select a 'Found' ONU row in the table.")
            return
        AIPanel(self, h)

    def on_close(self):
        try:
            self.box.stop()
        except Exception:
            pass
        super().on_close()


def main():
    if tk is None:
        print("tkinter was not found.")
        sys.exit(1)
    install_patches()
    App2().mainloop()


if __name__ == "__main__":
    main()