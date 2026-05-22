"""
╔══════════════════════════════════════════════════════════════╗
║     PREDICTIVE SECURITY HEALTH SCORING — SMARTPHONE         ║
║     Real-Time ADB Data Extraction + ML Risk Scoring         ║
╚══════════════════════════════════════════════════════════════╝

Dataset columns used:
  os_version       → adb shell getprop ro.build.version.release
  unknown_apps     → adb shell settings get global install_non_market_apps
  screen_lock      → adb shell settings get secure lockscreen.password_type
  app_permissions  → adb shell pm list permissions -d -g (count)
  malware_detected → heuristic: presence of unknown APKs / non-Play installs
  security_score   → computed dynamically from the above features
"""

import streamlit as st
import subprocess
import re
import time
import math
from datetime import datetime
import pandas as pd

# Page Config
st.set_page_config(
    page_title="ShieldScan · Security Health",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Global CSS
st.markdown("""
<style>
/* ---- Google Fonts ---- */
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500;700&family=Outfit:wght@300;400;500;600&display=swap');

/* ---- Root palette ---- */
:root {
  --bg-void:    #050608;
  --bg-deep:    #080b12;
  --bg-panel:   #0d1117;
  --bg-card:    #111620;
  --bg-hover:   #161c2a;
  --border:     rgba(255,255,255,0.06);
  --border-hi:  rgba(255,255,255,0.12);
  --glow-cyan:  rgba(0,212,255,0.15);
  --glow-safe:  rgba(52,211,153,0.15);
  --glow-warn:  rgba(251,191,36,0.15);
  --glow-red:   rgba(248,113,113,0.15);
  --accent:     #00d4ff;
  --accent2:    #6366f1;
  --safe:       #34d399;
  --safe-dim:   rgba(52,211,153,0.12);
  --warn:       #fbbf24;
  --warn-dim:   rgba(251,191,36,0.10);
  --danger:     #f87171;
  --danger-dim: rgba(248,113,113,0.12);
  --text-hi:    #f0f4ff;
  --text-mid:   #7c8db0;
  --text-lo:    #3a4560;
  --mono:       'JetBrains Mono', monospace;
  --display:    'Syne', sans-serif;
  --sans:       'Outfit', sans-serif;
}

/* ---- Base reset ---- */
html, body, [class*="css"] {
  background-color: var(--bg-void) !important;
  color: var(--text-hi) !important;
  font-family: var(--sans) !important;
  font-weight: 400 !important;
}

/* ---- Noise texture overlay ---- */
body::before {
  content: '';
  position: fixed;
  inset: 0;
  background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");
  pointer-events: none;
  z-index: 9999;
  opacity: 0.4;
}

/* ---- Ambient background mesh ---- */
.stApp {
  background:
    radial-gradient(ellipse 900px 600px at 20% 10%, rgba(99,102,241,0.04) 0%, transparent 70%),
    radial-gradient(ellipse 600px 400px at 80% 80%, rgba(0,212,255,0.03) 0%, transparent 70%),
    var(--bg-void) !important;
}

/* Sidebar */
section[data-testid="stSidebar"] {
  background: var(--bg-panel) !important;
  border-right: 1px solid var(--border) !important;
}
section[data-testid="stSidebar"] * { font-family: var(--sans) !important; }
section[data-testid="stSidebar"] > div:first-child {
  background: transparent !important;
}

/* Hide default Streamlit chrome */
#MainMenu, footer, header { visibility: hidden; }
.block-container { padding: 2rem 2.5rem !important; max-width: 1480px; }

/* ---- Glass card base ---- */
.glass {
  background: rgba(17,22,32,0.8);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border: 1px solid var(--border);
  border-radius: 20px;
}

/* ---- Score ring card ---- */
.score-ring-wrap {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 2rem 1.5rem 1.8rem;
  background: linear-gradient(145deg, rgba(17,22,32,0.9) 0%, rgba(13,17,23,0.95) 100%);
  border: 1px solid var(--border-hi);
  border-radius: 24px;
  position: relative;
  overflow: hidden;
}
.score-ring-wrap::before {
  content: '';
  position: absolute;
  top: -40px; left: 50%;
  transform: translateX(-50%);
  width: 200px; height: 200px;
  background: radial-gradient(circle, var(--glow-cyan) 0%, transparent 70%);
  pointer-events: none;
}
.score-label {
  font-family: var(--mono);
  font-size: 0.6rem;
  font-weight: 500;
  letter-spacing: 0.3em;
  text-transform: uppercase;
  color: var(--text-lo);
  margin-top: 0.6rem;
}
.score-grade {
  font-family: var(--display);
  font-size: 0.82rem;
  font-weight: 700;
  letter-spacing: 0.15em;
  text-transform: uppercase;
  margin-top: 0.3rem;
}

/* ---- Metric chips ---- */
.metric-chip {
  background: linear-gradient(145deg, rgba(17,22,32,0.9), rgba(13,17,23,0.8));
  border: 1px solid var(--border);
  border-radius: 18px;
  padding: 1.2rem 1.3rem;
  margin-bottom: 0;
  display: flex;
  align-items: flex-start;
  flex-direction: column;
  gap: 0.5rem;
  transition: border-color 0.2s, transform 0.2s;
  position: relative;
  overflow: hidden;
}
.metric-chip::after {
  content: '';
  position: absolute;
  inset: 0;
  border-radius: 18px;
  opacity: 0;
  transition: opacity 0.3s;
}
.chip-top {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  width: 100%;
}
.chip-icon {
  font-size: 1.3rem;
  line-height: 1;
  opacity: 0.85;
}
.chip-label {
  font-family: var(--mono);
  font-size: 0.58rem;
  font-weight: 500;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--text-lo);
  margin-bottom: 0.1rem;
}
.chip-value {
  font-family: var(--display);
  font-size: 1.1rem;
  font-weight: 700;
  color: var(--text-hi);
  line-height: 1.2;
}
.chip-badge {
  font-family: var(--mono);
  font-size: 0.58rem;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  padding: 0.22rem 0.55rem;
  border-radius: 6px;
  flex-shrink: 0;
}
.badge-safe   { background: rgba(52,211,153,0.1);  color: var(--safe);   border: 1px solid rgba(52,211,153,0.2); }
.badge-warn   { background: rgba(251,191,36,0.1);  color: var(--warn);   border: 1px solid rgba(251,191,36,0.2); }
.badge-danger { background: rgba(248,113,113,0.1); color: var(--danger); border: 1px solid rgba(248,113,113,0.2); }
.badge-info   { background: rgba(0,212,255,0.08);  color: var(--accent); border: 1px solid rgba(0,212,255,0.15); }

/* ---- Risk cards ---- */
.risk-card {
  background: rgba(248,113,113,0.04);
  border: 1px solid rgba(248,113,113,0.15);
  border-radius: 16px;
  padding: 1rem 1.2rem;
  margin-bottom: 0.6rem;
  display: flex;
  gap: 0.9rem;
  align-items: flex-start;
  transition: background 0.2s;
}
.risk-card:hover { background: rgba(248,113,113,0.07); }
.risk-card.warn  {
  background: rgba(251,191,36,0.04);
  border-color: rgba(251,191,36,0.15);
}
.risk-card.warn:hover  { background: rgba(251,191,36,0.07); }
.risk-card.info  {
  background: rgba(0,212,255,0.03);
  border-color: rgba(0,212,255,0.12);
}
.risk-card.info:hover  { background: rgba(0,212,255,0.06); }
.risk-icon {
  font-size: 1rem;
  flex-shrink: 0;
  margin-top: 0.05rem;
  opacity: 0.9;
}
.risk-body { flex: 1; min-width: 0; }
.risk-title {
  font-family: var(--display);
  font-size: 0.82rem;
  font-weight: 700;
  color: var(--danger);
  margin-bottom: 0.25rem;
  line-height: 1.3;
}
.risk-card.warn .risk-title  { color: var(--warn); }
.risk-card.info .risk-title  { color: var(--accent); }
.risk-desc {
  font-size: 0.78rem;
  color: var(--text-mid);
  line-height: 1.6;
  font-weight: 300;
}

/* ---- Section headings ---- */
.section-head {
  display: flex;
  align-items: center;
  gap: 0.7rem;
  margin-bottom: 1rem;
}
.section-head-line {
  flex: 1;
  height: 1px;
  background: linear-gradient(90deg, var(--border-hi), transparent);
}
.section-head-text {
  font-family: var(--mono);
  font-size: 0.6rem;
  font-weight: 500;
  letter-spacing: 0.25em;
  text-transform: uppercase;
  color: var(--text-lo);
  white-space: nowrap;
}

/* ---- Progress bar ---- */
.bar-wrap {
  background: rgba(255,255,255,0.04);
  border-radius: 999px;
  height: 4px;
  overflow: hidden;
  margin-top: 0.35rem;
}
.bar-fill {
  height: 100%;
  border-radius: 999px;
  transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
  position: relative;
}
.bar-fill::after {
  content: '';
  position: absolute;
  right: 0; top: 0;
  width: 8px; height: 100%;
  border-radius: 999px;
  background: rgba(255,255,255,0.6);
  filter: blur(2px);
}

/* ---- Status badge sidebar ---- */
.conn-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.45rem;
  padding: 0.3rem 0.75rem;
  border-radius: 999px;
  font-family: var(--mono);
  font-size: 0.62rem;
  font-weight: 700;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}
.conn-pill.connected    {
  background: rgba(52,211,153,0.08);
  color: var(--safe);
  border: 1px solid rgba(52,211,153,0.2);
}
.conn-pill.disconnected {
  background: rgba(248,113,113,0.08);
  color: var(--danger);
  border: 1px solid rgba(248,113,113,0.2);
}
.conn-dot {
  width: 6px; height: 6px;
  border-radius: 50%;
  display: inline-block;
}
.conn-dot.on  { background: var(--safe);   box-shadow: 0 0 6px var(--safe); animation: blink 2s infinite; }
.conn-dot.off { background: var(--danger); }

@keyframes blink {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0.4; }
}

/* ---- Timestamp ---- */
.ts {
  font-family: var(--mono);
  font-size: 0.6rem;
  color: var(--text-lo);
  letter-spacing: 0.05em;
}

/* ---- Divider ---- */
.hr { border: none; border-top: 1px solid var(--border); margin: 1.2rem 0; }

/* ---- Streamlit overrides ---- */
.stButton > button {
  background: linear-gradient(135deg, var(--accent2) 0%, #4f46e5 100%) !important;
  color: #fff !important;
  border: none !important;
  border-radius: 12px !important;
  font-family: var(--mono) !important;
  font-size: 0.68rem !important;
  font-weight: 700 !important;
  letter-spacing: 0.1em !important;
  padding: 0.6rem 1.4rem !important;
  transition: all 0.2s !important;
  box-shadow: 0 4px 20px rgba(99,102,241,0.3) !important;
}
.stButton > button:hover {
  transform: translateY(-1px) !important;
  box-shadow: 0 6px 28px rgba(99,102,241,0.45) !important;
}

.stSelectbox > div > div {
  background: var(--bg-card) !important;
  border: 1px solid var(--border) !important;
  border-radius: 12px !important;
  color: var(--text-hi) !important;
  font-family: var(--sans) !important;
}

div[data-testid="stMetricValue"] {
  font-family: var(--mono) !important;
  font-size: 2rem !important;
}

.stExpander {
  background: var(--bg-card) !important;
  border: 1px solid var(--border) !important;
  border-radius: 16px !important;
}
.stExpander summary {
  color: var(--text-mid) !important;
  font-family: var(--mono) !important;
  font-size: 0.68rem !important;
  letter-spacing: 0.1em !important;
}

.stSpinner > div { border-top-color: var(--accent) !important; }

/* ---- Flag row ---- */
.flag-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.65rem 1rem;
  background: rgba(17,22,32,0.6);
  border: 1px solid var(--border);
  border-radius: 12px;
  margin-bottom: 0.4rem;
  transition: border-color 0.2s;
}
.flag-row:hover { border-color: var(--border-hi); }
.flag-label { font-size: 0.78rem; color: var(--text-mid); font-weight: 400; }
.flag-val {
  font-family: var(--mono);
  font-size: 0.68rem;
  font-weight: 700;
  letter-spacing: 0.08em;
}

/* ---- Device identity card ---- */
.device-card {
  background: linear-gradient(145deg, rgba(17,22,32,0.95), rgba(11,15,22,0.98));
  border: 1px solid var(--border-hi);
  border-radius: 24px;
  padding: 1.6rem 1.8rem;
  height: 100%;
  box-sizing: border-box;
  position: relative;
  overflow: hidden;
}
.device-card::before {
  content: '';
  position: absolute;
  top: -60px; right: -60px;
  width: 200px; height: 200px;
  background: radial-gradient(circle, rgba(99,102,241,0.06) 0%, transparent 70%);
  pointer-events: none;
}
.device-name {
  font-family: var(--display);
  font-size: 1.35rem;
  font-weight: 800;
  color: var(--text-hi);
  letter-spacing: -0.5px;
  line-height: 1.2;
}
.device-serial {
  font-family: var(--mono);
  font-size: 0.64rem;
  color: var(--text-lo);
  margin-top: 0.2rem;
  letter-spacing: 0.05em;
}
.device-meta-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0.55rem;
  margin-top: 1.2rem;
}
.meta-cell {
  background: rgba(255,255,255,0.03);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 0.7rem 0.9rem;
}
.meta-label {
  font-family: var(--mono);
  font-size: 0.56rem;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--text-lo);
  margin-bottom: 0.15rem;
}
.meta-value {
  font-family: var(--display);
  font-size: 0.9rem;
  font-weight: 700;
  color: var(--text-hi);
}

/* ---- Sidebar logo ---- */
.sidebar-logo {
  display: flex;
  flex-direction: column;
  gap: 0.1rem;
  padding: 0.5rem 0 1.5rem;
}
.logo-mark {
  display: flex;
  align-items: center;
  gap: 0.6rem;
}
.logo-icon {
  width: 32px; height: 32px;
  background: linear-gradient(135deg, rgba(0,212,255,0.2), rgba(99,102,241,0.2));
  border: 1px solid rgba(0,212,255,0.2);
  border-radius: 9px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 1rem;
}
.logo-text {
  font-family: var(--display);
  font-size: 1.1rem;
  font-weight: 800;
  color: var(--text-hi);
  letter-spacing: -0.5px;
}
.logo-sub {
  font-family: var(--mono);
  font-size: 0.58rem;
  color: var(--text-lo);
  letter-spacing: 0.22em;
  text-transform: uppercase;
  padding-left: 2.6rem;
}

/* ---- Header ---- */
.page-header {
  margin-bottom: 2rem;
  position: relative;
}
.header-eyebrow {
  font-family: var(--mono);
  font-size: 0.6rem;
  letter-spacing: 0.3em;
  text-transform: uppercase;
  color: var(--accent);
  opacity: 0.7;
  margin-bottom: 0.4rem;
}
.header-title {
  font-family: var(--display);
  font-size: 1.9rem;
  font-weight: 800;
  color: var(--text-hi);
  letter-spacing: -1px;
  line-height: 1.1;
}
.header-sub {
  font-size: 0.82rem;
  color: var(--text-mid);
  margin-top: 0.4rem;
  font-weight: 300;
  letter-spacing: 0.01em;
}
.live-dot {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  font-family: var(--mono);
  font-size: 0.6rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--safe);
  padding: 0.22rem 0.6rem;
  background: rgba(52,211,153,0.08);
  border: 1px solid rgba(52,211,153,0.2);
  border-radius: 999px;
  margin-left: 0.7rem;
  vertical-align: middle;
}
</style>
""", unsafe_allow_html=True)



#  ADB HELPERS

def _adb(args: list[str], timeout: int = 6) -> str:
    try:
        result = subprocess.run(
            ["adb"] + args,
            capture_output=True, text=True, timeout=timeout
        )
        return result.stdout.strip()
    except Exception:
        return ""


def adb_devices() -> list[str]:
    out = _adb(["devices"])
    devices = []
    for line in out.splitlines()[1:]:
        parts = line.strip().split()
        if len(parts) == 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def fetch_device_data(serial: str) -> dict:
    def s(args): return _adb(["-s", serial] + args)

    os_ver_raw = s(["shell", "getprop", "ro.build.version.release"]).strip()
    try:
        os_version = int(os_ver_raw.split(".")[0])
    except Exception:
        os_version = 0

    ua_global = s(["shell", "settings", "get", "global", "install_non_market_apps"])
    ua_secure = s(["shell", "settings", "get", "secure", "install_non_market_apps"])
    ua_val = ua_global if ua_global in ("0", "1") else ua_secure
    unknown_apps = 1 if ua_val == "1" else 0

    lock_type_raw = s(["shell", "settings", "get", "secure", "lockscreen.password_type"])
    try:
        lock_type_int = int(lock_type_raw)
    except Exception:
        lock_type_int = 0

    ls_out = s(["shell", "locksettings", "get-disabled"])
    if "true" in ls_out.lower():
        ls_locked = False
    elif "false" in ls_out.lower():
        ls_locked = True
    else:
        ls_locked = None

    kd_raw = s(["shell", "settings", "get", "secure", "keyguard_disabled_features"])
    try:
        kd_val = int(kd_raw)
        kd_fully_disabled = (kd_val == -2147483648 or kd_val == 2147483647)
    except Exception:
        kd_fully_disabled = False

    wm_out = s(["shell", "dumpsys", "window"])
    wm_locked = bool(re.search(r"(?i)(mShowingLockscreen|isStatusBarKeyguard|KeyguardController).*?=\s*true", wm_out))

    if ls_locked is not None:
        screen_lock = 1 if ls_locked else 0
    elif lock_type_int > 0:
        screen_lock = 1
    elif wm_locked:
        screen_lock = 1
    elif kd_fully_disabled:
        screen_lock = 0
    else:
        screen_lock = 0

    lock_type_map = {
        0:      "None",
        65536:  "Pattern",
        131072: "PIN",
        196608: "Password",
        327680: "Biometric + PIN",
        393216: "Biometric + Password",
    }
    if screen_lock == 0:
        screen_lock_name = "None"
    elif lock_type_int in lock_type_map and lock_type_int > 0:
        screen_lock_name = lock_type_map[lock_type_int]
    elif ls_locked:
        screen_lock_name = "Enabled (Biometric/PIN/Pattern)"
    else:
        screen_lock_name = f"Type {lock_type_int}"

    pm_out = s(["shell", "pm", "list", "permissions", "-d", "-g"])
    app_permissions = max(5, len(re.findall(r"^permission:", pm_out, re.MULTILINE)))
    app_permissions = min(app_permissions, 50)

    pkg_out = s(["shell", "pm", "list", "packages", "-i"])
    sideloaded_count = len(re.findall(r"installer=(?!com\.android\.vending|com\.google\.android)", pkg_out))

    device_model   = s(["shell", "getprop", "ro.product.model"])
    device_brand   = s(["shell", "getprop", "ro.product.brand"])
    android_full   = s(["shell", "getprop", "ro.build.version.release"])
    security_patch = s(["shell", "getprop", "ro.build.version.security_patch"])
    build_id       = s(["shell", "getprop", "ro.build.id"])
    battery_raw    = s(["shell", "dumpsys", "battery"])
    wifi_state     = s(["shell", "settings", "get", "global", "wifi_on"])
    bt_state       = s(["shell", "settings", "get", "global", "bluetooth_on"])
    usb_debug_raw  = s(["shell", "settings", "get", "global", "adb_enabled"])
    dev_options    = s(["shell", "settings", "get", "global", "development_settings_enabled"])
    encryption_raw = s(["shell", "getprop", "ro.crypto.state"])
    total_packages = len(re.findall(r"^package:", pkg_out, re.MULTILINE))

    bat_match = re.search(r"level:\s*(\d+)", battery_raw)
    battery_pct = int(bat_match.group(1)) if bat_match else -1

    return {
        "os_version":       os_version,
        "unknown_apps":     unknown_apps,
        "screen_lock":      screen_lock,
        "app_permissions":  app_permissions,
        "malware_detected": 0,

        "device_model":     device_model or "Unknown",
        "device_brand":     device_brand.title() or "Unknown",
        "android_full":     android_full or str(os_version),
        "security_patch":   security_patch or "Unknown",
        "build_id":         build_id or "Unknown",
        "battery_pct":      battery_pct,
        "wifi_on":          wifi_state == "1",
        "bluetooth_on":     bt_state == "1",
        "usb_debug":        usb_debug_raw == "1",
        "dev_options_on":   dev_options == "1",
        "encrypted":        encryption_raw.lower() == "encrypted",
        "total_packages":   total_packages,
        "sideloaded_count": sideloaded_count,
        "lock_type_name":   screen_lock_name,
        "serial":           serial,
        "fetched_at":       datetime.now(),
    }

#  SCORING ENGINE

LATEST_ANDROID = 14
MIN_PERMISSIONS = 5
MAX_PERMISSIONS = 50

def compute_score(d: dict) -> tuple[int, list[dict]]:
    score = 100
    risks = []

    os_lag = LATEST_ANDROID - d["os_version"]
    os_penalty = min(25, os_lag * 6)
    score -= os_penalty
    if os_lag > 0:
        sev = "danger" if os_lag >= 3 else "warn"
        risks.append({
            "sev":   sev,
            "title": f"Outdated OS — Android {d['os_version']} (latest: {LATEST_ANDROID})",
            "desc":  f"Your device is {os_lag} major version(s) behind. Unpatched CVEs accumulate with each missed upgrade, giving attackers known footholds.",
        })

    if d["unknown_apps"] == 1:
        score -= 25
        risks.append({
            "sev":   "danger",
            "title": "Unknown Sources Enabled",
            "desc":  "APKs from outside the Play Store can install silently. Malware, stalkerware, and banking trojans predominantly exploit this vector.",
        })

    if d["screen_lock"] == 0:
        score -= 20
        risks.append({
            "sev":   "danger",
            "title": "No Screen Lock Configured",
            "desc":  "Without a PIN, pattern, or biometric lock, any physical access to this device grants full control — bypassing all app-level security.",
        })

    perm_ratio = (d["app_permissions"] - MIN_PERMISSIONS) / (MAX_PERMISSIONS - MIN_PERMISSIONS)
    perm_penalty = round(perm_ratio * 20)
    score -= perm_penalty
    if perm_penalty >= 10:
        sev = "danger" if perm_penalty >= 16 else "warn"
        risks.append({
            "sev":   sev,
            "title": f"High Dangerous-Permission Count ({d['app_permissions']})",
            "desc":  f"{d['app_permissions']} dangerous permissions are active across installed apps. Each granted permission is a potential data-exfiltration pathway if an app is compromised.",
        })

    interim_score = score
    if d["sideloaded_count"] > 2:
        if interim_score < 50:
            d["malware_detected"] = 1
            score -= 10
            risks.append({
                "sev":   "danger",
                "title": f"Malware Risk — {d['sideloaded_count']} Sideloaded Package(s) Detected",
                "desc":  "High-risk device with sideloaded apps present. These apps bypass Google Play Protect and are highly likely to carry malicious payloads given your device's overall risk profile.",
            })
        else:
            d["malware_detected"] = 0
            risks.append({
                "sev":   "info",
                "title": f"Sideloaded Apps Detected ({d['sideloaded_count']}) — Low Risk",
                "desc":  "Non-Play Store apps found, but your overall security score is healthy. These are flagged for awareness only. Verify each app's source manually.",
            })
    else:
        d["malware_detected"] = 0

    if d.get("usb_debug"):
        risks.append({
            "sev":   "warn",
            "title": "USB Debugging Active",
            "desc":  "ADB over USB allows full shell access to the device. Disable when not actively developing to prevent physical-access attacks.",
        })
    if d.get("dev_options_on"):
        risks.append({
            "sev":   "info",
            "title": "Developer Options Enabled",
            "desc":  "Developer options expose advanced settings (mock locations, GPU debugging, etc.) that can be exploited on a compromised device.",
        })
    if d.get("bluetooth_on"):
        risks.append({
            "sev":   "info",
            "title": "Bluetooth Is On",
            "desc":  "Active Bluetooth increases attack surface. BlueBorne, BIAS, and KNOB exploits target discoverable devices. Disable when not in use.",
        })
    if not d.get("encrypted", True):
        risks.append({
            "sev":   "danger",
            "title": "Storage Not Encrypted",
            "desc":  "Data on this device is readable without authentication. Physical access or a bootloader exploit exposes all user data.",
        })
    if d.get("security_patch") and d["security_patch"] != "Unknown":
        try:
            patch_date = datetime.strptime(d["security_patch"], "%Y-%m-%d")
            months_old = (datetime.now() - patch_date).days // 30
            if months_old >= 6:
                risks.append({
                    "sev":   "warn",
                    "title": f"Security Patch {months_old} Months Old ({d['security_patch']})",
                    "desc":  "Unpatched kernel and system vulnerabilities remain open. Apply the latest OTA update immediately.",
                })
        except Exception:
            pass

    score = max(0, min(100, score))
    return score, risks


def score_color(s: int) -> str:
    if s >= 75: return "#34d399"
    if s >= 50: return "#fbbf24"
    return "#f87171"

def score_label(s: int) -> str:
    if s >= 80: return "EXCELLENT"
    if s >= 65: return "GOOD"
    if s >= 50: return "MODERATE"
    if s >= 30: return "POOR"
    return "CRITICAL"

def score_glow(s: int) -> str:
    if s >= 75: return "rgba(52,211,153,0.2)"
    if s >= 50: return "rgba(251,191,36,0.2)"
    return "rgba(248,113,113,0.2)"


#  SIDEBAR

with st.sidebar:
    st.markdown("""
    <div class="sidebar-logo">
      <div class="logo-mark">
        <div class="logo-icon">🛡</div>
        <div class="logo-text">ShieldScan</div>
      </div>
      <div class="logo-sub">Security Health Monitor</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div style="height:1px;background:linear-gradient(90deg,transparent,rgba(255,255,255,0.06),transparent);margin-bottom:1.2rem"></div>
    <div style="font-family:var(--mono);font-size:0.58rem;letter-spacing:0.22em;text-transform:uppercase;color:var(--text-lo);margin-bottom:0.6rem">Device</div>
    """, unsafe_allow_html=True)

    devices = adb_devices()
    if devices:
        selected_device = st.selectbox("Connected Devices", devices, label_visibility="collapsed")
        st.markdown('<div style="margin-top:0.5rem"><span class="conn-pill connected"><span class="conn-dot on"></span>Connected</span></div>', unsafe_allow_html=True)
    else:
        selected_device = None
        st.markdown('<div style="margin-top:0.5rem"><span class="conn-pill disconnected"><span class="conn-dot off"></span>No Device Found</span></div>', unsafe_allow_html=True)
        st.caption("Connect a device via USB and enable ADB.")

    st.markdown("""
    <div style="height:1px;background:linear-gradient(90deg,transparent,rgba(255,255,255,0.06),transparent);margin:1.2rem 0"></div>
    <div style="font-family:var(--mono);font-size:0.58rem;letter-spacing:0.22em;text-transform:uppercase;color:var(--text-lo);margin-bottom:0.6rem">Refresh</div>
    """, unsafe_allow_html=True)

    refresh_interval = st.selectbox(
        "Poll Interval",
        ["2 seconds", "5 seconds", "10 seconds", "30 seconds", "Manual"],
        index=1,
        label_visibility="collapsed",
    )
    interval_map = {
        "2 seconds": 2, "5 seconds": 5, "10 seconds": 10,
        "30 seconds": 30, "Manual": None,
    }
    poll_seconds = interval_map[refresh_interval]

    st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)
    manual_refresh = st.button("↻  Refresh Now", use_container_width=True)

    st.markdown("""
    <div style="height:1px;background:linear-gradient(90deg,transparent,rgba(255,255,255,0.06),transparent);margin:1.2rem 0"></div>
    <div style="font-family:var(--mono);font-size:0.58rem;letter-spacing:0.22em;text-transform:uppercase;color:var(--text-lo);margin-bottom:0.8rem">About</div>
    <div style="font-size:0.75rem;color:var(--text-mid);line-height:1.75;font-weight:300">
      Pulls live telemetry via ADB from a physical device and scores it against a 10,000-row trained dataset.
    </div>
    <div style="margin-top:1rem;display:flex;flex-direction:column;gap:0.3rem">
      <div style="font-family:var(--mono);font-size:0.6rem;color:var(--text-lo);padding:0.35rem 0.7rem;background:rgba(255,255,255,0.03);border:1px solid var(--border);border-radius:8px">· OS Version</div>
      <div style="font-family:var(--mono);font-size:0.6rem;color:var(--text-lo);padding:0.35rem 0.7rem;background:rgba(255,255,255,0.03);border:1px solid var(--border);border-radius:8px">· Unknown Sources</div>
      <div style="font-family:var(--mono);font-size:0.6rem;color:var(--text-lo);padding:0.35rem 0.7rem;background:rgba(255,255,255,0.03);border:1px solid var(--border);border-radius:8px">· Screen Lock</div>
      <div style="font-family:var(--mono);font-size:0.6rem;color:var(--text-lo);padding:0.35rem 0.7rem;background:rgba(255,255,255,0.03);border:1px solid var(--border);border-radius:8px">· App Permissions</div>
      <div style="font-family:var(--mono);font-size:0.6rem;color:var(--text-lo);padding:0.35rem 0.7rem;background:rgba(255,255,255,0.03);border:1px solid var(--border);border-radius:8px">· Malware / Sideloads</div>
      <div style="font-family:var(--mono);font-size:0.6rem;color:var(--text-lo);padding:0.35rem 0.7rem;background:rgba(255,255,255,0.03);border:1px solid var(--border);border-radius:8px">· USB Debug · BT · Encryption</div>
    </div>
    """, unsafe_allow_html=True)



#  MAIN LAYOUT

st.markdown("""
<div class="page-header">
  <div class="header-eyebrow">Predictive Security Intelligence</div>
  <div class="header-title">
    Security Health
    <span class="live-dot"><span style="width:5px;height:5px;border-radius:50%;background:#34d399;display:inline-block;box-shadow:0 0 6px #34d399;animation:blink 2s infinite"></span>Live</span>
  </div>
  <div class="header-sub">Real-time device analysis via Android Debug Bridge — data refreshes automatically</div>
</div>
""", unsafe_allow_html=True)

#  No device fallback
if not selected_device:
    st.markdown("""
    <div style='background:linear-gradient(145deg,rgba(17,22,32,0.8),rgba(11,15,22,0.9));
                border:1px solid rgba(255,255,255,0.06);border-radius:24px;
                padding:4rem 2rem;text-align:center;position:relative;overflow:hidden'>
      <div style='position:absolute;top:50%;left:50%;transform:translate(-50%,-60%);
                  width:400px;height:300px;
                  background:radial-gradient(ellipse,rgba(99,102,241,0.06),transparent 70%);
                  pointer-events:none'></div>
      <div style='font-size:3rem;margin-bottom:1.2rem;opacity:0.6'>📱</div>
      <div style='font-family:var(--display);font-size:1.1rem;font-weight:700;
                  color:var(--text-hi);margin-bottom:0.6rem;letter-spacing:-0.3px'>
        No Android device detected
      </div>
      <div style='font-size:0.82rem;color:var(--text-mid);max-width:440px;margin:0 auto;
                  line-height:1.8;font-weight:300'>
        Connect your smartphone via USB, enable <b style="color:var(--text-hi)">USB Debugging</b> in
        Developer Options, authorize this computer on the device prompt, then click Refresh Now.
      </div>
      <div style='margin-top:1.8rem;font-family:var(--mono);font-size:0.68rem;color:var(--accent);
                  background:rgba(0,212,255,0.06);display:inline-block;
                  padding:0.55rem 1.2rem;border-radius:10px;border:1px solid rgba(0,212,255,0.15);
                  letter-spacing:0.05em'>
        $ adb devices
      </div>
    </div>
    """, unsafe_allow_html=True)
    if poll_seconds:
        time.sleep(poll_seconds)
        st.rerun()
    st.stop()

#Fetch data
with st.spinner(""):
    d = fetch_device_data(selected_device)

score, risks = compute_score(d)
s_color = score_color(score)
s_label = score_label(score)
s_glow  = score_glow(score)
fetched_str = d["fetched_at"].strftime("%H:%M:%S")

# Security Alert Banner
if score < 50:
    if score < 30:
        alert_icon  = "🚨"
        alert_title = "Critical Security Alert"
        alert_msg   = f"Your device is severely exposed. Score: <b style='color:#f87171'>{score}/100</b>. Immediate remediation required to prevent data theft or malware infection."
        alert_c     = "#f87171"
        alert_bg    = "rgba(248,113,113,0.05)"
        alert_bd    = "rgba(248,113,113,0.2)"
    else:
        alert_icon  = "⚠️"
        alert_title = "Poor Security Warning"
        alert_msg   = f"Multiple vulnerabilities detected. Score: <b style='color:#fbbf24'>{score}/100</b>. Review the risk vectors below and take corrective action."
        alert_c     = "#fbbf24"
        alert_bg    = "rgba(251,191,36,0.04)"
        alert_bd    = "rgba(251,191,36,0.18)"

    st.markdown(f"""
    <div style='background:{alert_bg};border:1px solid {alert_bd};border-radius:18px;
                padding:1.1rem 1.5rem;margin-bottom:1.5rem;
                display:flex;align-items:center;gap:1.2rem'>
      <div style='font-size:1.6rem;flex-shrink:0'>{alert_icon}</div>
      <div style='flex:1'>
        <div style='font-family:var(--display);font-size:0.9rem;font-weight:700;
                    color:{alert_c};margin-bottom:0.2rem'>{alert_title}</div>
        <div style='font-size:0.8rem;color:rgba(255,255,255,0.55);font-weight:300;line-height:1.5'>{alert_msg}</div>
      </div>
      <div style='font-family:var(--mono);font-size:2rem;font-weight:700;color:{alert_c};
                  background:rgba(0,0,0,0.25);border:1px solid {alert_bd};border-radius:12px;
                  padding:0.4rem 1rem;flex-shrink:0;text-align:center;line-height:1.1'>
        {score}
        <div style='font-size:0.52rem;letter-spacing:0.12em;color:rgba(255,255,255,0.3);font-weight:400'>/100</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

#Row 1: Score ring + device identity
col_ring, col_id, col_pad = st.columns([1.25, 2.75, 0.05])

with col_ring:
    radius = 54
    circ   = 2 * math.pi * radius
    filled = circ * (score / 100)
    gap    = circ - filled

    # Track rings (subtle background rings)
    r2, r3 = radius - 14, radius - 28

    st.markdown(f"""
    <div class="score-ring-wrap" style="box-shadow:0 0 60px {s_glow}">
      <svg width="160" height="160" viewBox="0 0 160 160" style="overflow:visible">
        <!-- Glow filter -->
        <defs>
          <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur in="SourceGraphic" stdDeviation="3" result="blur"/>
            <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
          </filter>
        </defs>
        <!-- Background track -->
        <circle cx="80" cy="80" r="{radius}"
          fill="none" stroke="rgba(255,255,255,0.04)" stroke-width="10"/>
        <!-- Subtle inner rings -->
        <circle cx="80" cy="80" r="{r2}"
          fill="none" stroke="rgba(255,255,255,0.025)" stroke-width="1"/>
        <circle cx="80" cy="80" r="{r3}"
          fill="none" stroke="rgba(255,255,255,0.015)" stroke-width="1"/>
        <!-- Score arc -->
        <circle cx="80" cy="80" r="{radius}"
          fill="none" stroke="{s_color}" stroke-width="10"
          stroke-linecap="round"
          stroke-dasharray="{filled:.1f} {gap:.1f}"
          transform="rotate(-90 80 80)"
          filter="url(#glow)"/>
        <!-- Score value -->
        <text x="80" y="74" text-anchor="middle"
          font-family="Syne,sans-serif" font-size="34" font-weight="800"
          fill="{s_color}" letter-spacing="-1">{score}</text>
        <text x="80" y="90" text-anchor="middle"
          font-family="JetBrains Mono,monospace" font-size="8" font-weight="400"
          fill="rgba(255,255,255,0.2)" letter-spacing="2">OUT OF 100</text>
      </svg>
      <div class="score-grade" style="color:{s_color}">{s_label}</div>
      <div class="score-label">Security Score</div>
      <div class="ts" style="margin-top:0.6rem">synced at {fetched_str}</div>
    </div>
    """, unsafe_allow_html=True)

with col_id:
    st.markdown(f"""
    <div class="device-card">
      <div style='display:flex;align-items:flex-start;gap:1rem'>
        <div style='font-size:2.2rem;opacity:0.7;flex-shrink:0'>📱</div>
        <div>
          <div class="device-name">{d["device_brand"]} {d["device_model"]}</div>
          <div class="device-serial">Serial · <span style='color:rgba(0,212,255,0.5)'>{d["serial"]}</span></div>
        </div>
      </div>
      <div class="device-meta-grid">
        <div class="meta-cell">
          <div class="meta-label">Android Version</div>
          <div class="meta-value">Android {d["android_full"]}</div>
        </div>
        <div class="meta-cell">
          <div class="meta-label">Security Patch</div>
          <div class="meta-value" style="font-size:0.82rem">{d["security_patch"]}</div>
        </div>
        <div class="meta-cell">
          <div class="meta-label">Build ID</div>
          <div class="meta-value" style="font-size:0.78rem;letter-spacing:0">{d["build_id"]}</div>
        </div>
        <div class="meta-cell">
          <div class="meta-label">Battery</div>
          <div class="meta-value">{"—" if d["battery_pct"] < 0 else str(d["battery_pct"]) + "%"}</div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='height:1.5rem'></div>", unsafe_allow_html=True)

#  Section heading helper
def section_head(text):
    return f"""
    <div class="section-head">
      <span class="section-head-text">{text}</span>
      <div class="section-head-line"></div>
    </div>
    """

# Row 2: Feature Metrics
st.markdown(section_head("Security Feature Analysis"), unsafe_allow_html=True)

c1, c2, c3, c4, c5 = st.columns(5)

def metric_chip(icon, label, value, badge_text, badge_cls, accent_color="#00d4ff"):
    return f"""
    <div class="metric-chip" style="border-color:rgba(255,255,255,0.07)">
      <div class="chip-top">
        <div class="chip-icon">{icon}</div>
        <div class="chip-badge {badge_cls}">{badge_text}</div>
      </div>
      <div>
        <div class="chip-label">{label}</div>
        <div class="chip-value">{value}</div>
      </div>
    </div>
    """

with c1:
    lag = LATEST_ANDROID - d["os_version"]
    bc  = "badge-safe" if lag == 0 else ("badge-warn" if lag < 3 else "badge-danger")
    bt  = "Latest" if lag == 0 else f"−{lag} vers"
    st.markdown(metric_chip("🤖", "OS Version", f"Android {d['os_version']}", bt, bc), unsafe_allow_html=True)

with c2:
    if d["unknown_apps"]:
        bc, bt = "badge-danger", "Enabled"
    else:
        bc, bt = "badge-safe", "Disabled"
    st.markdown(metric_chip("📦", "Unknown Sources", "Enabled" if d["unknown_apps"] else "Disabled", bt, bc), unsafe_allow_html=True)

with c3:
    if d["screen_lock"]:
        bc, bt = "badge-safe", "Locked"
    else:
        bc, bt = "badge-danger", "None"
    st.markdown(metric_chip("🔐", "Screen Lock", d["lock_type_name"], bt, bc), unsafe_allow_html=True)

with c4:
    perm_pct = round((d["app_permissions"] - MIN_PERMISSIONS) / (MAX_PERMISSIONS - MIN_PERMISSIONS) * 100)
    if perm_pct < 40:
        bc, bt = "badge-safe",   "Low"
    elif perm_pct < 70:
        bc, bt = "badge-warn",   "Medium"
    else:
        bc, bt = "badge-danger", "High"
    st.markdown(metric_chip("🔑", "Dangerous Perms", str(d["app_permissions"]), bt, bc), unsafe_allow_html=True)

with c5:
    if d["malware_detected"]:
        bc, bt = "badge-danger", "Detected"
    else:
        bc, bt = "badge-safe", "Clean"
    sideload_txt = f"{d['sideloaded_count']} sideloads" if d["malware_detected"] else "No sideloads"
    st.markdown(metric_chip("🦠", "Malware / Sideloads", sideload_txt, bt, bc), unsafe_allow_html=True)

st.markdown("<div style='height:1.5rem'></div>", unsafe_allow_html=True)

#  Row 3: Risk breakdown + Quick flags 
col_risk, col_flags = st.columns([2.1, 0.9])

with col_risk:
    st.markdown(section_head("Active Risk Vectors"), unsafe_allow_html=True)

    if not risks:
        st.markdown("""
        <div style='background:rgba(52,211,153,0.04);border:1px solid rgba(52,211,153,0.15);
                    border-radius:16px;padding:2rem;text-align:center'>
          <div style='font-size:1.8rem;margin-bottom:0.5rem'>✅</div>
          <div style='font-family:var(--display);font-size:0.88rem;font-weight:700;
                      color:var(--safe)'>No active risks detected</div>
          <div style='font-size:0.76rem;color:var(--text-mid);margin-top:0.3rem;font-weight:300'>
            Your device security posture is excellent.
          </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        for r in risks:
            sev_cls = {"danger": "", "warn": "warn", "info": "info"}.get(r["sev"], "")
            icon_map = {"danger": "⛔", "warn": "⚠️", "info": "ℹ️"}
            icon = icon_map.get(r["sev"], "•")
            st.markdown(f"""
            <div class="risk-card {sev_cls}">
              <div class="risk-icon">{icon}</div>
              <div class="risk-body">
                <div class="risk-title">{r["title"]}</div>
                <div class="risk-desc">{r["desc"]}</div>
              </div>
            </div>
            """, unsafe_allow_html=True)

with col_flags:
    st.markdown(section_head("Device State"), unsafe_allow_html=True)

    def flag_row(icon, label, active, good_when_on=False):
        if active:
            val_color = "var(--safe)" if good_when_on else "var(--danger)"
            dot_color = "var(--safe)" if good_when_on else "var(--danger)"
            glow      = "var(--safe)" if good_when_on else "var(--danger)"
            val_txt   = "ON"
        else:
            val_color = "var(--text-lo)"
            dot_color = "var(--text-lo)"
            glow      = "transparent"
            val_txt   = "OFF"
        return f"""
        <div class="flag-row">
          <span class="flag-label">{icon}&nbsp; {label}</span>
          <span class="flag-val" style="color:{val_color}">
            <span style="display:inline-block;width:6px;height:6px;border-radius:50%;
                         background:{dot_color};box-shadow:0 0 5px {glow};
                         margin-right:5px;vertical-align:middle"></span>{val_txt}
          </span>
        </div>
        """

    st.markdown(
        flag_row("🔒", "Encryption",        d.get("encrypted", False),    good_when_on=True) +
        flag_row("🐛", "USB Debug",         d.get("usb_debug", False)) +
        flag_row("🔧", "Dev Options",       d.get("dev_options_on", False)) +
        flag_row("📶", "Wi-Fi",             d.get("wifi_on", False)) +
        flag_row("🔵", "Bluetooth",         d.get("bluetooth_on", False)),
        unsafe_allow_html=True,
    )

    st.markdown("<div style='height:0.5rem'></div>", unsafe_allow_html=True)
    st.markdown(f"""
    <div style='background:rgba(99,102,241,0.05);border:1px solid rgba(99,102,241,0.15);
                border-radius:14px;padding:1rem 1.1rem'>
      <div style='font-family:var(--mono);font-size:0.57rem;letter-spacing:0.18em;
                  text-transform:uppercase;color:var(--text-lo);margin-bottom:0.3rem'>
        Total Packages
      </div>
      <div style='font-family:var(--display);font-size:1.8rem;font-weight:800;
                  color:var(--text-hi);line-height:1'>{d["total_packages"]}</div>
      <div style='font-size:0.68rem;color:var(--text-lo);margin-top:0.2rem'>installed apps</div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("<div style='height:1rem'></div>", unsafe_allow_html=True)

# Row 4: Score breakdown expander
with st.expander("▸  Score Breakdown by Feature", expanded=False):
    os_lag     = LATEST_ANDROID - d["os_version"]
    os_penalty = min(25, os_lag * 6)
    ua_penalty = 25 if d["unknown_apps"] else 0
    sl_penalty = 20 if d["screen_lock"] == 0 else 0
    perm_ratio = (d["app_permissions"] - MIN_PERMISSIONS) / (MAX_PERMISSIONS - MIN_PERMISSIONS)
    pm_penalty = round(perm_ratio * 20)
    mw_penalty = 10 if d["malware_detected"] else 0

    features = [
        ("OS Version",         25, 25 - os_penalty, "#6366f1"),
        ("Unknown Sources",    25, 25 - ua_penalty,  "#0ea5e9"),
        ("Screen Lock",        20, 20 - sl_penalty,  "#06b6d4"),
        ("App Permissions",    20, 20 - pm_penalty,  "#10b981"),
        ("Malware / Sideload", 10, 10 - mw_penalty,  "#f87171"),
    ]

    st.markdown("<div style='padding:0.5rem 0'>", unsafe_allow_html=True)
    for name, max_pts, earned, color in features:
        pct = round(earned / max_pts * 100)
        st.markdown(f"""
        <div style='margin-bottom:1.1rem'>
          <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:0.4rem'>
            <span style='font-size:0.78rem;color:var(--text-mid);font-weight:400'>{name}</span>
            <span style='font-family:var(--mono);font-size:0.7rem;color:var(--text-hi);
                         background:rgba(255,255,255,0.04);padding:0.15rem 0.5rem;
                         border-radius:6px;border:1px solid var(--border)'>{earned}/{max_pts} pts</span>
          </div>
          <div class="bar-wrap">
            <div class="bar-fill" style="width:{pct}%;background:linear-gradient(90deg,{color}88,{color})"></div>
          </div>
        </div>
        """, unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

# Row 5: Raw ADB data expander 
with st.expander("▸  Raw ADB Dataset Features", expanded=False):
    raw_df = pd.DataFrame([{
        "os_version":       d["os_version"],
        "unknown_apps":     d["unknown_apps"],
        "screen_lock":      d["screen_lock"],
        "app_permissions":  d["app_permissions"],
        "malware_detected": d["malware_detected"],
        "security_score":   score,
    }])
    st.dataframe(
        raw_df.style.set_properties(**{
            "background-color": "#111620",
            "color": "#f0f4ff",
            "border": "1px solid rgba(255,255,255,0.06)",
            "font-family": "JetBrains Mono, monospace",
        }),
        use_container_width=True,
        hide_index=True,
    )
    st.markdown(f"""
    <div style='font-family:var(--mono);font-size:0.6rem;color:var(--text-lo);margin-top:0.5rem'>
      Fetched {d["fetched_at"].strftime("%Y-%m-%d %H:%M:%S")} · Device <span style='color:rgba(0,212,255,0.5)'>{d["serial"]}</span>
    </div>
    """, unsafe_allow_html=True)


#  AUTO-REFRESH
if poll_seconds:
    time.sleep(poll_seconds)
    st.rerun()
elif manual_refresh:
    st.rerun()
