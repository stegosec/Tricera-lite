import os, re

ALLOWED_EXT = {".conf"}

def sanitize_filename(filename: str) -> str:
    return os.path.basename(filename)

def is_allowed_extension(filename: str) -> bool:
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXT

def is_suspicious_name(filename: str) -> bool:
    lower = filename.lower()
    for token in [".exe.", ".dll.", ".jar.", ".sh.", ".bat.", ".ps1.", ".scr."]:
        if token in lower:
            return True
    return False

def is_likely_text(data: bytes) -> bool:
    if b"\x00" in data[:1024]:
        return False
    try:
        data[:4096].decode("utf-8")
        return True
    except Exception:
        return False

FORTI_HINTS = [
    "config system global",
    "config firewall policy",
    "config system interface",
    "config system snmp",
    "config vpn",
    "config router"
]

def seems_fortinet_conf(text: str) -> bool:
    t = text.lower()
    if any(h in t for h in FORTI_HINTS):
        return True
    if re.search(r"#\s*config-version", t):
        return True
    if "set admin" in t and "config system global" in t:
        return True
    return False

def extract_firmware_version(text: str):
    """
    Devuelve algo tipo 'v7.4.8' si encuentra una versión FortiOS en el texto.
    Soporta formatos:
      - #config-version=FWF40F-7.4.8-FW-build2795-250523:...
      - # config-version: v7.0.5
      - # build v6.4.3
      - set version v7.2.4   /   set ver 7.2.4
    """
    patterns = [
        # #config-version= ...  (o :) y capturar X.Y[.Z] en cualquier parte de esa línea
        r"(?im)^\s*#\s*config-version\s*[:=]\s*.*?([vV]?\d+\.\d+(?:\.\d+)?)",
        # # build v6.4.3  /  # version: 7.0.5
        r"(?im)^\s*#\s*(?:version|build)\s*[:=]?\s*([vV]?\d+\.\d+(?:\.\d+)?)",
        # set version v7.2.4  /  set ver 7.2.4
        r"(?i)\bset\s+(?:version|ver)\s+([vV]?\d+\.\d+(?:\.\d+)?)",
        # FWF40F-7.4.8-FW (patrón genérico por si viene en otra línea)
        r"(?i)\bFW[A-Z0-9-]*[-_ ]([vV]?\d+\.\d+(?:\.\d+)?)\b",
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            v = m.group(1)
            # Normaliza: que siempre devuelva con prefijo 'v'
            if not v.lower().startswith('v'):
                v = f"v{v}"
            return v
    return None
def extract_hostname(text: str):
    m = re.search(r'set\s+hostname\s+"?([A-Za-z0-9._-]+)"?', text)
    return m.group(1) if m else None

