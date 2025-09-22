import re
from typing import List, Dict, Optional, Tuple

# === Mini base PSIRT (Lite) — SOLO RESUMEN ===
# Entradas de ejemplo para demo Lite (id/severidad/1 línea).
PSIRT_SHORT_DB: List[Dict] = [
    # 7.4.x
    {"id": "FG-PSIRT-2024-0741", "affects": "7.4.x", "severity": "high",
     "summary": "Vulnerabilidad en control de acceso web en escenarios específicos."},
    {"id": "FG-PSIRT-2024-0742", "affects": ">=7.4.0,<7.5.0", "severity": "medium",
     "summary": "Condición de denegación de servicio bajo carga anómala."},

    # 7.2.x
    {"id": "FG-PSIRT-2023-0723", "affects": "7.2.x", "severity": "critical",
     "summary": "Posible bypass de autenticación con módulos opcionales."},
    {"id": "FG-PSIRT-2023-0727", "affects": ">=7.2.0,<7.3.0", "severity": "high",
     "summary": "Exposición de información en API de administración."},

    # 7.0.x
    {"id": "FG-PSIRT-2023-0701", "affects": "7.0.x", "severity": "critical",
     "summary": "Autenticación remota no autorizada en condiciones poco comunes."},

    # 6.4.x
    {"id": "FG-PSIRT-2022-0645", "affects": "6.4.x", "severity": "high",
     "summary": "Bypass de control de acceso en GUI según opciones."},

    # 6.2.x
    {"id": "FG-PSIRT-2021-0628", "affects": "6.2.x", "severity": "medium",
     "summary": "Desbordamiento controlado por entrada externa."},

    # 6.0.x
    {"id": "FG-PSIRT-2020-0609", "affects": "6.0.x", "severity": "medium",
     "summary": "Validación insuficiente de parámetros en rutas infrecuentes."},

    # 5.6.x
    {"id": "FG-PSIRT-2019-0562", "affects": "5.6.x", "severity": "low",
     "summary": "Exposición de metadatos en escenarios de debug."},

    # genérico previo
    {"id": "FG-PSIRT-2023-0001", "affects": "7.0.x", "severity": "critical",
     "summary": "Autenticación remota no autorizada posible en condiciones específicas."},
]

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

def _parse_ver(v: str) -> Optional[Tuple[int,int,int]]:
    v = v.strip().lower().lstrip("v")
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?$", v)
    if not m: return None
    a, b, c = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
    return (a, b, c)

def _match_affects(fw: Tuple[int,int,int], affects: str) -> bool:
    affects = affects.strip().lower()
    # rama X.Y.x
    if "x" in affects and re.match(r"^\d+\.\d+\.x$", affects):
        major, minor = map(int, affects.replace(".x", "").split("."))
        return (fw[0], fw[1]) == (major, minor)
    # rango(s)
    if any(op in affects for op in (">=", "<=", "<", ">")):
        ok = True
        for cond in affects.split(","):
            cond = cond.strip()
            m = re.match(r"^(>=|<=|<|>)\s*(\d+\.\d+(?:\.\d+)?)$", cond)
            if not m: return False
            op, ver = m.group(1), _parse_ver(m.group(2))
            if not ver: return False
            if op == ">=" and not (fw >= ver): ok = False
            if op == "<=" and not (fw <= ver): ok = False
            if op == "<"  and not (fw <  ver): ok = False
            if op == ">"  and not (fw >  ver): ok = False
        return ok
    # fallback mayor.menor
    m2 = re.match(r"^(\d+)\.(\d+)$", affects)
    if m2:
        return (fw[0], fw[1]) == (int(m2.group(1)), int(m2.group(2)))
    return False

def lookup_psirt_for_version(fw_version: Optional[str]) -> List[Dict]:
    if not fw_version:
        return []
    fw_t = _parse_ver(fw_version)
    if not fw_t:
        return []
    matches = [p for p in PSIRT_SHORT_DB if _match_affects(fw_t, str(p.get("affects", "")))]
    if matches:
        matches.sort(key=lambda x: _SEV_ORDER.get(x["severity"], 9))
        return matches[:3]
    # si no hay match, devuelve 1-2 más severos como orientación
    db_sorted = sorted(PSIRT_SHORT_DB, key=lambda x: _SEV_ORDER.get(x["severity"], 9))
    return db_sorted[:2]

