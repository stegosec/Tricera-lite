from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import uvicorn, os, re, yaml

from psirt_db import lookup_psirt_for_version

APP_TITLE   = "TriceraAudit Lite (Scanner)"
APP_VERSION = "0.1.2"
RULES_PATH  = os.getenv("RULES_PATH", "/app/rules/fortinet_baseline.yml")

app = FastAPI(title=APP_TITLE, version=APP_VERSION)

# ---------- Helpers ----------
def load_rules():
    with open(RULES_PATH, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)

def preprocess_text(raw: str) -> str:
    """
    - Quita líneas que empiezan con '#'
    - Ofusca payloads dentro de set script "..."
    (Evita falsos positivos y previene que contenido tipo 'script' dispare reglas por accidente)
    """
    # 1) eliminar comentarios de línea
    lines = [ln for ln in raw.splitlines() if not ln.strip().startswith("#")]
    txt = "\n".join(lines)
    # 2) ofuscar set script "...."
    txt = re.sub(r'(?is)(set\s+script\s*")((?:\\.|[^"])*?)(")', r'\1<redacted>\3', txt)
    return txt

def evaluate_text_rules(text: str, ruleset):
    findings = []
    for r in ruleset.get("rules", []):
        ok = False
        m = r.get("match", {})
        # contains
        for c in m.get("any_of", []):
            if "contains" in c and c["contains"].lower() in text.lower():
                ok = True
        # regex
        if not ok and "regex" in m:
            if re.search(m["regex"], text):
                ok = True
        if ok:
            findings.append({
                "rule_id": r["id"],
                "title": r["title"],
                "severity": r["severity"],
                "remediation": r.get("remediation"),
            })
    return findings

def extract_firmware_version(text: str):
    """
    Devuelve algo tipo 'v7.4.8' si encuentra una versión FortiOS en:
      - #config-version=FWF40F-7.4.8-FW-build2795-...
      - # config-version: v7.0.5
      - # build v6.4.3
      - set version v7.2.4   /   set ver 7.2.4
      - FWF40F-7.4.8-FW (patrón genérico)
    """
    patterns = [
        r"(?im)^\s*#\s*config-version\s*[:=]\s*.*?([vV]?\d+\.\d+(?:\.\d+)?)",
        r"(?im)^\s*#\s*(?:version|build)\s*[:=]?\s*([vV]?\d+\.\d+(?:\.\d+)?)",
        r"(?i)\bset\s+(?:version|ver)\s+([vV]?\d+\.\d+(?:\.\d+)?)",
        r"(?i)\bFW[A-Z0-9-]*[-_ ]([vV]?\d+\.\d+(?:\.\d+)?)\b",
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            v = m.group(1)
            if not v.lower().startswith("v"):
                v = f"v{v}"
            return v
    return None

def extract_hostname(text: str):
    m = re.search(r'set\s+hostname\s+"?([A-Za-z0-9._-]+)"?', text)
    return m.group(1) if m else None

# ---------- Endpoints ----------
@app.get("/healthz")
def healthz():
    return {"ok": True, "service": "scanner", "version": APP_VERSION}

@app.get("/rules")
def rules_info():
    rs = load_rules()
    meta = rs.get("meta", {}) if isinstance(rs, dict) else {}
    return {"meta": meta, "rules_count": len(rs.get("rules", []))}

@app.post("/scan")
def scan(payload: dict):
    file_name = payload.get("file_name")
    content   = payload.get("content")
    if not file_name or content is None:
        raise HTTPException(status_code=400, detail="invalid_payload")

    # 1) cargar reglas
    rules = load_rules()

    # 2) extraer versión del texto *crudo* (porque muchas veces viene en comentarios '#')
    fw = extract_firmware_version(content)

    # 3) preprocesar para aplicar reglas (sin comentarios y con 'script' ofuscado)
    clean = preprocess_text(content)

    # 4) extraer hostname y evaluar reglas sobre el texto preprocesado
    hostname = extract_hostname(clean)
    findings = evaluate_text_rules(clean, rules)

    # 5) PSIRT resumen corto
    psirt = lookup_psirt_for_version(fw)

    return JSONResponse({
        "file": file_name,
        "hostname": hostname,
        "firmware": fw,
        "findings": findings,
        "psirt_summary": [
            {"id": p["id"], "severity": p["severity"], "summary": p["summary"]}
            for p in psirt
        ]
    })

if __name__ == "__main__":
    uvicorn.run("scanner:app", host="0.0.0.0", port=8090)

