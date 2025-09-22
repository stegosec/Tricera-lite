from fastapi import FastAPI, UploadFile, File
from fastapi.responses import HTMLResponse
import os
import httpx
import uvicorn

APP_NAME = "TriceraAudit Lite (Web)"
API_BASE = os.getenv("API_BASE_URL", "http://api:8080")
TIMEOUT = float(os.getenv("WEB_TIMEOUT", "30"))

app = FastAPI(title=APP_NAME)

INDEX_HTML = """
<!doctype html><html><head><meta charset="utf-8"/>
<title>TriceraAudit Lite — Web</title>
<style>
body{font-family:system-ui,Segoe UI,Roboto,Ubuntu,Arial;background:#0b1020;color:#e9ecf1;margin:0}
.container{max-width:900px;margin:32px auto;padding:0 16px}
.card{background:#111833;padding:20px;border-radius:16px;margin-bottom:16px;box-shadow:0 10px 30px rgba(0,0,0,.3)}
.small{color:#9aa3b2}
button{background:#3551e0;color:#fff;border:0;border-radius:12px;padding:10px 14px;cursor:pointer}
button[disabled]{opacity:.6;cursor:not-allowed}
input[type=file]{display:block;width:100%;padding:10px;border:1px dashed #2a3561;border-radius:10px;background:#0c1430;color:#e9ecf1}
.lock{filter:grayscale(1)}
pre{white-space:pre-wrap;background:#0c1430;padding:10px;border-radius:10px}
a{color:#6ee7ff;text-decoration:none}
</style>
</head><body><div class="container">
  <div class="card"><h2>🦖 TriceraAudit Lite — Web</h2>
    <p class="small">Solo se permite <b>1</b> archivo con extensión <code>.config</code>. Archivos no Fortinet serán rechazados.</p>
    <form action="/scan" method="post" enctype="multipart/form-data">
      <input name="file" type="file" accept=".conf" required />
      <div style="margin-top:10px"><button type="submit">Escanear</button></div>
    </form>
  </div>
  <div class="card">
    <h3>Funciones PRO</h3>
    <p><button class="lock" disabled title="Disponible solo en PRO">🔒 Subida múltiple</button></p>
    <p><button class="lock" disabled title="Disponible solo en PRO">🔒 Tokens de API</button></p>
    <p><button class="lock" disabled title="Disponible solo en PRO">🔒 Detalle PSIRT/CVE</button></p>
    <p class="small">Estas características están bloqueadas en Lite.</p>
  </div>
</div></body></html>
"""

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(INDEX_HTML)

@app.post("/scan", response_class=HTMLResponse)
async def scan(file: UploadFile = File(...)):
    content = await file.read()
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        r = await client.post(
            f"{API_BASE}/scan",
            files={"file": (file.filename, content, file.content_type or "text/plain")}
        )
    if r.status_code != 200:
        return HTMLResponse(
            f"<div class='container'><div class='card'><h3>Error</h3><pre>{r.text}</pre><a href='/'>← Volver</a></div></div>",
            status_code=r.status_code
        )
    data = r.json()
    findings = "\n".join([f"- [{f['severity'].upper()}] {f['title']}" for f in data.get("findings", [])]) or "Sin hallazgos."
    psirt = "\n".join([f"- {p['id']} [{p['severity'].upper()}] — {p['summary']}" for p in data.get("psirt_summary", [])]) or "Sin entradas PSIRT locales."
    html = f"""
    <div class='container'>
      <div class='card'><h2>Resultado — TriceraAudit Lite</h2>
        <p class='small'>Archivo: <b>{data.get('file')}</b> | Hostname: {data.get('hostname') or 'N/A'} | Firmware: {data.get('firmware') or 'N/D'}</p>
        <h3>Hallazgos</h3><pre>{findings}</pre>
        <h3>PSIRT (resumen corto)</h3><pre>{psirt}</pre>
        <a href='/'>← Nuevo escaneo</a>
      </div>
    </div>
    """
    return HTMLResponse(html)

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000)

