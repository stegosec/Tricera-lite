import os
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
import httpx, uvicorn

# ⬇️ CAMBIO: importar módulo del mismo folder sin punto relativo
from validators import (
    sanitize_filename, is_allowed_extension, is_suspicious_name,
    is_likely_text, seems_fortinet_conf, extract_firmware_version, extract_hostname
)

APP_NAME = "TriceraAudit Lite (API)"
SCANNER_URL = os.getenv("SCANNER_URL", "http://scanner:8090")
MAX_FILE_BYTES = int(os.getenv("MAX_FILE_BYTES", str(5*1024*1024)))  # 5MB
LITE_MODE = os.getenv("LITE_MODE", "true").lower() == "true"
TIMEOUT = float(os.getenv("API_TIMEOUT", "30"))

app = FastAPI(title=APP_NAME)

@app.post("/scan")
async def scan(file: UploadFile = File(...)):
    data = await file.read()
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="payload_too_large")
    fname = sanitize_filename(file.filename)
    if not is_allowed_extension(fname) or is_suspicious_name(fname):
        raise HTTPException(status_code=400, detail="invalid_extension")
    if not is_likely_text(data):
        raise HTTPException(status_code=400, detail="invalid_file_content")
    text = data.decode("utf-8", errors="ignore")
    if not seems_fortinet_conf(text):
        raise HTTPException(status_code=400, detail="not_fortinet_config")

    # Reenvía al scanner (single-file)
    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        r = await client.post(f"{SCANNER_URL}/scan", json={
            "file_name": fname,
            "content": text
        })
    return JSONResponse(r.json(), status_code=r.status_code)

@app.post("/scan-multi")
async def scan_multi():
    if LITE_MODE:
        raise HTTPException(status_code=403, detail={"error":"feature_locked_pro","message":"Multi-file upload is PRO"})
    raise HTTPException(status_code=501, detail="not_implemented")

@app.get("/tokens")
async def tokens():
    if LITE_MODE:
        raise HTTPException(status_code=403, detail={"error":"feature_locked_pro","message":"API tokens are PRO"})
    raise HTTPException(status_code=501, detail="not_implemented")

if __name__ == "__main__":
    uvicorn.run("api:app", host="0.0.0.0", port=8080)

