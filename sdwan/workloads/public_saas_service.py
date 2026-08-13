"""Single public collaboration SaaS used by the core topology."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePath
import uuid
from typing import Dict

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse

ROOT = Path(os.environ.get("SDWAN_SAAS_ROOT", "/srv/public-saas"))
MAX_UPLOAD_BYTES = int(os.environ.get("SDWAN_SAAS_MAX_BYTES", str(512 * 1024 * 1024)))
FILES = ROOT / "files"
MESSAGES = ROOT / "messages.jsonl"
app = FastAPI(title="Public SaaS Collaboration Service")


def _safe_name(value: str) -> str:
    name = PurePath(value).name
    if not name or name in {".", ".."} or len(name) > 128:
        raise HTTPException(422, "invalid filename")
    return name


@app.get("/healthz")
@app.get("/api/status")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "public_saas"}


@app.get("/api/messages")
def messages() -> Dict[str, object]:
    if not MESSAGES.is_file():
        return {"messages": []}
    rows = [json.loads(line) for line in MESSAGES.read_text(encoding="utf-8").splitlines()[-100:] if line]
    return {"messages": rows}


@app.post("/api/messages")
async def post_message(request: Request) -> Dict[str, object]:
    body = await request.json()
    text = str(body.get("message", "")).strip() if isinstance(body, dict) else ""
    if not text or len(text) > 2000:
        raise HTTPException(422, "message must be 1..2000 characters")
    record = {"id": uuid.uuid4().hex, "message": text, "created_at": datetime.now(timezone.utc).isoformat()}
    ROOT.mkdir(parents=True, exist_ok=True)
    with MESSAGES.open("a", encoding="utf-8") as output:
        output.write(json.dumps(record, sort_keys=True) + "\n")
    return record


@app.post("/files/upload")
async def upload(request: Request) -> Dict[str, object]:
    name = _safe_name(request.headers.get("x-filename", "upload.bin"))
    FILES.mkdir(parents=True, exist_ok=True)
    temporary, destination = FILES / f".{uuid.uuid4().hex}.part", FILES / name
    digest, size = hashlib.sha256(), 0
    try:
        with temporary.open("xb") as output:
            async for chunk in request.stream():
                if chunk:
                    size += len(chunk)
                    if size > MAX_UPLOAD_BYTES:
                        raise HTTPException(413, "upload exceeds configured size limit")
                    output.write(chunk)
                    digest.update(chunk)
        temporary.replace(destination)
    except HTTPException:
        temporary.unlink(missing_ok=True)
        raise
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise HTTPException(507, f"SaaS storage failure: {exc.strerror or exc}") from exc
    return {"filename": name, "bytes": size, "sha256": digest.hexdigest(), "status": "stored"}


@app.get("/files/{filename}")
def download(filename: str) -> FileResponse:
    path = FILES / _safe_name(filename)
    if not path.is_file():
        raise HTTPException(404, "file not found")
    return FileResponse(path)
