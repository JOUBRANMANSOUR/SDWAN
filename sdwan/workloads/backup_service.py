"""HTTPS central backup repository for the controlled SD-WAN lab."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import uuid
from typing import Dict

from fastapi import FastAPI, HTTPException, Request

ROOT = Path(os.environ.get("SDWAN_BACKUP_ROOT", "/srv/backups"))
MAX_UPLOAD_BYTES = int(os.environ.get("SDWAN_BACKUP_MAX_BYTES", str(2 * 1024 * 1024 * 1024)))
BRANCH_ID = re.compile(r"[a-z][a-z0-9-]{0,31}")
app = FastAPI(title="Central Enterprise Backup Repository")
JOBS: Dict[str, Dict[str, object]] = {}


@app.get("/healthz")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "central_backup"}


@app.post("/backup/{branch_id}")
async def backup(branch_id: str, request: Request) -> Dict[str, object]:
    if not BRANCH_ID.fullmatch(branch_id):
        raise HTTPException(422, "branch_id must be a lowercase DNS-style identifier")
    started = datetime.now(timezone.utc)
    job_id = f"{branch_id}-{started:%Y%m%d%H%M%S}-{uuid.uuid4().hex[:8]}"
    directory = ROOT / branch_id
    temporary = directory / f".{job_id}.part"
    destination = directory / f"{job_id}.bin"
    digest, byte_count = hashlib.sha256(), 0
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with temporary.open("xb") as output:
            async for chunk in request.stream():
                if not chunk:
                    continue
                byte_count += len(chunk)
                if byte_count > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, "backup exceeds configured size limit")
                output.write(chunk)
                digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())
        temporary.replace(destination)
    except HTTPException:
        temporary.unlink(missing_ok=True)
        raise
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise HTTPException(507, f"backup storage failure: {exc.strerror or exc}") from exc
    completed = datetime.now(timezone.utc)
    record: Dict[str, object] = {
        "job_id": job_id, "branch": branch_id, "bytes": byte_count,
        "sha256": digest.hexdigest(), "status": "stored",
        "started_at": started.isoformat(), "completed_at": completed.isoformat(),
    }
    JOBS[job_id] = record
    (directory / f"{job_id}.json").write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    return record


@app.get("/backup/status/{job_id}")
def status(job_id: str) -> Dict[str, object]:
    record = JOBS.get(job_id)
    if record is None:
        for candidate in ROOT.glob("*/*.json"):
            if candidate.name != f"{job_id}.json":
                continue
            if candidate.is_file():
                record = json.loads(candidate.read_text(encoding="utf-8"))
                break
    if record is None:
        raise HTTPException(404, "backup job not found")
    return record
