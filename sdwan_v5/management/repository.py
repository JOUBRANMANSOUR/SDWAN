"""Read-only service database access and isolated management audit storage."""
from __future__ import annotations

import json, sqlite3
from pathlib import Path
from typing import Any

def _ro(path: Path) -> sqlite3.Connection | None:
    if not path.is_file(): return None
    connection = sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection

class ReadOnlyState:
    def __init__(self, policy_db: Path, ztp_db: Path): self.policy_db, self.ztp_db = policy_db, ztp_db
    def rows(self, source: str, query: str, parameters: tuple = ()) -> list[dict[str, Any]]:
        path = self.policy_db if source == "policy" else self.ztp_db
        db = _ro(path)
        if db is None: return []
        try: return [dict(row) for row in db.execute(query, parameters)]
        finally: db.close()

class AuditStore:
    def __init__(self, state_dir: Path):
        state_dir.mkdir(parents=True, exist_ok=True); self.path = state_dir / "management.db"
        with sqlite3.connect(str(self.path)) as db:
            db.execute("CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY, created_at TEXT DEFAULT CURRENT_TIMESTAMP, actor TEXT, action TEXT, target TEXT, outcome TEXT, detail TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS chat_sessions (id INTEGER PRIMARY KEY, actor TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
            db.execute("CREATE TABLE IF NOT EXISTS chat_messages (id INTEGER PRIMARY KEY, session_id INTEGER NOT NULL, actor TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP)")
            db.execute("CREATE TABLE IF NOT EXISTS evidence_bundles (bundle_id TEXT PRIMARY KEY, session_id INTEGER NOT NULL, message_id INTEGER NOT NULL, actor TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP, finalized INTEGER NOT NULL DEFAULT 0, payload TEXT NOT NULL DEFAULT '{}', validation TEXT)")
    def add(self, actor: str, action: str, target: str, outcome: str, detail: str = "") -> None:
        with sqlite3.connect(str(self.path)) as db: db.execute("INSERT INTO audit_events(actor,action,target,outcome,detail) VALUES(?,?,?,?,?)", (actor,action,target,outcome,detail[:512]))
    def list(self) -> list[dict[str, Any]]:
        with sqlite3.connect(str(self.path)) as db:
            db.row_factory = sqlite3.Row; return [dict(row) for row in db.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 200")]

    def create_session(self, actor: str) -> int:
        with sqlite3.connect(str(self.path)) as db:
            return int(db.execute("INSERT INTO chat_sessions(actor) VALUES(?)",(actor,)).lastrowid)
    def add_message(self, session: int, actor: str, content: str) -> int:
        with sqlite3.connect(str(self.path)) as db:
            return int(db.execute("INSERT INTO chat_messages(session_id,actor,content) VALUES(?,?,?)",(session,actor,content[:4000])).lastrowid)
    def create_evidence_bundle(self, bundle_id: str, session: int, message_id: int, actor: str) -> None:
        with sqlite3.connect(str(self.path)) as db:
            db.execute("INSERT INTO evidence_bundles(bundle_id,session_id,message_id,actor,payload) VALUES(?,?,?,?,?)", (bundle_id,session,message_id,actor,json.dumps({"tool_calls":[],"facts":[],"sources":[],"unknowns":[],"limitations":[]})))
    def append_evidence_tool(self, bundle_id: str, tool: str, arguments: dict, result: dict) -> None:
        with sqlite3.connect(str(self.path)) as db:
            row=db.execute("SELECT payload,finalized FROM evidence_bundles WHERE bundle_id=?",(bundle_id,)).fetchone()
            if row is None or int(row[1]): return
            payload=json.loads(row[0]); payload["tool_calls"].append({"tool":tool,"arguments":arguments,"request_id":result.get("meta",{}).get("request_id")})
            payload["facts"].extend(result.get("facts",[])); payload["sources"].extend(result.get("meta",{}).get("sources",[])); payload["unknowns"].extend(result.get("meta",{}).get("unknowns",[])); payload["limitations"].extend(result.get("meta",{}).get("limitations",[]))
            db.execute("UPDATE evidence_bundles SET payload=? WHERE bundle_id=?",(json.dumps(payload,separators=(",",":")),bundle_id))
    def evidence_bundle(self, bundle_id: str, session: int, actor: str) -> dict | None:
        with sqlite3.connect(str(self.path)) as db:
            row=db.execute("SELECT session_id,message_id,actor,payload,finalized,validation FROM evidence_bundles WHERE bundle_id=?",(bundle_id,)).fetchone()
            if row is None or int(row[0]) != session or str(row[2]) != actor: return None
            return {"bundle_id":bundle_id,"session_id":int(row[0]),"message_id":int(row[1]),"actor":str(row[2]),"payload":json.loads(row[3]),"finalized":bool(row[4]),"validation":json.loads(row[5]) if row[5] else None}
    def finalize_evidence_bundle(self, bundle_id: str, session: int, actor: str, validation: dict) -> bool:
        with sqlite3.connect(str(self.path)) as db:
            row=db.execute("SELECT session_id,actor,finalized FROM evidence_bundles WHERE bundle_id=?",(bundle_id,)).fetchone()
            if row is None or int(row[0]) != session or str(row[1]) != actor or int(row[2]): return False
            db.execute("UPDATE evidence_bundles SET finalized=1,validation=? WHERE bundle_id=?",(json.dumps(validation,separators=(",",":")),bundle_id)); return True
    def owns_session(self, session: int, actor: str) -> bool:
        with sqlite3.connect(str(self.path)) as db:
            row=db.execute("SELECT actor FROM chat_sessions WHERE id=?",(session,)).fetchone()
            return row is not None and str(row[0]) == actor
    def messages(self, session: int) -> list[dict[str, Any]]:
        with sqlite3.connect(str(self.path)) as db:
            db.row_factory=sqlite3.Row; return [dict(row) for row in db.execute("SELECT id,actor,content,created_at FROM chat_messages WHERE session_id=? ORDER BY id",(session,))]

    def delete_session(self, session: int, actor: str) -> bool:
        with sqlite3.connect(str(self.path)) as db:
            owner=db.execute("SELECT actor FROM chat_sessions WHERE id=?",(session,)).fetchone()
            if owner is None or str(owner[0]) != actor: return False
            db.execute("DELETE FROM chat_messages WHERE session_id=?",(session,)); db.execute("DELETE FROM chat_sessions WHERE id=?",(session,)); return True
