from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from sdwan_v5.workloads import backup_client, backup_service, public_saas_service, saas_client


ROOT = Path(__file__).resolve().parents[1]


class FakeSocket:
    def __init__(self) -> None:
        self.options: list[tuple[int, int, int]] = []
    def settimeout(self, value: float) -> None:
        return None

    def bind(self, address: object) -> None:
        return None

    def connect(self, address: object) -> None:
        return None

    def close(self) -> None:
        return None

    def setsockopt(self, level: int, option: int, value: int) -> None:
        self.options.append((level, option, value))


class WorkloadTests(unittest.TestCase):
    def test_backup_service_stores_verifiable_payload_and_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(backup_service, "ROOT", root), patch.object(backup_service, "JOBS", {}):
                client = TestClient(backup_service.app)
                payload = b"branch-backup" * 1024
                response = client.post("/backup/node1", content=payload)
                self.assertEqual(response.status_code, 200)
                record = response.json()
                self.assertEqual(record["bytes"], len(payload))
                self.assertEqual(record["sha256"], hashlib.sha256(payload).hexdigest())
                status = client.get(f"/backup/status/{record['job_id']}")
                self.assertEqual(status.status_code, 200)
                self.assertEqual(status.json()["status"], "stored")
                self.assertTrue((root / "node1" / f"{record['job_id']}.bin").is_file())
                self.assertEqual(client.post("/backup/invalid_branch", content=b"x").status_code, 422)

    def test_backup_service_enforces_configured_size_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(backup_service, "ROOT", Path(directory)), patch.object(backup_service, "MAX_UPLOAD_BYTES", 4):
                response = TestClient(backup_service.app).post("/backup/node1", content=b"12345")
                self.assertEqual(response.status_code, 413)
                self.assertFalse(list(Path(directory).rglob("*.part")))

    def test_public_saas_messages_and_file_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(public_saas_service, "ROOT", root), \
                 patch.object(public_saas_service, "FILES", root / "files"), \
                 patch.object(public_saas_service, "MESSAGES", root / "messages.jsonl"):
                client = TestClient(public_saas_service.app)
                self.assertEqual(client.get("/healthz").json()["service"], "public_saas")
                message = client.post("/api/messages", json={"message": "hello"})
                self.assertEqual(message.status_code, 200)
                self.assertEqual(client.get("/api/messages").json()["messages"][0]["message"], "hello")
                payload = b"collaboration-document" * 128
                upload = client.post("/files/upload", content=payload, headers={"X-Filename": "report.bin"})
                self.assertEqual(upload.status_code, 200)
                self.assertEqual(upload.json()["sha256"], hashlib.sha256(payload).hexdigest())
                download = client.get("/files/report.bin")
                self.assertEqual(download.content, payload)
                self.assertEqual(client.get("/files/missing.bin").status_code, 404)

    def test_public_saas_rejects_unsafe_name_and_oversized_upload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(public_saas_service, "ROOT", root), \
                 patch.object(public_saas_service, "FILES", root / "files"), \
                 patch.object(public_saas_service, "MAX_UPLOAD_BYTES", 4):
                client = TestClient(public_saas_service.app)
                self.assertEqual(client.post("/files/upload", content=b"12345", headers={"X-Filename": "x.bin"}).status_code, 413)
                self.assertEqual(client.post("/files/upload", content=b"x", headers={"X-Filename": ".."}).status_code, 422)
                self.assertFalse(list(root.rglob("*.part")))

    def test_dscp_is_applied_before_tls_wrap_for_backup_and_saas(self) -> None:
        import socket
        for factory, expected_dscp in (
            (lambda: backup_client.DSCPHTTPSConnection("10.100.0.10", 8443, 8, 30), 8),
            (lambda: saas_client.DSCPHTTPSConnection("198.18.0.10", 18), 18),
        ):
            raw = FakeSocket()
            connection = factory()
            with patch("socket.create_connection", return_value=raw), patch("socket.socket", return_value=raw), patch.object(connection._context, "wrap_socket", return_value=raw):
                connection.connect()
            self.assertIn((socket.IPPROTO_IP, socket.IP_TOS, expected_dscp << 2), raw.options)

    def test_rtp_sender_is_one_real_h264_rtp_stream(self) -> None:
        script = (ROOT / "workloads" / "rtp_sender.sh").read_text(encoding="utf-8")
        self.assertIn("-c:v libx264", script)
        self.assertIn("-f rtp", script)
        self.assertIn("-payload_type 96", script)
        self.assertNotIn("sine=", script)
        self.assertNotIn("-c:a", script)
        sdp = (ROOT / "workloads" / "rtp-video.sdp").read_text(encoding="utf-8")
        self.assertIn("m=video 5004 RTP/AVP 96", sdp)
        self.assertIn("a=rtpmap:96 H264/90000", sdp)


if __name__ == "__main__":
    unittest.main()
