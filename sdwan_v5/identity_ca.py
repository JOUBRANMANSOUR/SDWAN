"""Laboratory CA and device-generated CSR helpers backed by Ubuntu OpenSSL."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from .identity_store import IdentityStore


class CertificateError(RuntimeError):
    pass


def _run(arguments: list[str], *, input_text: str | None = None) -> str:
    result = subprocess.run(arguments, input=input_text, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise CertificateError(f"OpenSSL command failed: {' '.join(arguments[:3])}: {result.stderr.strip()}")
    return result.stdout


def generate_device_csr(store: IdentityStore, device_id: str) -> str:
    """Generate the edge private key locally once and return a device CSR."""
    key, csr = store.private_key_path(), store.csr_path()
    if not key.exists():
        _run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)])
        key.chmod(0o600)
    _run(["openssl", "req", "-new", "-key", str(key), "-subj", f"/CN={device_id}", "-out", str(csr)])
    csr.chmod(0o600)
    return csr.read_text(encoding="utf-8")


class LaboratoryCA:
    """CA key remains at the ZTP/CA boundary, never on edges or Policy Service."""

    def __init__(self, certificate_path: Path, signing_key_path: Path, *, lifetime_days: int = 30):
        self.certificate_path = certificate_path
        self.signing_key_path = signing_key_path
        self.lifetime_days = lifetime_days

    def initialize(self, common_name: str = "sdwan-lab-ca") -> None:
        self.certificate_path.parent.mkdir(parents=True, exist_ok=True)
        self.signing_key_path.parent.mkdir(parents=True, exist_ok=True)
        if self.certificate_path.exists() != self.signing_key_path.exists():
            raise CertificateError("CA certificate/key pair is incomplete")
        if not self.signing_key_path.exists():
            _run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.signing_key_path)])
            self.signing_key_path.chmod(0o600)
            _run(["openssl", "req", "-x509", "-new", "-key", str(self.signing_key_path), "-subj", f"/CN={common_name}", "-days", "365", "-out", str(self.certificate_path)])

    def issue(self, *, site: str, device_id: str, csr_pem: str) -> tuple[str, str, str, str, str]:
        self.initialize()
        with TemporaryDirectory(prefix="sdwan-ca-") as directory:
            root = Path(directory)
            csr, cert, ext = root / "device.csr.pem", root / "device.cert.pem", root / "extensions.cnf"
            csr.write_text(csr_pem, encoding="utf-8")
            _run(["openssl", "req", "-in", str(csr), "-verify", "-noout"])
            subject = _run(["openssl", "req", "-in", str(csr), "-noout", "-subject"])
            if f"CN = {device_id}" not in subject and f"CN={device_id}" not in subject:
                raise CertificateError("CSR common name does not match claimed device identity")
            ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth,serverAuth\nsubjectAltName=DNS:" + site + ",URI:urn:sdwan:device:" + device_id + "\n", encoding="utf-8")
            _run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(self.certificate_path), "-CAkey", str(self.signing_key_path), "-CAcreateserial", "-days", str(self.lifetime_days), "-extfile", str(ext), "-out", str(cert)])
            certificate = cert.read_text(encoding="utf-8")
            serial = _run(["openssl", "x509", "-in", str(cert), "-noout", "-serial"]).strip().split("=", 1)[1]
            fingerprint = _run(["openssl", "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha256"]).strip().split("=", 1)[1].replace(":", "")
            not_before = _run(["openssl", "x509", "-in", str(cert), "-noout", "-startdate"]).strip().split("=", 1)[1]
            not_after = _run(["openssl", "x509", "-in", str(cert), "-noout", "-enddate"]).strip().split("=", 1)[1]
            return serial, fingerprint, not_before, not_after, certificate


def certificate_fingerprint(certificate_pem: str) -> str:
    return hashlib.sha256(certificate_pem.encode("utf-8")).hexdigest()
