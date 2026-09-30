"""App attestation. Failure policy: FAIL CLOSED. A request that presents an attestation
which cannot be verified is blocked (Step 0), as the design requires.

Android: Google Play Integrity, verified server-side through the decodeIntegrityToken API.
iOS: Apple App Attest. Per-request *assertions* are verified here against a public key that
was registered at enrolment. Enrolment (validating the one-time attestation object and its
certificate chain against Apple's App Attest root CA) is a separate flow; see
AppAttestKeyStore.register_key and the README.
"""
import base64
import hashlib
import json

from ..services import AttestResult
from .http import default_session, json_or_error, log


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _b64decode(s: str) -> bytes:
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except Exception:
        return base64.b64decode(s + pad)


class PlayIntegrityVerifier:
    """attestation = {"platform": "android", "token": "<integrity token>"}"""

    def __init__(self, package_name, access_token_provider, session=None, timeout=5.0,
                 require_strong_integrity=False):
        self.package_name = package_name
        self.access_token_provider = access_token_provider   # callable -> bearer token
        self.session = session or default_session()
        self.timeout = timeout
        self.require_strong = require_strong_integrity

    @property
    def url(self):
        return f"https://playintegrity.googleapis.com/v1/{self.package_name}:decodeIntegrityToken"

    def verify(self, attestation, nonce):
        token = (attestation or {}).get("token")
        if not token:
            return AttestResult(False)
        try:
            data = json_or_error(self.session.post(
                self.url, json={"integrity_token": token},
                headers={"Authorization": f"Bearer {self.access_token_provider()}"}, timeout=self.timeout))
        except Exception as e:
            log.warning("play integrity unavailable: %s", e)
            return AttestResult(False)
        payload = data.get("tokenPayloadExternal", {})
        req = payload.get("requestDetails", {})
        if req.get("requestPackageName") != self.package_name:
            return AttestResult(False)
        # Classic API carries the nonce base64url-encoded; Standard API carries requestHash.
        want = _b64url(nonce.encode()) if isinstance(nonce, str) else _b64url(nonce)
        if req.get("nonce") not in (nonce, want) and req.get("requestHash") not in (nonce, want):
            return AttestResult(False)
        verdicts = set(payload.get("deviceIntegrity", {}).get("deviceRecognitionVerdict", []))
        needed = "MEETS_STRONG_INTEGRITY" if self.require_strong else "MEETS_DEVICE_INTEGRITY"
        if needed not in verdicts:
            return AttestResult(False)
        if payload.get("appIntegrity", {}).get("appRecognitionVerdict") != "PLAY_RECOGNIZED":
            return AttestResult(False)
        if payload.get("accountDetails", {}).get("appLicensingVerdict") != "LICENSED":
            return AttestResult(False)
        return AttestResult(True, "android")


class AppAttestKeyStore:
    """Public keys and signature counters for enrolled App Attest keys, in the pipeline store."""

    def __init__(self, store):
        self.store = store

    def register_key(self, key_id, public_key_pem):
        """Call this from the enrolment endpoint after validating the attestation object's
        certificate chain against Apple's App Attest root CA."""
        self.store.set(f"appattest:key:{key_id}", public_key_pem)
        self.store.set(f"appattest:counter:{key_id}", 0)

    def public_key_pem(self, key_id):
        return self.store.get(f"appattest:key:{key_id}")

    def counter(self, key_id):
        return int(self.store.get(f"appattest:counter:{key_id}") or 0)

    def set_counter(self, key_id, value):
        self.store.set(f"appattest:counter:{key_id}", int(value))


class AppAttestVerifier:
    """attestation = {"platform": "ios", "key_id": "<b64>", "assertion": "<b64 CBOR>",
                      "client_data": "<b64 JSON containing {"challenge": <nonce>, ...}>"}"""

    def __init__(self, app_id, key_store):
        self.app_id = app_id            # "<TEAMID>.<bundle id>"
        self.keys = key_store

    def verify(self, attestation, nonce):
        try:
            import cbor2
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.exceptions import InvalidSignature
        except ImportError as e:
            log.error("app attest needs cbor2 and cryptography: %s", e)
            return AttestResult(False)

        a = attestation or {}
        key_id, assertion_b64, client_data_b64 = a.get("key_id"), a.get("assertion"), a.get("client_data")
        if not (key_id and assertion_b64 and client_data_b64):
            return AttestResult(False)
        pem = self.keys.public_key_pem(key_id)
        if pem is None:
            return AttestResult(False)

        try:
            client_data = _b64decode(client_data_b64)
            if json.loads(client_data).get("challenge") != nonce:
                return AttestResult(False)
            assertion = cbor2.loads(_b64decode(assertion_b64))
            signature, auth_data = assertion["signature"], assertion["authenticatorData"]
            client_hash = hashlib.sha256(client_data).digest()
            expected = hashlib.sha256(auth_data + client_hash).digest()
            pub = serialization.load_pem_public_key(pem.encode())
            pub.verify(signature, expected, ec.ECDSA(hashes.SHA256()))
            if auth_data[:32] != hashlib.sha256(self.app_id.encode()).digest():
                return AttestResult(False)
            counter = int.from_bytes(auth_data[33:37], "big")
            if counter <= self.keys.counter(key_id):
                return AttestResult(False)          # replayed or rolled-back assertion
            self.keys.set_counter(key_id, counter)
            return AttestResult(True, "ios")
        except (InvalidSignature, KeyError, ValueError, TypeError) as e:
            log.info("app attest assertion rejected: %s", type(e).__name__)
            return AttestResult(False)


class CompositeAttestationVerifier:
    def __init__(self, verifiers):
        self.verifiers = verifiers          # {"ios": AppAttestVerifier, "android": PlayIntegrityVerifier}

    def verify(self, attestation, nonce):
        v = self.verifiers.get((attestation or {}).get("platform"))
        if v is None:
            return AttestResult(False)
        return v.verify(attestation, nonce)


class GoogleServiceAccountTokenProvider:
    """Bearer tokens for Google APIs (Play Integrity, FCM) from a service-account JSON file."""

    def __init__(self, credentials_path, scopes):
        self.credentials_path, self.scopes = credentials_path, scopes
        self._creds = None

    def __call__(self):
        from google.oauth2 import service_account
        from google.auth.transport.requests import Request
        if self._creds is None:
            self._creds = service_account.Credentials.from_service_account_file(
                self.credentials_path, scopes=self.scopes)
        if not self._creds.valid:
            self._creds.refresh(Request())
        return self._creds.token
