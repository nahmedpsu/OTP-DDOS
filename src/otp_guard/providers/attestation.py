"""App attestation. Failure policy: FAIL CLOSED. A request that presents an attestation
which cannot be verified is blocked (Step 0), as the design requires.

Android: Google Play Integrity, verified server-side through the decodeIntegrityToken API.
iOS: Apple App Attest, both halves. Enrolment (AppAttestEnrollment.enroll, POST /attest/enroll)
validates the one-time attestation object against Apple's published steps and registers the key;
per-request *assertions* (AppAttestVerifier) are then verified against that key. The Apple App
Attestation Root CA is configured by path (APP_ATTEST_ROOT_CA_PATH), downloaded from
https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem; it is not embedded.
Tested with a synthetic certificate chain; no real device or Apple-issued attestation has been run.
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


APP_ATTEST_NONCE_OID = "1.2.840.113635.100.8.2"
AAGUID_PRODUCTION = b"appattest" + b"\x00" * 7
AAGUID_DEVELOPMENT = b"appattestdevelop"


def _der_nonce(ext_value: bytes) -> bytes:
    """The nonce extension's value: SEQUENCE { [1] EXPLICIT OCTET STRING nonce }."""
    def tlv(buf, i):
        tag = buf[i]; i += 1
        length = buf[i]; i += 1
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(buf[i:i + n], "big"); i += n
        return tag, buf[i:i + length], i + length
    tag, seq, _ = tlv(ext_value, 0)
    if tag != 0x30:
        raise ValueError("nonce extension: not a SEQUENCE")
    tag, inner, _ = tlv(seq, 0)
    if tag != 0xA1:
        raise ValueError("nonce extension: no [1] element")
    tag, octets, _ = tlv(inner, 0)
    if tag != 0x04:
        raise ValueError("nonce extension: not an OCTET STRING")
    return octets


class AppAttestEnrollment:
    """Validates an App Attest attestation object and registers the key, following Apple's
    'Validating apps that connect to your server' steps:
      1. the credential certificate chains (x5c[0] <- x5c[1] <- root) to the pinned App Attestation
         root CA, every certificate within its validity period;
      2. nonce = SHA-256(authData || SHA-256(challenge)) equals the credential certificate's
         1.2.840.113635.100.8.2 extension;
      3. SHA-256 of the credential public key (uncompressed point) equals the key id;
      4. the authenticator data's RP ID hash equals SHA-256(app id);
      5. its counter is 0;
      6. its AAGUID is 'appattest' (production) or 'appattestdevelop' (development, if allowed);
      7. its credential id equals the key id.
    On success the public key is registered for assertions and the receipt kept for fraud-metric
    refreshes. Fail closed: any malformed or unverifiable input is rejected."""

    def __init__(self, app_id, key_store, root_ca_pem, allow_development=False, clock=None):
        self.app_id = app_id
        self.keys = key_store
        self.root_pem = root_ca_pem.encode() if isinstance(root_ca_pem, str) else root_ca_pem
        self.allow_development = allow_development
        self.clock = clock

    def _now(self):
        import datetime as dt
        t = self.clock.now() if self.clock is not None else dt.datetime.now(dt.timezone.utc).timestamp()
        return dt.datetime.fromtimestamp(t, dt.timezone.utc)

    @staticmethod
    def _signed_by(cert, issuer):
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        pub = issuer.public_key()
        if cert.issuer != issuer.subject:
            raise ValueError("issuer name mismatch")
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
        else:
            raise ValueError("unsupported issuer key")

    def enroll(self, key_id_b64, attestation_object_b64, challenge):
        """Returns (ok, reason). key_id_b64: the key identifier from DCAppAttestService (base64)."""
        try:
            import cbor2
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
        except ImportError as e:
            log.error("app attest enrolment needs cbor2 and cryptography: %s", e)
            return False, "unavailable"
        try:
            key_id = _b64decode(key_id_b64)
            obj = cbor2.loads(_b64decode(attestation_object_b64))
            if obj.get("fmt") != "apple-appattest":
                return False, "format"
            stmt, auth_data = obj["attStmt"], obj["authData"]
            chain = [x509.load_der_x509_certificate(c) for c in stmt["x5c"]]
            root = x509.load_pem_x509_certificate(self.root_pem)
            if len(chain) < 2:
                return False, "chain"
            now = self._now()
            for c in chain + [root]:
                if not (c.not_valid_before.replace(tzinfo=now.tzinfo) <= now <= c.not_valid_after.replace(tzinfo=now.tzinfo)):
                    return False, "validity"
            for child, parent in zip(chain, chain[1:] + [root]):
                self._signed_by(child, parent)                                   # step 1
            cred = chain[0]
            client_hash = hashlib.sha256(challenge.encode() if isinstance(challenge, str) else challenge).digest()
            nonce = hashlib.sha256(auth_data + client_hash).digest()
            ext = cred.extensions.get_extension_for_oid(x509.ObjectIdentifier(APP_ATTEST_NONCE_OID))
            if _der_nonce(ext.value.value) != nonce:
                return False, "nonce"                                            # step 2
            point = cred.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            if hashlib.sha256(point).digest() != key_id:
                return False, "key_id"                                           # step 3
            if auth_data[:32] != hashlib.sha256(self.app_id.encode()).digest():
                return False, "rp_id"                                            # step 4
            if int.from_bytes(auth_data[33:37], "big") != 0:
                return False, "counter"                                          # step 5
            aaguid = auth_data[37:53]
            if aaguid != AAGUID_PRODUCTION and not (self.allow_development and aaguid == AAGUID_DEVELOPMENT):
                return False, "aaguid"                                           # step 6
            n = int.from_bytes(auth_data[53:55], "big")
            if auth_data[55:55 + n] != key_id:
                return False, "credential_id"                                    # step 7
        except Exception as e:                    # fail closed on anything malformed (CBOR, DER, signatures)
            log.info("app attest enrolment rejected: %s", type(e).__name__)
            return False, "invalid"
        pem = cred.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        kid = _b64url(key_id)
        self.keys.register_key(kid, pem)
        self.keys.store.set(f"appattest:receipt:{kid}", base64.b64encode(stmt.get("receipt", b"")).decode())
        return True, "enrolled"


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
