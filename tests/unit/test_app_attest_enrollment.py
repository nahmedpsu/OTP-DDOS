"""App Attest enrolment against a synthetic certificate chain built here (root P-384 -> intermediate
P-384 -> credential P-256 with the nonce extension), following Apple's validation steps. No
Apple-issued attestation is involved: this checks the verifier's logic, not a live device."""
import base64
import datetime as dt
import hashlib

import cbor2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from otp_guard.providers.attestation import (AppAttestEnrollment, AppAttestKeyStore, AppAttestVerifier,
                                             AAGUID_PRODUCTION, AAGUID_DEVELOPMENT)
from otp_guard.store import MemoryStore, Clock

APP_ID = "TEAMID1234.com.example.app"
NOW = dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject_key, issuer_key, subject, issuer, ca, extensions=(), days=(-1, 365)):
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
         .public_key(subject_key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW + dt.timedelta(days=days[0])).not_valid_after(NOW + dt.timedelta(days=days[1]))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    for e in extensions:
        b = b.add_extension(e, critical=False)
    return b.sign(issuer_key, hashes.SHA384() if ca else hashes.SHA256())


def _nonce_ext(nonce):
    octet = b"\x04" + bytes([len(nonce)]) + nonce
    tagged = b"\xa1" + bytes([len(octet)]) + octet
    der = b"\x30" + bytes([len(tagged)]) + tagged
    return x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.840.113635.100.8.2"), der)


def build(challenge="c-123", app_id=APP_ID, aaguid=AAGUID_PRODUCTION, counter=0, tamper=None, leaf_days=(-1, 365)):
    root_k, inter_k, leaf_k = ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP256R1())
    root = _cert(root_k, root_k, "Test App Attestation Root CA", "Test App Attestation Root CA", True)
    inter = _cert(inter_k, root_k, "Test App Attestation CA 1", "Test App Attestation Root CA", True)
    point = leaf_k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    key_id = hashlib.sha256(point).digest()
    cred_id = key_id if tamper != "credential_id" else b"\x00" * 32
    auth = (hashlib.sha256(app_id.encode()).digest() + b"\x40" + counter.to_bytes(4, "big") + aaguid
            + len(cred_id).to_bytes(2, "big") + cred_id + cbor2.dumps({1: 2, 3: -7}))
    nonce = hashlib.sha256(auth + hashlib.sha256(challenge.encode()).digest()).digest()
    if tamper == "nonce":
        nonce = b"\x01" * 32
    leaf = _cert(leaf_k, inter_k, "credential", "Test App Attestation CA 1", False, [_nonce_ext(nonce)], days=leaf_days)
    obj = {"fmt": "apple-appattest", "attStmt": {"x5c": [leaf.public_bytes(serialization.Encoding.DER),
                                                         inter.public_bytes(serialization.Encoding.DER)], "receipt": b"receipt-bytes"},
           "authData": auth}
    root_pem = root.public_bytes(serialization.Encoding.PEM)
    return base64.b64encode(key_id).decode(), base64.b64encode(cbor2.dumps(obj)).decode(), root_pem, leaf_k, key_id


def _enrollment(root_pem, **kw):
    clock = Clock(NOW.timestamp())
    store = MemoryStore(clock)
    return AppAttestEnrollment(APP_ID, AppAttestKeyStore(store), root_pem, clock=clock, **kw), store


def test_valid_attestation_enrols_the_key_and_assertions_then_verify():
    kid, obj, root, leaf_k, key_id = build()
    enr, store = _enrollment(root)
    assert enr.enroll(kid, obj, "c-123") == (True, "enrolled")
    kid_url = base64.urlsafe_b64encode(key_id).decode().rstrip("=")
    assert enr.keys.public_key_pem(kid_url) is not None and store.get(f"appattest:receipt:{kid_url}")
    # an assertion signed by the enrolled key is accepted by the per-request verifier
    import json
    client_data = json.dumps({"challenge": "n-1"}).encode()
    auth = hashlib.sha256(APP_ID.encode()).digest() + b"\x40" + (1).to_bytes(4, "big")
    sig = leaf_k.sign(hashlib.sha256(auth + hashlib.sha256(client_data).digest()).digest(), ec.ECDSA(hashes.SHA256()))
    att = {"platform": "ios", "key_id": kid_url, "assertion": base64.b64encode(cbor2.dumps({"signature": sig, "authenticatorData": auth})).decode(),
           "client_data": base64.b64encode(client_data).decode()}
    assert AppAttestVerifier(APP_ID, enr.keys).verify(att, "n-1").valid


@pytest.mark.parametrize("case,expected", [
    (dict(challenge="c-123"), "nonce"),                         # enrolled against another challenge (see below)
    (dict(tamper="nonce"), "nonce"),
    (dict(app_id="OTHERTEAM.com.example.app"), "rp_id"),
    (dict(counter=1), "counter"),
    (dict(aaguid=AAGUID_DEVELOPMENT), "aaguid"),
    (dict(tamper="credential_id"), "credential_id"),
    (dict(leaf_days=(-30, -1)), "validity"),
])
def test_invalid_attestations_are_rejected(case, expected):
    kid, obj, root, _, _ = build(**case)
    enr, _ = _enrollment(root)
    challenge = "another-challenge" if case == dict(challenge="c-123") else "c-123"
    assert enr.enroll(kid, obj, challenge) == (False, expected)


def test_development_aaguid_only_when_allowed():
    kid, obj, root, _, _ = build(aaguid=AAGUID_DEVELOPMENT)
    enr, _ = _enrollment(root, allow_development=True)
    assert enr.enroll(kid, obj, "c-123")[0]


def test_a_chain_to_another_root_is_rejected():
    kid, obj, _, _, _ = build()
    _, _, other_root, _, _ = build()
    enr, _ = _enrollment(other_root)
    assert enr.enroll(kid, obj, "c-123") == (False, "invalid")


def test_wrong_key_id_and_garbage_are_rejected():
    _, obj, root, _, _ = build()
    enr, _ = _enrollment(root)
    assert enr.enroll(base64.b64encode(b"\x02" * 32).decode(), obj, "c-123") == (False, "key_id")
    assert enr.enroll(base64.b64encode(b"\x02" * 32).decode(), base64.b64encode(b"not cbor").decode(), "c-123")[0] is False
