from __future__ import annotations

import hashlib
import os
import warnings
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.x509.oid import NameOID

JKS_KEY_PROTECTOR_OID_DER = b"\x2b\x06\x01\x04\x01\x2a\x02\x11\x01\x01"


def _password_bytes(password: str) -> bytes:
    return password.encode("utf-16be")


def _keystream(password: str, salt: bytes, n: int) -> bytes:
    pwd = _password_bytes(password)
    out = bytearray()
    digest = salt
    while len(out) < n:
        md = hashlib.sha1()
        md.update(pwd)
        md.update(digest)
        digest = md.digest()
        out.extend(digest)
    return bytes(out[:n])


def _der_len_encode(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    enc = []
    while n:
        enc.append(n & 0xFF)
        n >>= 8
    enc.reverse()
    return bytes([0x80 | len(enc), *enc])


def _der_len_decode(data: bytes, off: int) -> tuple[int, int]:
    if off >= len(data):
        raise ValueError("Invalid DER length")
    first = data[off]
    off += 1
    if (first & 0x80) == 0:
        return first, off
    nbytes = first & 0x7F
    if nbytes == 0 or off + nbytes > len(data):
        raise ValueError("Invalid DER length")
    value = 0
    for b in data[off : off + nbytes]:
        value = (value << 8) | b
    return value, off + nbytes


def _unwrap_encrypted_private_key_info(blob: bytes) -> bytes | None:
    try:
        off = 0
        if blob[off] != 0x30:
            return None
        off += 1
        outer_len, off = _der_len_decode(blob, off)
        outer_end = off + outer_len
        if outer_end > len(blob):
            return None

        if blob[off] != 0x30:
            return None
        off += 1
        alg_len, off = _der_len_decode(blob, off)
        alg_end = off + alg_len
        if alg_end > outer_end:
            return None

        if blob[off] != 0x06:
            return None
        off += 1
        oid_len, off = _der_len_decode(blob, off)
        oid = blob[off : off + oid_len]
        off += oid_len
        if oid != JKS_KEY_PROTECTOR_OID_DER:
            return None
        # ignore optional/unknown algorithm parameters
        off = alg_end

        if blob[off] != 0x04:
            return None
        off += 1
        oct_len, off = _der_len_decode(blob, off)
        octets = blob[off : off + oct_len]
        off += oct_len
        if off != outer_end:
            return None
        return octets
    except Exception:
        return None


def _wrap_encrypted_private_key_info(protected_raw: bytes) -> bytes:
    oid = b"\x06" + _der_len_encode(len(JKS_KEY_PROTECTOR_OID_DER)) + JKS_KEY_PROTECTOR_OID_DER
    alg_id = b"\x30" + _der_len_encode(len(oid)) + oid
    encrypted = b"\x04" + _der_len_encode(len(protected_raw)) + protected_raw
    body = alg_id + encrypted
    return b"\x30" + _der_len_encode(len(body)) + body


def _encrypt_key_protected_raw(pkcs8_der: bytes, password: str) -> bytes:
    salt = os.urandom(20)
    stream = _keystream(password, salt, len(pkcs8_der))
    encrypted = bytes(a ^ b for a, b in zip(pkcs8_der, stream))
    md = hashlib.sha1()
    md.update(_password_bytes(password))
    md.update(pkcs8_der)
    check = md.digest()
    return salt + encrypted + check


def encrypt_key_protected_data(pkcs8_der: bytes, password: str) -> bytes:
    return _wrap_encrypted_private_key_info(_encrypt_key_protected_raw(pkcs8_der, password))


def decrypt_key_protected_data(protected: bytes, password: str) -> bytes:
    unwrapped = _unwrap_encrypted_private_key_info(protected)
    if unwrapped is not None:
        protected = unwrapped
    if len(protected) < 40:
        raise ValueError("Invalid protected key data")
    salt = protected[:20]
    check = protected[-20:]
    encrypted = protected[20:-20]
    stream = _keystream(password, salt, len(encrypted))
    plain = bytes(a ^ b for a, b in zip(encrypted, stream))
    md = hashlib.sha1()
    md.update(_password_bytes(password))
    md.update(plain)
    if md.digest() != check:
        raise ValueError("Incorrect key password")
    return plain


def serialize_pkcs8_private_key(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_pkcs8_private_key(pkcs8_der: bytes):
    return serialization.load_der_private_key(pkcs8_der, password=None)


def load_x509_der(der: bytes) -> x509.Certificate:
    # Java keytool accepts legacy certs that trigger this warning in cryptography.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=CryptographyDeprecationWarning)
        return x509.load_der_x509_certificate(der)


def load_x509_pem_or_der(raw: bytes) -> x509.Certificate:
    data = raw.strip()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=CryptographyDeprecationWarning)
        if b"-----BEGIN CERTIFICATE-----" in data:
            return x509.load_pem_x509_certificate(raw)
        return x509.load_der_x509_certificate(raw)


def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def cert_to_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def format_fingerprint_sha256(cert: x509.Certificate) -> str:
    fp = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in fp)


def parse_dname(dname: str) -> x509.Name:
    parts = []
    for piece in dname.split(","):
        if "=" not in piece:
            continue
        k, v = piece.split("=", 1)
        k = k.strip().upper()
        v = v.strip()
        if k == "CN":
            oid = NameOID.COMMON_NAME
        elif k == "OU":
            oid = NameOID.ORGANIZATIONAL_UNIT_NAME
        elif k == "O":
            oid = NameOID.ORGANIZATION_NAME
        elif k == "L":
            oid = NameOID.LOCALITY_NAME
        elif k == "ST":
            oid = NameOID.STATE_OR_PROVINCE_NAME
        elif k == "C":
            oid = NameOID.COUNTRY_NAME
        elif k == "EMAILADDRESS":
            oid = NameOID.EMAIL_ADDRESS
        else:
            continue
        parts.append(x509.NameAttribute(oid, v))
    if not parts:
        parts = [x509.NameAttribute(NameOID.COMMON_NAME, "Unknown")]
    return x509.Name(parts)


def generate_private_key(keyalg: str, keysize: int):
    alg = keyalg.upper()
    if alg == "RSA":
        return rsa.generate_private_key(public_exponent=65537, key_size=keysize)
    if alg in ("EC", "ECDSA"):
        curve = ec.SECP256R1() if keysize <= 256 else ec.SECP384R1()
        return ec.generate_private_key(curve)
    raise ValueError(f"Unsupported key algorithm: {keyalg}")


def create_self_signed_cert(private_key, dname: str, validity_days: int) -> x509.Certificate:
    subject = parse_dname(dname)
    now = datetime.now(timezone.utc)
    serial = x509.random_serial_number()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(serial)
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    return builder.sign(private_key=private_key, algorithm=hashes.SHA256())
