from __future__ import annotations

import hashlib
import io
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import BinaryIO

from .crypto import (
    decrypt_key_protected_data,
    encrypt_key_protected_data,
    load_pkcs8_private_key,
    serialize_pkcs8_private_key,
)

MAGIC = 0xFEEDFEED
VERSION = 2
WHITENER = b"Mighty Aphrodite"


def _pack_u2(v: int) -> bytes:
    return struct.pack(">H", v)


def _pack_u4(v: int) -> bytes:
    return struct.pack(">I", v)


def _pack_i8(v: int) -> bytes:
    return struct.pack(">q", v)


def _read_exact(stream: BinaryIO, n: int) -> bytes:
    data = stream.read(n)
    if len(data) != n:
        raise ValueError("Unexpected end of file")
    return data


def _read_u2(stream: BinaryIO) -> int:
    return struct.unpack(">H", _read_exact(stream, 2))[0]


def _read_u4(stream: BinaryIO) -> int:
    return struct.unpack(">I", _read_exact(stream, 4))[0]


def _read_i8(stream: BinaryIO) -> int:
    return struct.unpack(">q", _read_exact(stream, 8))[0]


def _java_modified_utf_encode(text: str) -> bytes:
    out = bytearray()
    for ch in text:
        code = ord(ch)
        if code == 0x0000:
            out.extend(b"\xC0\x80")
        elif code <= 0x007F:
            out.append(code)
        elif code <= 0x07FF:
            out.append(0xC0 | ((code >> 6) & 0x1F))
            out.append(0x80 | (code & 0x3F))
        else:
            out.append(0xE0 | ((code >> 12) & 0x0F))
            out.append(0x80 | ((code >> 6) & 0x3F))
            out.append(0x80 | (code & 0x3F))
    if len(out) > 0xFFFF:
        raise ValueError("Modified UTF string too long")
    return _pack_u2(len(out)) + bytes(out)


def _java_modified_utf_decode(stream: BinaryIO) -> str:
    length = _read_u2(stream)
    data = _read_exact(stream, length)
    out = []
    i = 0
    while i < len(data):
        b0 = data[i]
        if (b0 & 0x80) == 0:
            if b0 == 0:
                raise ValueError("Invalid modified UTF encoding")
            out.append(chr(b0))
            i += 1
        elif (b0 & 0xE0) == 0xC0:
            if i + 1 >= len(data):
                raise ValueError("Truncated modified UTF sequence")
            b1 = data[i + 1]
            if b0 == 0xC0 and b1 == 0x80:
                out.append("\x00")
            else:
                out.append(chr(((b0 & 0x1F) << 6) | (b1 & 0x3F)))
            i += 2
        elif (b0 & 0xF0) == 0xE0:
            if i + 2 >= len(data):
                raise ValueError("Truncated modified UTF sequence")
            b1 = data[i + 1]
            b2 = data[i + 2]
            out.append(chr(((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F)))
            i += 3
        else:
            raise ValueError("Unsupported modified UTF sequence")
    return "".join(out)


def _password_utf16be(password: str) -> bytes:
    return password.encode("utf-16be")


def _compute_digest(data: bytes, store_password: str) -> bytes:
    md = hashlib.sha1()
    md.update(_password_utf16be(store_password))
    md.update(WHITENER)
    md.update(data)
    return md.digest()


def _to_millis(dt: datetime) -> int:
    return int(dt.astimezone(timezone.utc).timestamp() * 1000)


def _from_millis(ms: int) -> datetime:
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)


@dataclass
class Certificate:
    cert_type: str
    cert_data: bytes


@dataclass
class PrivateKeyEntry:
    alias: str
    timestamp: datetime
    key_protected_data: bytes
    chain: list[Certificate] = field(default_factory=list)


@dataclass
class TrustedCertEntry:
    alias: str
    timestamp: datetime
    cert: Certificate


@dataclass
class JKSStore:
    entries: dict[str, PrivateKeyEntry | TrustedCertEntry] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str, store_password: str) -> "JKSStore":
        with open(path, "rb") as f:
            return cls.loads(f.read(), store_password)

    @classmethod
    def loads(cls, blob: bytes, store_password: str) -> "JKSStore":
        if len(blob) < 4 + 4 + 4 + 20:
            raise ValueError("Not a valid JKS file")
        payload = blob[:-20]
        sig = blob[-20:]
        expected = _compute_digest(payload, store_password)
        if sig != expected:
            raise ValueError("Keystore password was incorrect or file was tampered")

        s = io.BytesIO(payload)
        magic = _read_u4(s)
        if magic != MAGIC:
            raise ValueError("Unsupported keystore magic")
        version = _read_u4(s)
        if version not in (1, 2):
            raise ValueError(f"Unsupported JKS version: {version}")

        count = _read_u4(s)
        store = cls()
        for _ in range(count):
            tag = _read_u4(s)
            alias = _java_modified_utf_decode(s)
            timestamp = _from_millis(_read_i8(s))
            if tag == 1:
                key_len = _read_u4(s)
                key_protected_data = _read_exact(s, key_len)
                chain_len = _read_u4(s)
                chain = []
                for _ in range(chain_len):
                    cert_type = _java_modified_utf_decode(s)
                    cert_len = _read_u4(s)
                    cert_data = _read_exact(s, cert_len)
                    chain.append(Certificate(cert_type=cert_type, cert_data=cert_data))
                store.entries[alias] = PrivateKeyEntry(
                    alias=alias,
                    timestamp=timestamp,
                    key_protected_data=key_protected_data,
                    chain=chain,
                )
            elif tag == 2:
                cert_type = _java_modified_utf_decode(s)
                cert_len = _read_u4(s)
                cert_data = _read_exact(s, cert_len)
                store.entries[alias] = TrustedCertEntry(
                    alias=alias,
                    timestamp=timestamp,
                    cert=Certificate(cert_type=cert_type, cert_data=cert_data),
                )
            else:
                raise ValueError(f"Unknown entry tag: {tag}")
        return store

    def dumps(self, store_password: str) -> bytes:
        out = io.BytesIO()
        out.write(_pack_u4(MAGIC))
        out.write(_pack_u4(VERSION))
        out.write(_pack_u4(len(self.entries)))
        for entry in self.entries.values():
            if isinstance(entry, PrivateKeyEntry):
                out.write(_pack_u4(1))
                out.write(_java_modified_utf_encode(entry.alias))
                out.write(_pack_i8(_to_millis(entry.timestamp)))
                out.write(_pack_u4(len(entry.key_protected_data)))
                out.write(entry.key_protected_data)
                out.write(_pack_u4(len(entry.chain)))
                for cert in entry.chain:
                    out.write(_java_modified_utf_encode(cert.cert_type))
                    out.write(_pack_u4(len(cert.cert_data)))
                    out.write(cert.cert_data)
            elif isinstance(entry, TrustedCertEntry):
                out.write(_pack_u4(2))
                out.write(_java_modified_utf_encode(entry.alias))
                out.write(_pack_i8(_to_millis(entry.timestamp)))
                out.write(_java_modified_utf_encode(entry.cert.cert_type))
                out.write(_pack_u4(len(entry.cert.cert_data)))
                out.write(entry.cert.cert_data)
            else:
                raise TypeError("Unsupported entry type")
        payload = out.getvalue()
        digest = _compute_digest(payload, store_password)
        return payload + digest

    def save(self, path: str, store_password: str) -> None:
        blob = self.dumps(store_password)
        with open(path, "wb") as f:
            f.write(blob)

    def aliases(self) -> list[str]:
        return sorted(self.entries.keys())

    def get(self, alias: str) -> PrivateKeyEntry | TrustedCertEntry | None:
        return self.entries.get(alias)

    def put(self, entry: PrivateKeyEntry | TrustedCertEntry) -> None:
        self.entries[entry.alias] = entry

    def delete(self, alias: str) -> None:
        if alias not in self.entries:
            raise KeyError(alias)
        del self.entries[alias]

    def rename_alias(self, old_alias: str, new_alias: str) -> None:
        if old_alias not in self.entries:
            raise KeyError(old_alias)
        if new_alias in self.entries:
            raise ValueError(f"Alias '{new_alias}' already exists")
        entry = self.entries.pop(old_alias)
        entry.alias = new_alias
        self.entries[new_alias] = entry

    def extract_private_key(self, alias: str, key_password: str):
        entry = self.entries.get(alias)
        if not isinstance(entry, PrivateKeyEntry):
            raise KeyError(alias)
        pkcs8 = decrypt_key_protected_data(entry.key_protected_data, key_password)
        return load_pkcs8_private_key(pkcs8)

    def set_private_key(self, alias: str, private_key, key_password: str, chain: list[Certificate]) -> None:
        if alias not in self.entries:
            raise KeyError(alias)
        current = self.entries[alias]
        if not isinstance(current, PrivateKeyEntry):
            raise ValueError("Alias is not a key entry")
        pkcs8 = serialize_pkcs8_private_key(private_key)
        current.key_protected_data = encrypt_key_protected_data(pkcs8, key_password)
        current.chain = chain

