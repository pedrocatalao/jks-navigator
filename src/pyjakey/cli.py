from __future__ import annotations

import base64
import getpass
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import SignatureAlgorithmOID

from .crypto import (
    cert_to_der,
    cert_to_pem,
    create_self_signed_cert,
    encrypt_key_protected_data,
    format_fingerprint_sha256,
    generate_private_key,
    load_x509_der,
    load_x509_pem_or_der,
    serialize_pkcs8_private_key,
)
from .jks import Certificate, JKSStore, PrivateKeyEntry, TrustedCertEntry


def _err(msg: str) -> int:
    print(f"keytool error: {msg}", file=sys.stderr)
    return 1


def _parse_args(argv: list[str]) -> tuple[str | None, dict[str, str | bool]]:
    if not argv:
        return None, {}
    cmd = None
    opts: dict[str, str | bool] = {}
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok.startswith("-") and cmd is None and tok in {
            "-list",
            "-importcert",
            "-exportcert",
            "-printcert",
            "-importkeystore",
            "-delete",
            "-changealias",
            "-genkeypair",
            "-storepasswd",
            "-keypasswd",
        }:
            cmd = tok
            i += 1
            continue
        if not tok.startswith("-"):
            return None, {}
        key = tok[1:]
        if key in {"v", "rfc", "noprompt"}:
            opts[key] = True
            i += 1
            continue
        if i + 1 >= len(argv):
            raise ValueError(f"Missing value for {tok}")
        opts[key] = argv[i + 1]
        i += 2
    return cmd, opts


def _need_opt(opts: dict[str, str | bool], name: str) -> str:
    val = opts.get(name)
    if val is None or isinstance(val, bool):
        raise ValueError(f"Missing required option -{name}")
    return val


def _get_password(opts: dict[str, str | bool], name: str, prompt: str) -> str:
    val = opts.get(name)
    if isinstance(val, str):
        return val
    return getpass.getpass(prompt)


def _load_or_new(keystore: str, storepass: str) -> JKSStore:
    path = Path(keystore)
    if path.exists():
        return JKSStore.load(keystore, storepass)
    return JKSStore()


def _print_cert(alias: str, cert: x509.Certificate, verbose: bool) -> None:
    print(f"Alias name: {alias}")
    print(f"Owner: {cert.subject.rfc4514_string()}")
    print(f"Issuer: {cert.issuer.rfc4514_string()}")
    print(f"Serial number: {cert.serial_number:x}")
    print(f"Valid from: {cert.not_valid_before_utc} until: {cert.not_valid_after_utc}")
    print(f"Certificate fingerprints:\n\tSHA-256: {format_fingerprint_sha256(cert)}")
    if verbose:
        print(cert.public_bytes(encoding=serialization.Encoding.PEM).decode("ascii").strip())


def _cmd_list(opts: dict[str, str | bool]) -> int:
    def fmt_date(dt: datetime) -> str:
        local_dt = dt.astimezone()
        return f"{local_dt.strftime('%b')} {local_dt.day}, {local_dt.year}"

    def primary_cert(entry: PrivateKeyEntry | TrustedCertEntry) -> x509.Certificate | None:
        if isinstance(entry, PrivateKeyEntry):
            if not entry.chain:
                return None
            return load_x509_der(entry.chain[0].cert_data)
        return load_x509_der(entry.cert.cert_data)

    keystore = _need_opt(opts, "keystore")
    storepass = _get_password(opts, "storepass", "Enter keystore password: ")
    verbose = bool(opts.get("v"))
    store = JKSStore.load(keystore, storepass)
    aliases = store.aliases()
    print(f"Keystore type: JKS")
    print(f"Keystore provider: SUN")
    print()
    print(f"Your keystore contains {len(aliases)} entries")

    warnings: list[str] = []
    first = True
    for alias in aliases:
        entry = store.get(alias)
        if isinstance(entry, PrivateKeyEntry):
            kind = "PrivateKeyEntry"
        else:
            kind = "trustedCertEntry"
        dt = fmt_date(entry.timestamp)
        if first:
            print()
            first = False
        print(f"{alias}, {dt}, {kind},")
        cert = primary_cert(entry)
        if cert is not None:
            print(f"Certificate fingerprint (SHA-256): {format_fingerprint_sha256(cert)}")
            pub = cert.public_key()
            if isinstance(pub, rsa.RSAPublicKey) and pub.key_size < 2048:
                warnings.append(
                    f"<{alias}> uses a {pub.key_size}-bit RSA key which is considered a security risk. "
                    "This key size will be disabled in a future update."
                )
            if isinstance(pub, dsa.DSAPublicKey) and pub.key_size < 2048:
                warnings.append(
                    f"<{alias}> uses a {pub.key_size}-bit DSA key which is considered a security risk. "
                    "This key size will be disabled in a future update."
                )
            if isinstance(pub, ec.EllipticCurvePublicKey) and pub.key_size < 224:
                warnings.append(
                    f"<{alias}> uses a {pub.key_size}-bit EC key which is considered a security risk. "
                    "This key size will be disabled in a future update."
                )
            if isinstance(entry, PrivateKeyEntry) and cert.signature_algorithm_oid == SignatureAlgorithmOID.RSA_WITH_SHA1:
                warnings.append(
                    f"<{alias}> uses the SHA1withRSA signature algorithm which is considered a security risk."
                )

        if verbose:
            if cert is not None:
                _print_cert(alias, cert, verbose=False)

    if warnings:
        print("\nWarning:")
        for line in warnings:
            print(line)

    ks_path = str(Path(keystore).expanduser().resolve())
    print(
        'The JKS keystore uses a proprietary format. It is recommended to migrate to PKCS12 which is an '
        f'industry standard format using "keytool -importkeystore -srckeystore {ks_path} -destkeystore '
        f'{ks_path} -deststoretype pkcs12".'
    )
    return 0


def _cmd_importcert(opts: dict[str, str | bool]) -> int:
    keystore = _need_opt(opts, "keystore")
    alias = _need_opt(opts, "alias")
    filename = _need_opt(opts, "file")
    storepass = _get_password(opts, "storepass", "Enter keystore password: ")
    store = _load_or_new(keystore, storepass)
    cert = load_x509_pem_or_der(Path(filename).read_bytes())
    if alias in store.entries and not opts.get("noprompt"):
        ans = input(f"Certificate already exists for alias <{alias}>. Overwrite? [no]: ").strip().lower()
        if ans not in ("y", "yes"):
            return _err("Certificate not imported")
    store.put(
        TrustedCertEntry(
            alias=alias,
            timestamp=datetime.now(timezone.utc),
            cert=Certificate(cert_type="X.509", cert_data=cert_to_der(cert)),
        )
    )
    store.save(keystore, storepass)
    print("Certificate was added to keystore")
    return 0


def _cmd_exportcert(opts: dict[str, str | bool]) -> int:
    keystore = _need_opt(opts, "keystore")
    alias = _need_opt(opts, "alias")
    storepass = _get_password(opts, "storepass", "Enter keystore password: ")
    out_file = opts.get("file")
    rfc = bool(opts.get("rfc"))
    store = JKSStore.load(keystore, storepass)
    entry = store.get(alias)
    if entry is None:
        return _err(f"Alias <{alias}> does not exist")
    if isinstance(entry, PrivateKeyEntry):
        if not entry.chain:
            return _err(f"Alias <{alias}> has no certificate chain")
        cert_der = entry.chain[0].cert_data
    else:
        cert_der = entry.cert.cert_data
    cert = load_x509_der(cert_der)
    if rfc:
        pem_lines = cert_to_pem(cert).decode("ascii").splitlines()
        if len(pem_lines) >= 2 and pem_lines[0].startswith("-----BEGIN ") and pem_lines[-1].startswith("-----END "):
            head = pem_lines[0]
            body = pem_lines[1:-1]
            tail = pem_lines[-1]
            body_block = "\r\n".join(body)
            if body_block:
                data = (head + "\n" + body_block + "\n" + tail + "\n").encode("ascii")
            else:
                data = (head + "\n" + tail + "\n").encode("ascii")
        else:
            data = cert_to_pem(cert)
    else:
        data = cert_to_der(cert)
    if isinstance(out_file, str):
        Path(out_file).write_bytes(data)
    else:
        if rfc:
            sys.stdout.write(data.decode("ascii"))
        else:
            sys.stdout.write(base64.b64encode(data).decode("ascii") + "\n")
    return 0


def _cmd_printcert(opts: dict[str, str | bool]) -> int:
    filename = _need_opt(opts, "file")
    cert = load_x509_pem_or_der(Path(filename).read_bytes())
    _print_cert("N/A", cert, verbose=bool(opts.get("v")))
    return 0


def _cmd_importkeystore(opts: dict[str, str | bool]) -> int:
    src = _need_opt(opts, "srckeystore")
    srcpass = _get_password(opts, "srcstorepass", "Enter source keystore password: ")
    dest = _need_opt(opts, "destkeystore")
    destpass = _get_password(opts, "deststorepass", "Enter destination keystore password: ")
    src_alias_opt = opts.get("srcalias")
    dest_alias_opt = opts.get("destalias")
    src_store = JKSStore.load(src, srcpass)
    dest_store = _load_or_new(dest, destpass)

    def clone_entry(entry, alias_override: str | None = None):
        alias = alias_override if alias_override is not None else entry.alias
        if isinstance(entry, PrivateKeyEntry):
            return PrivateKeyEntry(
                alias=alias,
                timestamp=entry.timestamp,
                key_protected_data=bytes(entry.key_protected_data),
                chain=[Certificate(cert_type=c.cert_type, cert_data=bytes(c.cert_data)) for c in entry.chain],
            )
        return TrustedCertEntry(
            alias=alias,
            timestamp=entry.timestamp,
            cert=Certificate(cert_type=entry.cert.cert_type, cert_data=bytes(entry.cert.cert_data)),
        )

    if isinstance(src_alias_opt, str):
        entry = src_store.get(src_alias_opt)
        if entry is None:
            return _err(f"Alias <{src_alias_opt}> does not exist in source keystore")
        target_alias = dest_alias_opt if isinstance(dest_alias_opt, str) else src_alias_opt
        if target_alias in dest_store.entries:
            return _err(f"Alias <{target_alias}> already exists in destination keystore")
        dest_store.put(clone_entry(entry, alias_override=target_alias))
    else:
        for alias in src_store.aliases():
            entry = src_store.get(alias)
            if entry is None:
                continue
            if alias in dest_store.entries:
                continue
            dest_store.put(clone_entry(entry))
    dest_store.save(dest, destpass)
    return 0


def _cmd_delete(opts: dict[str, str | bool]) -> int:
    keystore = _need_opt(opts, "keystore")
    alias = _need_opt(opts, "alias")
    storepass = _get_password(opts, "storepass", "Enter keystore password: ")
    store = JKSStore.load(keystore, storepass)
    try:
        store.delete(alias)
    except KeyError:
        return _err(f"Alias <{alias}> does not exist")
    store.save(keystore, storepass)
    return 0


def _cmd_changealias(opts: dict[str, str | bool]) -> int:
    keystore = _need_opt(opts, "keystore")
    old_alias = _need_opt(opts, "alias")
    new_alias = _need_opt(opts, "destalias")
    storepass = _get_password(opts, "storepass", "Enter keystore password: ")
    store = JKSStore.load(keystore, storepass)
    try:
        store.rename_alias(old_alias, new_alias)
    except KeyError:
        return _err(f"Alias <{old_alias}> does not exist")
    except ValueError as exc:
        return _err(str(exc))
    store.save(keystore, storepass)
    return 0


def _cmd_genkeypair(opts: dict[str, str | bool]) -> int:
    keystore = _need_opt(opts, "keystore")
    alias = _need_opt(opts, "alias")
    storepass = _get_password(opts, "storepass", "Enter keystore password: ")
    keypass = _get_password(opts, "keypass", "Enter key password: ")
    dname = str(opts.get("dname", "CN=Unknown"))
    keyalg = str(opts.get("keyalg", "RSA"))
    keysize = int(str(opts.get("keysize", "2048")))
    validity = int(str(opts.get("validity", "365")))
    store = _load_or_new(keystore, storepass)
    if alias in store.entries:
        return _err(f"Alias <{alias}> already exists")
    private_key = generate_private_key(keyalg, keysize)
    cert = create_self_signed_cert(private_key, dname, validity)
    p8 = serialize_pkcs8_private_key(private_key)
    prot = encrypt_key_protected_data(p8, keypass)
    entry = PrivateKeyEntry(
        alias=alias,
        timestamp=datetime.now(timezone.utc),
        key_protected_data=prot,
        chain=[Certificate(cert_type="X.509", cert_data=cert_to_der(cert))],
    )
    store.put(entry)
    store.save(keystore, storepass)
    print("Generating key pair and self-signed certificate")
    return 0


def _cmd_storepasswd(opts: dict[str, str | bool]) -> int:
    keystore = _need_opt(opts, "keystore")
    old_pass = _get_password(opts, "storepass", "Enter keystore password: ")
    new_pass = _get_password(opts, "new", "Enter new keystore password: ")
    store = JKSStore.load(keystore, old_pass)
    store.save(keystore, new_pass)
    return 0


def _cmd_keypasswd(opts: dict[str, str | bool]) -> int:
    keystore = _need_opt(opts, "keystore")
    alias = _need_opt(opts, "alias")
    storepass = _get_password(opts, "storepass", "Enter keystore password: ")
    old_keypass = _get_password(opts, "keypass", "Enter key password: ")
    new_keypass = _get_password(opts, "new", "Enter new key password: ")
    store = JKSStore.load(keystore, storepass)
    entry = store.get(alias)
    if not isinstance(entry, PrivateKeyEntry):
        return _err(f"Alias <{alias}> is not a key entry")
    try:
        private_key = store.extract_private_key(alias, old_keypass)
    except ValueError:
        return _err("Key password was incorrect")
    pkcs8 = serialize_pkcs8_private_key(private_key)
    entry.key_protected_data = encrypt_key_protected_data(pkcs8, new_keypass)
    store.save(keystore, storepass)
    return 0


def _usage() -> str:
    return (
        "Usage: jksnav <command> [options]\n"
        "Commands:\n"
        "  -list -keystore <file> [-storepass <pass>] [-v]\n"
        "  -importcert -alias <a> -file <cert> -keystore <file> [-storepass <pass>] [-noprompt]\n"
        "  -exportcert -alias <a> -keystore <file> [-storepass <pass>] [-rfc] [-file <out>]\n"
        "  -printcert -file <cert> [-v]\n"
        "  -importkeystore -srckeystore <src> -srcstorepass <pass> -destkeystore <dst> -deststorepass <pass> "
        "[-srcalias <a>] [-destalias <a>]\n"
        "  -delete -alias <a> -keystore <file> [-storepass <pass>]\n"
        "  -changealias -alias <old> -destalias <new> -keystore <file> [-storepass <pass>]\n"
        "  -genkeypair -alias <a> -keystore <file> [-storepass <pass>] [-keypass <pass>] "
        "[-dname <dn>] [-keyalg RSA|EC] [-keysize <n>] [-validity <days>]\n"
        "  -storepasswd -keystore <file> [-storepass <old>] [-new <new>]\n"
        "  -keypasswd -alias <a> -keystore <file> [-storepass <pass>] [-keypass <old>] [-new <new>]\n"
    )


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        cmd, opts = _parse_args(argv)
    except ValueError as exc:
        return _err(str(exc))
    if cmd is None:
        print(_usage(), file=sys.stderr)
        return 2
    try:
        if cmd == "-list":
            return _cmd_list(opts)
        if cmd == "-importcert":
            return _cmd_importcert(opts)
        if cmd == "-exportcert":
            return _cmd_exportcert(opts)
        if cmd == "-printcert":
            return _cmd_printcert(opts)
        if cmd == "-importkeystore":
            return _cmd_importkeystore(opts)
        if cmd == "-delete":
            return _cmd_delete(opts)
        if cmd == "-changealias":
            return _cmd_changealias(opts)
        if cmd == "-genkeypair":
            return _cmd_genkeypair(opts)
        if cmd == "-storepasswd":
            return _cmd_storepasswd(opts)
        if cmd == "-keypasswd":
            return _cmd_keypasswd(opts)
        return _err(f"Unsupported command {cmd}")
    except FileNotFoundError as exc:
        return _err(str(exc))
    except ValueError as exc:
        return _err(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
