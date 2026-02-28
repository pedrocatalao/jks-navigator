from __future__ import annotations

import re
import shutil
from pathlib import Path

from conftest import KEYPASS, NEWKEYPASS, NEWPASS, STOREPASS, run_cmd


ENTRY_RE = re.compile(r"^(.+),\s+([A-Z][a-z]{2}\s+\d{1,2},\s+\d{4}),\s+(PrivateKeyEntry|trustedCertEntry),\s*$")
FP_RE = re.compile(r"^Certificate fingerprint \(SHA-256\):\s+([0-9A-F:]+)$")


def parse_list_output(text: str) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    lines = [ln.rstrip() for ln in text.splitlines()]
    i = 0
    while i < len(lines):
        m = ENTRY_RE.match(lines[i])
        if not m:
            i += 1
            continue
        alias = m.group(1)
        kind = m.group(3)
        fp = ""
        if i + 1 < len(lines):
            mfp = FP_RE.match(lines[i + 1])
            if mfp:
                fp = mfp.group(1)
                i += 1
        result[alias] = (kind, fp)
        i += 1
    return result


def parse_fingerprint(text: str) -> str:
    for line in text.splitlines():
        m = FP_RE.search(line) or re.search(r"SHA-?256:\s*([0-9A-F:]+)", line)
        if m:
            return m.group(1)
    raise AssertionError(f"No SHA-256 fingerprint found in output:\n{text}")


def list_with(cmd: list[str], env: dict[str, str], keystore: Path, storepass: str) -> dict[str, tuple[str, str]]:
    args = ["-list", "-keystore", str(keystore), "-storepass", storepass]
    if cmd and cmd[0].endswith("keytool"):
        args = ["-storetype", "JKS"] + args
    cp = run_cmd(cmd + args, env=env)
    return parse_list_output(cp.stdout)


def assert_keystore_parity(cmd_a: list[str], cmd_b: list[str], env: dict[str, str], ks_a: Path, ks_b: Path, pass_a: str, pass_b: str) -> None:
    assert list_with(cmd_a, env, ks_a, pass_a) == list_with(cmd_b, env, ks_b, pass_b)


def test_list_parity(seed_keystore: Path, keytool_cmd: list[str], jksnav_cmd: list[str], base_env: dict[str, str]) -> None:
    jks = parse_list_output(
        run_cmd(jksnav_cmd + ["-list", "-keystore", str(seed_keystore), "-storepass", STOREPASS], env=base_env).stdout
    )
    jdk = parse_list_output(
        run_cmd(keytool_cmd + ["-storetype", "JKS", "-list", "-keystore", str(seed_keystore), "-storepass", STOREPASS], env=base_env).stdout
    )
    assert jks == jdk


def test_exportcert_parity(seed_keystore: Path, tmp_path: Path, keytool_cmd: list[str], jksnav_cmd: list[str], base_env: dict[str, str]) -> None:
    jks_der = tmp_path / "jks.der"
    jdk_der = tmp_path / "jdk.der"
    run_cmd(
        jksnav_cmd + ["-exportcert", "-alias", "seedkey", "-keystore", str(seed_keystore), "-storepass", STOREPASS, "-file", str(jks_der)],
        env=base_env,
    )
    run_cmd(
        keytool_cmd + ["-storetype", "JKS", "-exportcert", "-alias", "seedkey", "-keystore", str(seed_keystore), "-storepass", STOREPASS, "-file", str(jdk_der)],
        env=base_env,
    )
    assert jks_der.read_bytes() == jdk_der.read_bytes()

    jks_pem = tmp_path / "jks.pem"
    jdk_pem = tmp_path / "jdk.pem"
    run_cmd(
        jksnav_cmd + ["-exportcert", "-alias", "seedkey", "-keystore", str(seed_keystore), "-storepass", STOREPASS, "-rfc", "-file", str(jks_pem)],
        env=base_env,
    )
    run_cmd(
        keytool_cmd + ["-storetype", "JKS", "-exportcert", "-alias", "seedkey", "-keystore", str(seed_keystore), "-storepass", STOREPASS, "-rfc", "-file", str(jdk_pem)],
        env=base_env,
    )
    assert jks_pem.read_bytes() == jdk_pem.read_bytes()


def test_printcert_parity(seed_keystore: Path, tmp_path: Path, keytool_cmd: list[str], jksnav_cmd: list[str], base_env: dict[str, str]) -> None:
    cert = tmp_path / "c.pem"
    run_cmd(
        keytool_cmd + ["-storetype", "JKS", "-exportcert", "-alias", "seedkey", "-keystore", str(seed_keystore), "-storepass", STOREPASS, "-rfc", "-file", str(cert)],
        env=base_env,
    )
    jks_out = run_cmd(jksnav_cmd + ["-printcert", "-file", str(cert)], env=base_env).stdout
    jdk_out = run_cmd(keytool_cmd + ["-printcert", "-file", str(cert)], env=base_env).stdout
    assert parse_fingerprint(jks_out) == parse_fingerprint(jdk_out)


def test_importcert_delete_changealias_parity(
    seed_keystore: Path, tmp_path: Path, keytool_cmd: list[str], jksnav_cmd: list[str], base_env: dict[str, str]
) -> None:
    jks_store = tmp_path / "jks.jks"
    jdk_store = tmp_path / "jdk.jks"
    shutil.copy2(seed_keystore, jks_store)
    shutil.copy2(seed_keystore, jdk_store)

    cert_file = tmp_path / "import.pem"
    run_cmd(
        keytool_cmd + ["-storetype", "JKS", "-exportcert", "-alias", "seedkey", "-keystore", str(seed_keystore), "-storepass", STOREPASS, "-rfc", "-file", str(cert_file)],
        env=base_env,
    )

    run_cmd(
        jksnav_cmd + ["-importcert", "-alias", "toimport", "-keystore", str(jks_store), "-storepass", STOREPASS, "-file", str(cert_file), "-noprompt"],
        env=base_env,
    )
    run_cmd(
        keytool_cmd
        + ["-storetype", "JKS", "-importcert", "-alias", "toimport", "-keystore", str(jdk_store), "-storepass", STOREPASS, "-file", str(cert_file), "-noprompt"],
        env=base_env,
    )
    assert_keystore_parity(jksnav_cmd, keytool_cmd, base_env, jks_store, jdk_store, STOREPASS, STOREPASS)

    run_cmd(
        jksnav_cmd + ["-changealias", "-alias", "toimport", "-destalias", "renamed", "-keystore", str(jks_store), "-storepass", STOREPASS],
        env=base_env,
    )
    run_cmd(
        keytool_cmd
        + ["-storetype", "JKS", "-changealias", "-alias", "toimport", "-destalias", "renamed", "-keystore", str(jdk_store), "-storepass", STOREPASS],
        env=base_env,
    )
    assert_keystore_parity(jksnav_cmd, keytool_cmd, base_env, jks_store, jdk_store, STOREPASS, STOREPASS)

    run_cmd(
        jksnav_cmd + ["-delete", "-alias", "renamed", "-keystore", str(jks_store), "-storepass", STOREPASS],
        env=base_env,
    )
    run_cmd(
        keytool_cmd + ["-storetype", "JKS", "-delete", "-alias", "renamed", "-keystore", str(jdk_store), "-storepass", STOREPASS],
        env=base_env,
    )
    assert_keystore_parity(jksnav_cmd, keytool_cmd, base_env, jks_store, jdk_store, STOREPASS, STOREPASS)


def test_storepasswd_and_keypasswd_parity(
    seed_keystore: Path, tmp_path: Path, keytool_cmd: list[str], jksnav_cmd: list[str], base_env: dict[str, str]
) -> None:
    jks_store = tmp_path / "jks-pass.jks"
    jdk_store = tmp_path / "jdk-pass.jks"
    shutil.copy2(seed_keystore, jks_store)
    shutil.copy2(seed_keystore, jdk_store)

    run_cmd(
        jksnav_cmd + ["-keypasswd", "-alias", "seedkey", "-keystore", str(jks_store), "-storepass", STOREPASS, "-keypass", KEYPASS, "-new", NEWKEYPASS],
        env=base_env,
    )
    run_cmd(
        keytool_cmd
        + ["-storetype", "JKS", "-keypasswd", "-alias", "seedkey", "-keystore", str(jdk_store), "-storepass", STOREPASS, "-keypass", KEYPASS, "-new", NEWKEYPASS],
        env=base_env,
    )

    run_cmd(jksnav_cmd + ["-storepasswd", "-keystore", str(jks_store), "-storepass", STOREPASS, "-new", NEWPASS], env=base_env)
    run_cmd(keytool_cmd + ["-storetype", "JKS", "-storepasswd", "-keystore", str(jdk_store), "-storepass", STOREPASS, "-new", NEWPASS], env=base_env)

    assert_keystore_parity(jksnav_cmd, keytool_cmd, base_env, jks_store, jdk_store, NEWPASS, NEWPASS)


def test_importkeystore_parity(seed_keystore: Path, tmp_path: Path, keytool_cmd: list[str], jksnav_cmd: list[str], base_env: dict[str, str]) -> None:
    src = tmp_path / "src.jks"
    shutil.copy2(seed_keystore, src)

    jks_dst_all = tmp_path / "jks-all.jks"
    jdk_dst_all = tmp_path / "jdk-all.jks"

    run_cmd(
        jksnav_cmd + ["-importkeystore", "-srckeystore", str(src), "-srcstorepass", STOREPASS, "-destkeystore", str(jks_dst_all), "-deststorepass", STOREPASS],
        env=base_env,
    )
    run_cmd(
        keytool_cmd
        + [
            "-importkeystore",
            "-srckeystore",
            str(src),
            "-srcstoretype",
            "JKS",
            "-srcstorepass",
            STOREPASS,
            "-destkeystore",
            str(jdk_dst_all),
            "-deststoretype",
            "JKS",
            "-deststorepass",
            STOREPASS,
            "-noprompt",
        ],
        env=base_env,
    )
    assert_keystore_parity(jksnav_cmd, keytool_cmd, base_env, jks_dst_all, jdk_dst_all, STOREPASS, STOREPASS)

    jks_dst_one = tmp_path / "jks-one.jks"
    jdk_dst_one = tmp_path / "jdk-one.jks"
    run_cmd(
        jksnav_cmd
        + [
            "-importkeystore",
            "-srckeystore",
            str(src),
            "-srcstorepass",
            STOREPASS,
            "-srcalias",
            "seedtrusted",
            "-destalias",
            "onlyone",
            "-destkeystore",
            str(jks_dst_one),
            "-deststorepass",
            STOREPASS,
        ],
        env=base_env,
    )
    run_cmd(
        keytool_cmd
        + [
            "-importkeystore",
            "-srckeystore",
            str(src),
            "-srcstoretype",
            "JKS",
            "-srcstorepass",
            STOREPASS,
            "-srcalias",
            "seedtrusted",
            "-destalias",
            "onlyone",
            "-destkeystore",
            str(jdk_dst_one),
            "-deststoretype",
            "JKS",
            "-deststorepass",
            STOREPASS,
            "-noprompt",
        ],
        env=base_env,
    )
    assert_keystore_parity(jksnav_cmd, keytool_cmd, base_env, jks_dst_one, jdk_dst_one, STOREPASS, STOREPASS)


def test_genkeypair_parity_invariants(tmp_path: Path, keytool_cmd: list[str], jksnav_cmd: list[str], base_env: dict[str, str]) -> None:
    jks_store = tmp_path / "jks-gen.jks"
    jdk_store = tmp_path / "jdk-gen.jks"

    run_cmd(
        jksnav_cmd
        + [
            "-genkeypair",
            "-alias",
            "gen1",
            "-keystore",
            str(jks_store),
            "-storepass",
            STOREPASS,
            "-keypass",
            KEYPASS,
            "-dname",
            "CN=Gen1,O=JKSNav",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "365",
        ],
        env=base_env,
    )
    run_cmd(
        keytool_cmd
        + [
            "-genkeypair",
            "-alias",
            "gen1",
            "-storetype",
            "JKS",
            "-keystore",
            str(jdk_store),
            "-storepass",
            STOREPASS,
            "-keypass",
            KEYPASS,
            "-dname",
            "CN=Gen1,O=JKSNav",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "365",
            "-noprompt",
        ],
        env=base_env,
    )

    jks_map = list_with(jksnav_cmd, base_env, jks_store, STOREPASS)
    jdk_map = list_with(keytool_cmd, base_env, jdk_store, STOREPASS)
    assert "gen1" in jks_map and "gen1" in jdk_map
    assert jks_map["gen1"][0] == "PrivateKeyEntry"
    assert jdk_map["gen1"][0] == "PrivateKeyEntry"


def test_common_error_paths_have_nonzero_exit(
    seed_keystore: Path, keytool_cmd: list[str], jksnav_cmd: list[str], base_env: dict[str, str]
) -> None:
    jks_args = ["-delete", "-alias", "does-not-exist", "-keystore", str(seed_keystore), "-storepass", STOREPASS]
    jdk_args = ["-storetype", "JKS"] + jks_args
    jks = run_cmd(jksnav_cmd + jks_args, env=base_env, check=False)
    jdk = run_cmd(keytool_cmd + jdk_args, env=base_env, check=False)
    assert jks.returncode != 0
    assert jdk.returncode != 0
