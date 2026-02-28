from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
STOREPASS = "changeit"
NEWPASS = "newpass123"
KEYPASS = "changeit"
NEWKEYPASS = "newkeypass123"


@pytest.fixture(scope="session")
def keytool_path() -> str:
    path = shutil.which("keytool")
    if not path:
        pytest.skip("keytool not found in PATH (install a JDK)")
    return path


@pytest.fixture(scope="session")
def base_env() -> dict[str, str]:
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "C"
    env["TZ"] = "UTC"
    env["PYTHONPATH"] = str(SRC)
    return env


def run_cmd(cmd: list[str], env: dict[str, str], check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        env=env,
        input=input_text,
        text=True,
        capture_output=True,
        check=check,
    )


@pytest.fixture
def jksnav_cmd() -> list[str]:
    return [sys.executable, "-m", "jksnav.cli"]


@pytest.fixture
def keytool_cmd(keytool_path: str) -> list[str]:
    return [keytool_path]


def create_seed_keystore(path: Path, keytool_cmd: list[str], env: dict[str, str]) -> None:
    run_cmd(
        keytool_cmd
        + [
            "-genkeypair",
            "-alias",
            "seedkey",
            "-storetype",
            "JKS",
            "-keystore",
            str(path),
            "-storepass",
            STOREPASS,
            "-keypass",
            KEYPASS,
            "-dname",
            "CN=Seed,O=JKSNav",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "365",
            "-noprompt",
        ],
        env=env,
    )

    cert_file = path.parent / "seedcert.pem"
    run_cmd(
        keytool_cmd
        + [
            "-exportcert",
            "-alias",
            "seedkey",
            "-storetype",
            "JKS",
            "-keystore",
            str(path),
            "-storepass",
            STOREPASS,
            "-rfc",
            "-file",
            str(cert_file),
        ],
        env=env,
    )
    run_cmd(
        keytool_cmd
        + [
            "-importcert",
            "-alias",
            "seedtrusted",
            "-storetype",
            "JKS",
            "-keystore",
            str(path),
            "-storepass",
            STOREPASS,
            "-file",
            str(cert_file),
            "-noprompt",
        ],
        env=env,
    )


@pytest.fixture
def seed_keystore(tmp_path: Path, keytool_cmd: list[str], base_env: dict[str, str]) -> Path:
    ks = tmp_path / "seed.jks"
    create_seed_keystore(ks, keytool_cmd, base_env)
    return ks
