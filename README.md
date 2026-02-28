# jks-navigator

`jks-navigator` is a pure Python, zero-Java-runtime CLI for inspecting and
manipulating Java KeyStore (JKS) files with `keytool`-style commands.

## Requirements

- Python `3.11+`
- `cryptography` (installed automatically via package dependency)

## Quick Start

### Option 1: Install editable package

```bash
python3 -m pip install -e .
jksnav -list -keystore keystore.jks -storepass changeit
```

### Option 2: Use bundled launcher script

The `./jksnav` script bootstraps a local virtual environment in `.venv/`,
installs `cryptography` if needed, and runs the CLI directly from `src/`.

```bash
./jksnav -list -keystore keystore.jks -storepass changeit
```

## Supported Commands

- `-list`
- `-importcert`
- `-exportcert`
- `-printcert`
- `-importkeystore`
- `-delete`
- `-changealias`
- `-genkeypair`
- `-storepasswd`
- `-keypasswd`

## Common Examples

```bash
jksnav -list -keystore keystore.jks -storepass changeit
jksnav -genkeypair -alias demo -keystore keystore.jks -storepass changeit -keypass changeit -dname "CN=Demo" -keyalg RSA -keysize 2048 -validity 365
jksnav -exportcert -alias demo -keystore keystore.jks -storepass changeit -rfc -file demo.crt
jksnav -importcert -alias ca -keystore keystore.jks -storepass changeit -file ca.crt -noprompt
jksnav -delete -alias demo -keystore keystore.jks -storepass changeit
```

## Testing

Unit/parity tests live in `tests/` and compare behavior with Java `keytool`
for covered operations.

```bash
python3 -m pip install -e ".[test]"
pytest -q
```

If `keytool` is not available in `PATH`, parity tests are skipped.

## Scope

- Keystore format supported: `JKS`
- Focused on parity with common `keytool` JKS workflows
