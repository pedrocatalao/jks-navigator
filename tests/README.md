# Keytool Parity Tests

This suite compares `jksnav` behavior against Java `keytool` for supported
commands.

## Covered command parity

- `-list`
- `-exportcert` (DER and `-rfc`)
- `-printcert`
- `-importcert`
- `-delete`
- `-changealias`
- `-storepasswd`
- `-keypasswd`
- `-importkeystore` (all entries and single alias remap)
- `-genkeypair` (invariant parity)

## Prerequisites

- Python 3.11+
- JDK with `keytool` in `PATH`
- Python deps installed (`cryptography`, `pytest`)

## Run

```bash
cd /Users/pedro/Git/pyjakey
python3 -m pip install -e ".[test]"
pytest -q
```

If `keytool` is not present, tests are skipped with a clear message.
