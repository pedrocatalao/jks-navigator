# pyjakey

`pyjakey` is a zero-Java-dependency Python implementation of a `keytool`-style
CLI for inspecting and manipulating JKS keystores.

## Install

```bash
pip install -e .
```

## CLI

The CLI accepts keytool-like commands and options:

```bash
pykeytool -list -keystore keystore.jks -storepass changeit
pykeytool -genkeypair -alias demo -keystore keystore.jks -storepass changeit -keypass changeit -dname "CN=Demo" -keyalg RSA -keysize 2048 -validity 365
pykeytool -exportcert -alias demo -keystore keystore.jks -storepass changeit -rfc -file demo.crt
pykeytool -importcert -alias ca -keystore keystore.jks -storepass changeit -file ca.crt -noprompt
pykeytool -delete -alias demo -keystore keystore.jks -storepass changeit
```

## Notes

- Store type supported: `JKS`
- No Java runtime required
- Focused on JKS parity with common `keytool` flows
