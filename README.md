# Keyring Auth

A static, encrypted TOTP authenticator. No backend, accounts, telemetry, or runtime network calls.

- RFC 6238: SHA-1 / SHA-256 / SHA-512, 6 or 8 digits, custom period
- `otpauth://` paste and local camera QR scanning
- PBKDF2-SHA-256 (650,000 iterations) + per-record AES-256-GCM
- encrypted JSON backup, five-minute idle lock, best-effort clipboard clearing

Run `npm test`, then serve this directory over localhost or HTTPS.
