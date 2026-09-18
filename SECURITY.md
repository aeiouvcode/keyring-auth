# Security model

Keyring Auth is a fully static, client-side TOTP vault. It makes no network requests at runtime and has no account, sync service, analytics, or recovery channel.

## What it protects

Stored token records are JSON-encrypted individually with AES-256-GCM and a unique random 96-bit IV per write. The AES key is derived from the vault passphrase with PBKDF2-HMAC-SHA-256, a random 128-bit vault salt, and 650,000 iterations. IndexedDB contains KDF metadata, IVs, and ciphertext only. The passphrase and decrypted records exist only in JavaScript memory while unlocked. Locking drops application references to both; the app automatically locks after five minutes of input inactivity.

AES-GCM authenticates each record. A wrong passphrase or changed ciphertext fails authentication and is reported without exposing records. Backups preserve the encrypted records and KDF parameters. They are not decrypted exports.

## Threat model and limits

This design helps against someone copying browser storage, a casual user opening a locked vault, and disclosure through a server operator because there is no server. Passphrase strength still matters: a stolen database can be attacked offline.

A web app cannot protect secrets from a compromised device, malicious browser or extension, screen capture, keylogger, process-memory inspection, or clipboard monitoring. It cannot guarantee that garbage collection immediately overwrites old memory. "Dropped from app memory" means references are released, not securely zeroed RAM.

XSS or a malicious update executing while the vault is unlocked could read secrets and codes. This build avoids third-party runtime dependencies except a vendored QR decoder, uses no remote assets, and applies user labels with `textContent`. Static hosting integrity remains a trust boundary. Review downloaded source or pin a known commit for higher assurance. GitHub Pages itself can observe ordinary page requests, even though the app makes no runtime API/telemetry calls.

Camera frames remain in browser memory and are used only to decode QR data. Clipboard auto-clear is best effort after about 30 seconds: browser permission rules, another clipboard write, page closure, or OS behavior can prevent clearing.

There is no forgotten-passphrase recovery, cross-device sync, HOTP, push approval, hardware-key support, encrypted multi-vault import merge, issuer icons, or protection against a user pasting a hostile non-TOTP URI (non-TOTP URIs are rejected). Clock accuracy depends on the device. Custom periods are accepted from 1 to 300 seconds; SHA-1, SHA-256, SHA-512 and 6/8 digits are supported.

## Verification

`npm test` runs all 18 published RFC 6238 Appendix B vectors across SHA-1, SHA-256, and SHA-512. Use browser developer tools to verify the Network panel remains empty after the initial static document/module loads and to inspect IndexedDB `keyring-auth/vault` for absence of plaintext token material.

Report security issues privately to the repository owner. Do not include real TOTP seeds in reports.
