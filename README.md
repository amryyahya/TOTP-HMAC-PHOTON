# Modified TOTP HMAC-Photon Implementation in C

This project is a custom implementation of Time-based One-Time Password (TOTP) using the Photon hash algorithm instead of the traditional HMAC-SHA1. The implementation provides an additional layer of security by utilizing the Photon hash, a lightweight cryptographic hash function.

## Features
- **TOTP Algorithm**: Generates a time-based one-time password.
- **Photon Hash**: Instead of using the SHA1 hash as in the standard TOTP HMAC-SHA1, this implementation uses Photon, which is ideal for resource-constrained environments.
- **HMAC Integration**: Uses Photon hash within the HMAC (Hash-based Message Authentication Code) structure for generating the TOTP.

## Technology Stack
- **Language**: C
- **Cryptographic Algorithm**: [Photon hash](https://eprint.iacr.org/2011/609.pdf)
- **Standard**: TOTP (Time-based One-Time Password) [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238)
