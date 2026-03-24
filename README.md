# rpifwcrypto-pkcs11

PKCS#11 module that exposes the Raspberry Pi firmware OTP ECDSA unique secure stored key through the PKCS#11 interface.

The Raspberry Pi OTP stores a single ECDSA key (ID 1). This project wraps `librpifwcrypto` from Raspberry Pi's `raspi-utils` project, allowing OpenSSL, p11-kit and other PKCS#11 consumers to use this hardware-backed key without exporting private key material.

## Features

- Exposes the single Raspberry Pi OTP ECDSA key (ID 1) as PKCS#11 private and public key objects
- Supports `CKM_ECDSA` signing with firmware-backed key
- Returns public key material through `CKA_EC_POINT`
- No PIN required
- Works with locked device key


## Build requirements

- CMake 3.10 or newer
- C compiler with C99 support
- GnuTLS development libraries

## Build

The build automatically detects whether `librpifwcrypto` is installed on the system. If found, it links against the system library. Otherwise, it builds `librpifwcrypto` statically from the bundled `raspi-utils` submodule.

```sh
git clone --recursive https://github.com/embetrix/rpifwcrypto-pkcs11.git
cd rpifwcrypto-pkcs11
mkdir build && cd build
cmake ..
make
```

## Install

```sh
make install
```

## Key provisioning

Before using this module, the OTP key must be provisioned on the Raspberry Pi:

```sh
rpi-fw-crypto genkey --key-id 1 --alg ec
```

> **Warning:** This is a one-time operation. Once written to OTP, the key cannot be changed or deleted.

## Example usage

### Extract public key

```
openssl pkey -provider pkcs11 -provider default \
  -in "pkcs11:token=RPi%20OTP%20key;id=%01;type=private" \
  -pubout -out pubkey.pem
```

### Generate a device self-signed certificate

```
openssl req -x509 -new -provider pkcs11 -provider default \
  -key "pkcs11:token=RPi%20OTP%20key;id=%01;type=private" \
  -out cert.pem -days 365 -subj "/CN=RaspberryPi"
```

### Start a TLS server using the PKCS#11 key

```
openssl s_server -provider pkcs11 -provider default \
  -key "pkcs11:token=RPi%20OTP%20key;id=%01;type=private" \
  -cert cert.pem -accept 4433
```

## Notes

- The OTP contains a single ECDSA key with ID 1.
- Debug logging can be enabled with `RPIFWCRYPTO_PKCS11_DEBUG=1`.

## ECDSA signing format

This module implements **`CKM_ECDSA`** only (not `CKM_ECDSA_SHA256`). The caller must hash the data **before** calling `C_Sign`:

- **Input**:  32 bytes  a pre-computed SHA-256 digest.
- **Output**: 64 bytes flat `r || s` format (each integer zero-padded to 32 bytes).

The firmware internally returns a DER-encoded `ECDSA-Sig-Value`; the module converts it to the flat r||s format that PKCS#11 `CKM_ECDSA` requires.

> **Common pitfall**: passing raw data instead of a hash, or expecting a DER-encoded signature back. OpenSSL's pkcs11-provider handles this correctly when using `CKM_ECDSA`, but custom code must pre-hash with SHA-256 and expect the 64-byte flat output.

## License

This project is licensed under GPL-3.0-or-later.

It links against `librpifwcrypto`, which is provided under the BSD 3-Clause License. See `THIRD-PARTY-NOTICES` for details.
