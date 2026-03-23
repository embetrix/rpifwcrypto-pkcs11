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

### Generate a device certificate

```
export PKCS11_PROVIDER_MODULE=/usr/lib/pkcs11/rpifwcrypto-pkcs11.so
```

```
openssl req -x509 -new -provider pkcs11 -provider default \
  -key "pkcs11:token=RPi%20OTP%20key;id=%01;type=private" \
  -out cert.pem -days 365 -subj "/CN=RaspberryPi" \
  -propquery "?provider=pkcs11"
```

### Start a TLS server using the PKCS#11 key

```
openssl s_server -provider pkcs11 -provider default \
  -key "pkcs11:token=RPi%20OTP%20key;id=%01;type=private" \
  -cert cert.pem -accept 4433 \
  -propquery "?provider=pkcs11"
```

## Notes

- The OTP contains a single ECDSA key with ID 1.
- Debug logging can be enabled with `RPIFWCRYPTO_PKCS11_DEBUG=1`.

## License

This project is licensed under GPL-3.0-or-later.

It links against `librpifwcrypto`, which is provided under the BSD 3-Clause License. See `THIRD-PARTY-NOTICES` for details.
