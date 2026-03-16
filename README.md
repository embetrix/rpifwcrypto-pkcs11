# rpifwcrypto-pkcs11

PKCS#11 module that exposes Raspberry Pi firmware OTP ECDSA keys through the PKCS#11 interface.

This project wraps `librpifwcrypto` from Raspberry Pi's `raspi-utils` project, allowing OpenSSL, p11-kit, and other PKCS#11 consumers to use hardware-backed OTP keys without exporting private key material.

## Features

- Exposes Raspberry Pi OTP ECDSA private and public keys as PKCS#11 objects
- Supports `CKM_ECDSA` signing with firmware-backed keys
- Returns public key material through `CKA_EC_POINT`
- Filters out unprovisioned key slots automatically
- Works with locked device keys

## License

This project is licensed under GPL-3.0-or-later.

It links against `librpifwcrypto`, which is provided under the BSD 3-Clause License. See `THIRD-PARTY-NOTICES` for details.

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

If you already cloned without `--recursive`:

```sh
git submodule update --init
```

## Install

```sh
make install
```

By default this installs:

- `rpifwcrypto-pkcs11.so` to `${CMAKE_INSTALL_LIBDIR}/pkcs11`
- `rpifwcrypto.module` to `${CMAKE_INSTALL_DATADIR}/p11-kit/modules`

You can override these with:

```sh
cmake -DPKCS11_MODULE_DIR=/usr/lib/pkcs11 -DP11KIT_MODULE_DIR=/usr/share/p11-kit/modules ..
```

## Example usage

```sh
export PKCS11_PROVIDER_MODULE=/usr/lib/pkcs11/rpifwcrypto-pkcs11.so
openssl req -x509 -new \
  -provider pkcs11 -provider default \
  -key "pkcs11:token=RPi%20OTP%20Keys;id=%01;type=private" \
  -out cert.pem -days 365 -subj "/CN=RaspberryPi" \
  -propquery "?provider=pkcs11"
```

## Notes

- Firmware key IDs are treated as 1-based IDs.
- If a key slot is present but not provisioned, it is skipped and not exposed as a PKCS#11 object.
- Debug logging can be enabled with `RPIFWCRYPTO_PKCS11_DEBUG=1`.
