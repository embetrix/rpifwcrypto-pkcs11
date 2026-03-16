// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * (C) Copyright 2026
 * Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
 *
 * rpifwcrypto PKCS#11 module
 *
 * Minimal PKCS#11 provider that exposes Raspberry Pi firmware OTP keys
 * for ECDSA P-256 signing. Works even when the device key is locked.
 *
 * Supported operations:
 *   - C_Sign with CKM_ECDSA (pre-hashed 32-byte SHA-256 digest)
 *   - Key discovery (public + private key objects per OTP slot)
 *   - Public key retrieval via CKA_EC_POINT
 *
 * Usage with OpenSSL 3.x (pkcs11-provider):
 *   openssl req -x509 -new -provider pkcs11 -provider default \
 *     -key "pkcs11:token=RPi%20OTP%20Keys;id=%01;type=private" \
 *     -out cert.pem -days 365 -subj "/CN=device" \
 *     -propquery "?provider=pkcs11"
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "pkcs11_types.h"
#include "pkcs11_funcs.h"
#include <rpifwcrypto.h>

/* --- Debug logging ------------------------------------------------------- */

static int g_debug = -1; /* -1 = not checked yet */

static int debug_enabled(void)
{
    if (g_debug < 0) {
        const char *env = getenv("RPIFWCRYPTO_PKCS11_DEBUG");
        g_debug = (env && *env != '0');
    }
    return g_debug;
}

#define DBG(fmt, ...) do { \
    if (debug_enabled()) \
        fprintf(stderr, "rpifwcrypto-pkcs11: " fmt "\n", ##__VA_ARGS__); \
} while (0)

static const char *ckr_str(CK_RV rv)
{
    switch (rv) {
    case CKR_OK:                       return "CKR_OK";
    case CKR_ARGUMENTS_BAD:            return "CKR_ARGUMENTS_BAD";
    case CKR_ATTRIBUTE_TYPE_INVALID:   return "CKR_ATTRIBUTE_TYPE_INVALID";
    case CKR_BUFFER_TOO_SMALL:         return "CKR_BUFFER_TOO_SMALL";
    case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
    case CKR_DEVICE_ERROR:             return "CKR_DEVICE_ERROR";
    case CKR_FUNCTION_NOT_SUPPORTED:   return "CKR_FUNCTION_NOT_SUPPORTED";
    case CKR_KEY_HANDLE_INVALID:       return "CKR_KEY_HANDLE_INVALID";
    case CKR_MECHANISM_INVALID:        return "CKR_MECHANISM_INVALID";
    case CKR_OBJECT_HANDLE_INVALID:    return "CKR_OBJECT_HANDLE_INVALID";
    case CKR_OPERATION_ACTIVE:         return "CKR_OPERATION_ACTIVE";
    case CKR_OPERATION_NOT_INITIALIZED:return "CKR_OPERATION_NOT_INITIALIZED";
    case CKR_SESSION_HANDLE_INVALID:   return "CKR_SESSION_HANDLE_INVALID";
    case CKR_SLOT_ID_INVALID:          return "CKR_SLOT_ID_INVALID";
    default:                           return "CKR_?";
    }
}

/* --- Module state -------------------------------------------------------- */

static CK_BBOOL g_initialized = CK_FALSE;
static int g_num_keys = 0;

/* We support one slot (0), one session at a time */
#define SLOT_ID         0
#define SESSION_HANDLE  1
#define MAX_OBJECTS     16  /* max OTP key slots */
#define MAX_SCAN        16  /* max key IDs to probe */

static CK_BBOOL g_session_open = CK_FALSE;

/* Per-key cached public key (DER) */
static struct {
    uint32_t fw_key_id;     /* actual firmware key ID */
    uint8_t  pubkey_der[RPI_FW_CRYPTO_PUBLIC_KEY_MAX_SIZE];
    size_t   pubkey_der_len;
    uint8_t  ec_point[67];  /* OCTET STRING { 04 || x || y } for P-256 */
    size_t   ec_point_len;
    CK_BBOOL pubkey_loaded;
    uint32_t status;
    CK_BBOOL valid;
} g_keys[MAX_OBJECTS];

/* Object handles: key_id*2+1 = private key, key_id*2+2 = public key */
#define PRIV_HANDLE(key_id) ((CK_OBJECT_HANDLE)((key_id) * 2 + 1))
#define PUB_HANDLE(key_id)  ((CK_OBJECT_HANDLE)((key_id) * 2 + 2))
#define HANDLE_KEY_ID(h)    (((h) - 1) / 2)
#define HANDLE_IS_PRIV(h)   (((h) & 1) == 1)

/* Find objects state */
static struct {
    CK_BBOOL active;
    CK_OBJECT_CLASS find_class;
    CK_BBOOL filter_class;
    CK_BBOOL filter_id;
    CK_BYTE  filter_fw_id;
    int next_key;
    CK_BBOOL return_priv;
    CK_BBOOL return_pub;
} g_find;

/* Sign state */
static struct {
    CK_BBOOL active;
    uint32_t key_id;
    CK_MECHANISM_TYPE mech;
    uint8_t  hash_buf[32];
    size_t   hash_len;
} g_sign;

/* --- Helpers ------------------------------------------------------------- */

/* ECDSA P-256 OID: 1.2.840.10045.3.1.7 (DER encoded) */
static const CK_BYTE ec_params_p256[] = {
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
};

static void pad_string(CK_UTF8CHAR *dst, const char *src, size_t len)
{
    size_t slen = strlen(src);
    if (slen > len) slen = len;
    memcpy(dst, src, slen);
    memset(dst + slen, ' ', len - slen);
}

/*
 * Extract raw EC point from SubjectPublicKeyInfo DER and wrap in OCTET STRING.
 * SPKI for P-256: 30 59 30 13 06 07 ... 06 08 ... 03 42 00 04 <x><y>
 * CKA_EC_POINT wants: 04 41 04 <x><y>  (OCTET STRING tag + length + point)
 */
static int extract_ec_point(const uint8_t *spki, size_t spki_len,
                            uint8_t *out, size_t out_max, size_t *out_len)
{
    /* Walk the SPKI to find the BIT STRING containing the EC point */
    size_t pos = 0;

    /* Outer SEQUENCE */
    if (pos >= spki_len || spki[pos] != 0x30) return -1;
    pos++;
    /* Skip length (may be 1 or 2 bytes) */
    if (pos >= spki_len) return -1;
    if (spki[pos] & 0x80) pos += (spki[pos] & 0x7f) + 1; else pos++;

    /* Inner SEQUENCE (algorithm identifier) */
    if (pos >= spki_len || spki[pos] != 0x30) return -1;
    pos++;
    if (pos >= spki_len) return -1;
    size_t alg_len = spki[pos]; pos++;
    pos += alg_len; /* skip algorithm identifier contents */

    /* BIT STRING */
    if (pos >= spki_len || spki[pos] != 0x03) return -1;
    pos++;
    if (pos >= spki_len) return -1;
    size_t bs_len = spki[pos]; pos++;
    if (pos >= spki_len) return -1;
    /* Skip unused-bits byte (should be 0) */
    pos++;
    bs_len--;

    /* bs_len should be 65 for uncompressed P-256 (04 || x || y) */
    if (bs_len != 65 || pos + bs_len > spki_len)
        return -1;

    /* Wrap in OCTET STRING: tag 0x04, length, then the point */
    size_t needed = 2 + bs_len; /* tag + length + data */
    if (needed > out_max) return -1;

    out[0] = 0x04; /* OCTET STRING tag */
    out[1] = (uint8_t)bs_len;
    memcpy(out + 2, spki + pos, bs_len);
    *out_len = needed;
    return 0;
}

static int ensure_pubkey(int idx)
{
    if (idx < 0 || idx >= g_num_keys || !g_keys[idx].valid)
        return -1;
    if (g_keys[idx].pubkey_loaded)
        return 0;

    uint32_t fw_id = g_keys[idx].fw_key_id;
    DBG("ensure_pubkey: fetching pubkey for key[%d] fw_id=%u", idx, fw_id);
    int rc = rpi_fw_crypto_get_pubkey(0, fw_id,
                                      g_keys[idx].pubkey_der,
                                      sizeof(g_keys[idx].pubkey_der),
                                      &g_keys[idx].pubkey_der_len);
    if (rc == 0) {
        g_keys[idx].pubkey_loaded = CK_TRUE;
        DBG("ensure_pubkey: key[%d] pubkey loaded (%zu bytes)",
            idx, g_keys[idx].pubkey_der_len);
        /* Extract EC point and wrap in OCTET STRING */
        rc = extract_ec_point(g_keys[idx].pubkey_der, g_keys[idx].pubkey_der_len,
                              g_keys[idx].ec_point, sizeof(g_keys[idx].ec_point),
                              &g_keys[idx].ec_point_len);
        if (rc != 0) {
            DBG("ensure_pubkey: key[%d] EC point extraction failed", idx);
            g_keys[idx].pubkey_loaded = CK_FALSE;
            return -1;
        }
        DBG("ensure_pubkey: key[%d] EC point %zu bytes",
            idx, g_keys[idx].ec_point_len);
    } else {
        DBG("ensure_pubkey: key[%d] fw_id=%u failed rc=%d", idx, fw_id, rc);
    }
    return rc;
}

/* --- PKCS#11 functions --------------------------------------------------- */

CK_RV C_Initialize(CK_C_INITIALIZE_ARGS *pInitArgs)
{
    (void)pInitArgs;

    if (g_initialized)
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;

    DBG("C_Initialize: opening /dev/vcio");
    int n = rpi_fw_crypto_get_num_otp_keys();
    DBG("C_Initialize: get_num_otp_keys returned %d", n);
    if (n < 0) {
        DBG("C_Initialize: FAILED — no OTP keys (rc=%d)", n);
        return CKR_DEVICE_ERROR;
    }

    memset(g_keys, 0, sizeof(g_keys));
    g_num_keys = 0;

    /* Probe key IDs — firmware uses 1-based IDs (1..n) */
    int scan_max = n;
    if (scan_max > MAX_SCAN) scan_max = MAX_SCAN;

    for (int i = 1; i <= scan_max && g_num_keys < MAX_OBJECTS; i++) {
        uint32_t status = 0;
        int rc = rpi_fw_crypto_get_key_status((uint32_t)i, &status);
        DBG("C_Initialize: probe key %d -> rc=%d status=0x%x", i, rc, status);
        if (rc != 0) {
            DBG("C_Initialize: key %d not accessible, skipping", i);
            continue;
        }
        if (!(status & ARM_CRYPTO_KEY_STATUS_TYPE_DEVICE_PRIVATE_KEY)) {
            DBG("C_Initialize: key %d not provisioned (status=0x%x), skipping", i, status);
            continue;
        }
        int idx = g_num_keys;
        g_keys[idx].fw_key_id = (uint32_t)i;
        g_keys[idx].status = status;
        g_keys[idx].valid = CK_TRUE;
        g_num_keys++;
        DBG("C_Initialize: registered key[%d] = fw_key_id %d status=0x%x",
            idx, i, status);
    }

    g_session_open = CK_FALSE;
    memset(&g_find, 0, sizeof(g_find));
    memset(&g_sign, 0, sizeof(g_sign));
    g_initialized = CK_TRUE;

    DBG("C_Initialize: OK, %d keys found", g_num_keys);
    return CKR_OK;
}

CK_RV C_Finalize(void *pReserved)
{
    (void)pReserved;
    if (!g_initialized)
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    g_initialized = CK_FALSE;
    g_session_open = CK_FALSE;
    return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO *pInfo)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pInfo) return CKR_ARGUMENTS_BAD;

    memset(pInfo, 0, sizeof(*pInfo));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    pad_string(pInfo->manufacturerID, "Raspberry Pi", sizeof(pInfo->manufacturerID));
    pad_string(pInfo->libraryDescription, "rpifwcrypto PKCS#11", sizeof(pInfo->libraryDescription));
    pInfo->libraryVersion.major = 1;
    pInfo->libraryVersion.minor = 0;
    return CKR_OK;
}

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID *pSlotList, CK_ULONG *pulCount)
{
    (void)tokenPresent;
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (!pulCount) return CKR_ARGUMENTS_BAD;

    if (!pSlotList) {
        *pulCount = 1;
        return CKR_OK;
    }
    if (*pulCount < 1) {
        *pulCount = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    pSlotList[0] = SLOT_ID;
    *pulCount = 1;
    return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO *pInfo)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != SLOT_ID) return CKR_SLOT_ID_INVALID;
    if (!pInfo) return CKR_ARGUMENTS_BAD;

    memset(pInfo, 0, sizeof(*pInfo));
    pad_string(pInfo->slotDescription, "RPi Firmware Crypto OTP", sizeof(pInfo->slotDescription));
    pad_string(pInfo->manufacturerID, "Raspberry Pi", sizeof(pInfo->manufacturerID));
    pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
    pInfo->hardwareVersion.major = 1;
    return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO *pInfo)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != SLOT_ID) return CKR_SLOT_ID_INVALID;
    if (!pInfo) return CKR_ARGUMENTS_BAD;

    memset(pInfo, 0, sizeof(*pInfo));
    pad_string(pInfo->label, "RPi OTP Keys", sizeof(pInfo->label));
    pad_string(pInfo->manufacturerID, "Raspberry Pi", sizeof(pInfo->manufacturerID));
    pad_string(pInfo->model, "BCM2712", sizeof(pInfo->model));
    pad_string(pInfo->serialNumber, "0000", sizeof(pInfo->serialNumber));
    pInfo->flags = CKF_TOKEN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH;
    pInfo->ulMaxSessionCount = 1;
    pInfo->ulMaxRwSessionCount = 1;
    pInfo->hardwareVersion.major = 1;
    return CKR_OK;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE *pMechanismList, CK_ULONG *pulCount)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != SLOT_ID) return CKR_SLOT_ID_INVALID;
    if (!pulCount) return CKR_ARGUMENTS_BAD;

    if (!pMechanismList) {
        *pulCount = 1;
        return CKR_OK;
    }
    if (*pulCount < 1) {
        *pulCount = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    pMechanismList[0] = CKM_ECDSA;
    *pulCount = 1;
    return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *pInfo)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != SLOT_ID) return CKR_SLOT_ID_INVALID;
    if (!pInfo) return CKR_ARGUMENTS_BAD;

    if (type != CKM_ECDSA)
        return CKR_MECHANISM_INVALID;

    pInfo->ulMinKeySize = 256;
    pInfo->ulMaxKeySize = 256;
    pInfo->flags = CKF_SIGN | CKF_EC_F_P;
    return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, void *pApplication,
                     CK_NOTIFY notify, CK_SESSION_HANDLE *phSession)
{
    (void)pApplication;
    (void)notify;

    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != SLOT_ID) return CKR_SLOT_ID_INVALID;
    if (!(flags & CKF_SERIAL_SESSION)) return CKR_FUNCTION_FAILED;
    if (!phSession) return CKR_ARGUMENTS_BAD;

    g_session_open = CK_TRUE;
    g_find.active = CK_FALSE;
    g_sign.active = CK_FALSE;
    *phSession = SESSION_HANDLE;
    return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (hSession != SESSION_HANDLE || !g_session_open)
        return CKR_SESSION_HANDLE_INVALID;
    g_session_open = CK_FALSE;
    g_find.active = CK_FALSE;
    g_sign.active = CK_FALSE;
    return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (slotID != SLOT_ID) return CKR_SLOT_ID_INVALID;
    g_session_open = CK_FALSE;
    g_find.active = CK_FALSE;
    g_sign.active = CK_FALSE;
    return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO *pInfo)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (hSession != SESSION_HANDLE || !g_session_open)
        return CKR_SESSION_HANDLE_INVALID;
    if (!pInfo) return CKR_ARGUMENTS_BAD;

    pInfo->slotID = SLOT_ID;
    pInfo->state = CKS_RO_PUBLIC_SESSION;
    pInfo->flags = CKF_SERIAL_SESSION;
    pInfo->ulDeviceError = 0;
    return CKR_OK;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
               CK_UTF8CHAR *pPin, CK_ULONG ulPinLen)
{
    (void)userType; (void)pPin; (void)ulPinLen;
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (hSession != SESSION_HANDLE || !g_session_open)
        return CKR_SESSION_HANDLE_INVALID;
    /* No PIN required — hardware-protected keys */
    return CKR_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (hSession != SESSION_HANDLE || !g_session_open)
        return CKR_SESSION_HANDLE_INVALID;
    return CKR_OK;
}

/* --- Object discovery ---------------------------------------------------- */

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (hSession != SESSION_HANDLE || !g_session_open)
        return CKR_SESSION_HANDLE_INVALID;
    if (g_find.active) return CKR_OPERATION_ACTIVE;

    g_find.filter_class = CK_FALSE;
    g_find.filter_id = CK_FALSE;
    g_find.return_priv = CK_TRUE;
    g_find.return_pub = CK_TRUE;
    g_find.next_key = 0;

    /* Parse filter template */
    for (CK_ULONG i = 0; i < ulCount; i++) {
        if (pTemplate[i].type == CKA_CLASS && pTemplate[i].pValue && pTemplate[i].ulValueLen == sizeof(CK_OBJECT_CLASS)) {
            g_find.filter_class = CK_TRUE;
            memcpy(&g_find.find_class, pTemplate[i].pValue, sizeof(CK_OBJECT_CLASS));
            if (g_find.find_class == CKO_PRIVATE_KEY) {
                g_find.return_pub = CK_FALSE;
            } else if (g_find.find_class == CKO_PUBLIC_KEY) {
                g_find.return_priv = CK_FALSE;
            }
        }
        if (pTemplate[i].type == CKA_ID && pTemplate[i].pValue && pTemplate[i].ulValueLen > 0) {
            /* Filter by firmware key ID — map to internal index */
            CK_BYTE fw_id = *(CK_BYTE *)pTemplate[i].pValue;
            g_find.filter_id = CK_TRUE;
            g_find.filter_fw_id = fw_id;
            DBG("C_FindObjectsInit: filter by fw_key_id=%u", fw_id);
        }
    }

    g_find.active = CK_TRUE;
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE *phObject,
                     CK_ULONG ulMaxObjectCount, CK_ULONG *pulObjectCount)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (hSession != SESSION_HANDLE || !g_session_open)
        return CKR_SESSION_HANDLE_INVALID;
    if (!g_find.active) return CKR_OPERATION_NOT_INITIALIZED;
    if (!phObject || !pulObjectCount) return CKR_ARGUMENTS_BAD;

    CK_ULONG count = 0;

    while (g_find.next_key < g_num_keys && count < ulMaxObjectCount) {
        int k = g_find.next_key;

        /* Skip keys that don't match the ID filter */
        if (g_find.filter_id && g_keys[k].fw_key_id != g_find.filter_fw_id) {
            g_find.next_key++;
            continue;
        }

        if (g_find.return_priv) {
            phObject[count++] = PRIV_HANDLE(k);
            DBG("C_FindObjects: returning PRIV handle=%lu (fw_id=%u)",
                PRIV_HANDLE(k), g_keys[k].fw_key_id);
            if (count >= ulMaxObjectCount) {
                /* Come back for the public key on next call */
                if (g_find.return_pub) {
                    g_find.return_priv = CK_FALSE;
                    break;
                }
                g_find.next_key++;
                break;
            }
        }

        if (g_find.return_pub) {
            phObject[count++] = PUB_HANDLE(k);
            DBG("C_FindObjects: returning PUB handle=%lu (fw_id=%u)",
                PUB_HANDLE(k), g_keys[k].fw_key_id);
        }

        g_find.next_key++;
        g_find.return_priv = !g_find.filter_class || g_find.find_class == CKO_PRIVATE_KEY;
        g_find.return_pub = !g_find.filter_class || g_find.find_class == CKO_PUBLIC_KEY;
    }

    *pulObjectCount = count;
    return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (hSession != SESSION_HANDLE || !g_session_open)
        return CKR_SESSION_HANDLE_INVALID;
    g_find.active = CK_FALSE;
    return CKR_OK;
}

/* --- Attribute retrieval ------------------------------------------------- */

static CK_RV set_attr(CK_ATTRIBUTE *attr, const void *data, CK_ULONG len)
{
    if (!attr->pValue) {
        attr->ulValueLen = len;
        return CKR_OK;
    }
    if (attr->ulValueLen < len) {
        attr->ulValueLen = len;
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(attr->pValue, data, len);
    attr->ulValueLen = len;
    return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                           CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (hSession != SESSION_HANDLE || !g_session_open)
        return CKR_SESSION_HANDLE_INVALID;
    if (hObject == CK_INVALID_HANDLE) return CKR_OBJECT_HANDLE_INVALID;

    int key_id = (int)HANDLE_KEY_ID(hObject);
    CK_BBOOL is_priv = HANDLE_IS_PRIV(hObject);

    if (key_id < 0 || key_id >= g_num_keys || !g_keys[key_id].valid)
        return CKR_OBJECT_HANDLE_INVALID;

    CK_RV rv = CKR_OK;

    DBG("C_GetAttributeValue: handle=%lu count=%lu is_priv=%d key=%d",
        hObject, ulCount, is_priv, key_id);

    for (CK_ULONG i = 0; i < ulCount; i++) {
        CK_RV attr_rv = CKR_OK;

        switch (pTemplate[i].type) {
        case CKA_CLASS: {
            CK_OBJECT_CLASS cls = is_priv ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
            attr_rv = set_attr(&pTemplate[i], &cls, sizeof(cls));
            break;
        }
        case CKA_KEY_TYPE: {
            CK_KEY_TYPE kt = CKK_EC;
            attr_rv = set_attr(&pTemplate[i], &kt, sizeof(kt));
            break;
        }
        case CKA_ID: {
            CK_BYTE id = (CK_BYTE)g_keys[key_id].fw_key_id;
            attr_rv = set_attr(&pTemplate[i], &id, 1);
            break;
        }
        case CKA_LABEL: {
            char label[32];
            int len = snprintf(label, sizeof(label), "OTP Key %u", g_keys[key_id].fw_key_id);
            attr_rv = set_attr(&pTemplate[i], label, (CK_ULONG)len);
            break;
        }
        case CKA_TOKEN: {
            CK_BBOOL v = CK_TRUE;
            attr_rv = set_attr(&pTemplate[i], &v, sizeof(v));
            break;
        }
        case CKA_PRIVATE: {
            CK_BBOOL v = is_priv ? CK_TRUE : CK_FALSE;
            attr_rv = set_attr(&pTemplate[i], &v, sizeof(v));
            break;
        }
        case CKA_SIGN: {
            CK_BBOOL v = is_priv ? CK_TRUE : CK_FALSE;
            attr_rv = set_attr(&pTemplate[i], &v, sizeof(v));
            break;
        }
        case CKA_VERIFY: {
            CK_BBOOL v = is_priv ? CK_FALSE : CK_TRUE;
            attr_rv = set_attr(&pTemplate[i], &v, sizeof(v));
            break;
        }
        case CKA_SENSITIVE: {
            CK_BBOOL v = CK_TRUE;
            attr_rv = set_attr(&pTemplate[i], &v, sizeof(v));
            break;
        }
        case CKA_EXTRACTABLE: {
            CK_BBOOL v = CK_FALSE;
            attr_rv = set_attr(&pTemplate[i], &v, sizeof(v));
            break;
        }
        case CKA_ALWAYS_AUTHENTICATE:
        case CKA_MODIFIABLE:
        case CKA_COPYABLE:
        case CKA_DESTROYABLE: {
            CK_BBOOL v = CK_FALSE;
            attr_rv = set_attr(&pTemplate[i], &v, sizeof(v));
            break;
        }
        case CKA_EC_PARAMS:
            attr_rv = set_attr(&pTemplate[i], ec_params_p256, sizeof(ec_params_p256));
            break;
        case CKA_EC_POINT: {
            if (ensure_pubkey(key_id) != 0) {
                DBG("C_GetAttributeValue: CKA_EC_POINT unavailable for key %d", key_id);
                pTemplate[i].ulValueLen = (CK_ULONG)-1;
                attr_rv = CKR_ATTRIBUTE_TYPE_INVALID;
                break;
            }
            attr_rv = set_attr(&pTemplate[i],
                               g_keys[key_id].ec_point,
                               (CK_ULONG)g_keys[key_id].ec_point_len);
            break;
        }
        default:
            DBG("C_GetAttributeValue: unknown attr 0x%lx", pTemplate[i].type);
            pTemplate[i].ulValueLen = (CK_ULONG)-1;
            attr_rv = CKR_ATTRIBUTE_TYPE_INVALID;
            break;
        }

        if (attr_rv != CKR_OK)
            rv = attr_rv;
    }

    DBG("C_GetAttributeValue: returning %s (0x%lx)", ckr_str(rv), rv);
    return rv;
}

/* --- Signing ------------------------------------------------------------- */

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM *pMechanism, CK_OBJECT_HANDLE hKey)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (hSession != SESSION_HANDLE || !g_session_open)
        return CKR_SESSION_HANDLE_INVALID;
    if (g_sign.active) return CKR_OPERATION_ACTIVE;
    if (!pMechanism) return CKR_ARGUMENTS_BAD;

    DBG("C_SignInit: mech=0x%lx key_handle=%lu", pMechanism->mechanism, hKey);

    if (pMechanism->mechanism != CKM_ECDSA)
        return CKR_MECHANISM_INVALID;

    if (!HANDLE_IS_PRIV(hKey))
        return CKR_KEY_HANDLE_INVALID;

    int key_id = (int)HANDLE_KEY_ID(hKey);
    if (key_id < 0 || key_id >= g_num_keys || !g_keys[key_id].valid)
        return CKR_KEY_HANDLE_INVALID;

    g_sign.key_id = (uint32_t)key_id;
    g_sign.mech = pMechanism->mechanism;
    g_sign.hash_len = 0;
    g_sign.active = CK_TRUE;

    DBG("C_SignInit: key_id=%d OK", key_id);
    return CKR_OK;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE *pData, CK_ULONG ulDataLen,
              CK_BYTE *pSignature, CK_ULONG *pulSignatureLen)
{
    if (!g_initialized) return CKR_CRYPTOKI_NOT_INITIALIZED;
    if (hSession != SESSION_HANDLE || !g_session_open)
        return CKR_SESSION_HANDLE_INVALID;
    if (!g_sign.active) return CKR_OPERATION_NOT_INITIALIZED;
    if (!pData || !pulSignatureLen) return CKR_ARGUMENTS_BAD;

    uint8_t hash[32];
    int rc;

    /* CKM_ECDSA: input must be exactly 32 bytes (SHA-256 digest) */
    if (ulDataLen != 32) {
        g_sign.active = CK_FALSE;
        return CKR_DATA_LEN_RANGE;
    }
    memcpy(hash, pData, 32);

    /* Query output size */
    if (!pSignature) {
        /* ECDSA P-256 signature is at most 72 bytes (DER), or 64 bytes (r||s) */
        *pulSignatureLen = RPI_FW_CRYPTO_ECDSA_RESP_MAX_SIZE;
        return CKR_OK;
    }

    uint8_t sig_buf[RPI_FW_CRYPTO_ECDSA_RESP_MAX_SIZE];
    size_t sig_len = 0;

    DBG("C_Sign: calling ecdsa_sign key[%u] fw_id=%u len=%lu",
        g_sign.key_id, g_keys[g_sign.key_id].fw_key_id, ulDataLen);
    rc = rpi_fw_crypto_ecdsa_sign(0, g_keys[g_sign.key_id].fw_key_id, hash, 32,
                                  sig_buf, sizeof(sig_buf), &sig_len);
    g_sign.active = CK_FALSE;

    if (rc != 0) {
        DBG("C_Sign: ecdsa_sign failed rc=%d", rc);
        return CKR_DEVICE_ERROR;
    }
    DBG("C_Sign: signature %zu bytes", sig_len);

    if (*pulSignatureLen < (CK_ULONG)sig_len) {
        *pulSignatureLen = (CK_ULONG)sig_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(pSignature, sig_buf, sig_len);
    *pulSignatureLen = (CK_ULONG)sig_len;
    return CKR_OK;
}

/* --- Stubs for unimplemented but required functions ---------------------- */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

#define STUB(name, ...) \
    CK_RV name(__VA_ARGS__) { return CKR_FUNCTION_NOT_SUPPORTED; }

STUB(C_InitToken, CK_SLOT_ID s, CK_UTF8CHAR *p, CK_ULONG l, CK_UTF8CHAR *la)
STUB(C_InitPIN, CK_SESSION_HANDLE h, CK_UTF8CHAR *p, CK_ULONG l)
STUB(C_SetPIN, CK_SESSION_HANDLE h, CK_UTF8CHAR *o, CK_ULONG ol, CK_UTF8CHAR *n, CK_ULONG nl)
STUB(C_CreateObject, CK_SESSION_HANDLE h, CK_ATTRIBUTE *t, CK_ULONG c, CK_OBJECT_HANDLE *o)
STUB(C_CopyObject, CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o, CK_ATTRIBUTE *t, CK_ULONG c, CK_OBJECT_HANDLE *n)
STUB(C_DestroyObject, CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o)
STUB(C_GetObjectSize, CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o, CK_ULONG *s)
STUB(C_SetAttributeValue, CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o, CK_ATTRIBUTE *t, CK_ULONG c)
STUB(C_EncryptInit, CK_SESSION_HANDLE h, CK_MECHANISM *m, CK_OBJECT_HANDLE k)
STUB(C_Encrypt, CK_SESSION_HANDLE h, CK_BYTE *d, CK_ULONG dl, CK_BYTE *e, CK_ULONG *el)
STUB(C_EncryptUpdate, CK_SESSION_HANDLE h, CK_BYTE *p, CK_ULONG pl, CK_BYTE *e, CK_ULONG *el)
STUB(C_EncryptFinal, CK_SESSION_HANDLE h, CK_BYTE *e, CK_ULONG *el)
STUB(C_DecryptInit, CK_SESSION_HANDLE h, CK_MECHANISM *m, CK_OBJECT_HANDLE k)
STUB(C_Decrypt, CK_SESSION_HANDLE h, CK_BYTE *e, CK_ULONG el, CK_BYTE *d, CK_ULONG *dl)
STUB(C_DecryptUpdate, CK_SESSION_HANDLE h, CK_BYTE *e, CK_ULONG el, CK_BYTE *d, CK_ULONG *dl)
STUB(C_DecryptFinal, CK_SESSION_HANDLE h, CK_BYTE *d, CK_ULONG *dl)
STUB(C_DigestInit, CK_SESSION_HANDLE h, CK_MECHANISM *m)
STUB(C_Digest, CK_SESSION_HANDLE h, CK_BYTE *d, CK_ULONG dl, CK_BYTE *di, CK_ULONG *dil)
STUB(C_DigestUpdate, CK_SESSION_HANDLE h, CK_BYTE *p, CK_ULONG pl)
STUB(C_DigestKey, CK_SESSION_HANDLE h, CK_OBJECT_HANDLE k)
STUB(C_DigestFinal, CK_SESSION_HANDLE h, CK_BYTE *d, CK_ULONG *dl)
STUB(C_SignUpdate, CK_SESSION_HANDLE h, CK_BYTE *p, CK_ULONG pl)
STUB(C_SignFinal, CK_SESSION_HANDLE h, CK_BYTE *s, CK_ULONG *sl)
STUB(C_SignRecoverInit, CK_SESSION_HANDLE h, CK_MECHANISM *m, CK_OBJECT_HANDLE k)
STUB(C_SignRecover, CK_SESSION_HANDLE h, CK_BYTE *d, CK_ULONG dl, CK_BYTE *s, CK_ULONG *sl)
STUB(C_VerifyInit, CK_SESSION_HANDLE h, CK_MECHANISM *m, CK_OBJECT_HANDLE k)
STUB(C_Verify, CK_SESSION_HANDLE h, CK_BYTE *d, CK_ULONG dl, CK_BYTE *s, CK_ULONG sl)
STUB(C_VerifyUpdate, CK_SESSION_HANDLE h, CK_BYTE *p, CK_ULONG pl)
STUB(C_VerifyFinal, CK_SESSION_HANDLE h, CK_BYTE *s, CK_ULONG sl)
STUB(C_VerifyRecoverInit, CK_SESSION_HANDLE h, CK_MECHANISM *m, CK_OBJECT_HANDLE k)
STUB(C_VerifyRecover, CK_SESSION_HANDLE h, CK_BYTE *s, CK_ULONG sl, CK_BYTE *d, CK_ULONG *dl)
STUB(C_DigestEncryptUpdate, CK_SESSION_HANDLE h, CK_BYTE *p, CK_ULONG pl, CK_BYTE *e, CK_ULONG *el)
STUB(C_DecryptDigestUpdate, CK_SESSION_HANDLE h, CK_BYTE *e, CK_ULONG el, CK_BYTE *p, CK_ULONG *pl)
STUB(C_SignEncryptUpdate, CK_SESSION_HANDLE h, CK_BYTE *p, CK_ULONG pl, CK_BYTE *e, CK_ULONG *el)
STUB(C_DecryptVerifyUpdate, CK_SESSION_HANDLE h, CK_BYTE *e, CK_ULONG el, CK_BYTE *p, CK_ULONG *pl)
STUB(C_GenerateKey, CK_SESSION_HANDLE h, CK_MECHANISM *m, CK_ATTRIBUTE *t, CK_ULONG c, CK_OBJECT_HANDLE *k)
STUB(C_GenerateKeyPair, CK_SESSION_HANDLE h, CK_MECHANISM *m, CK_ATTRIBUTE *pu, CK_ULONG puc, CK_ATTRIBUTE *pr, CK_ULONG prc, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *prv)
STUB(C_WrapKey, CK_SESSION_HANDLE h, CK_MECHANISM *m, CK_OBJECT_HANDLE w, CK_OBJECT_HANDLE k, CK_BYTE *wk, CK_ULONG *wkl)
STUB(C_UnwrapKey, CK_SESSION_HANDLE h, CK_MECHANISM *m, CK_OBJECT_HANDLE u, CK_BYTE *wk, CK_ULONG wkl, CK_ATTRIBUTE *t, CK_ULONG tc, CK_OBJECT_HANDLE *k)
STUB(C_DeriveKey, CK_SESSION_HANDLE h, CK_MECHANISM *m, CK_OBJECT_HANDLE k, CK_ATTRIBUTE *t, CK_ULONG tc, CK_OBJECT_HANDLE *dk)
STUB(C_SeedRandom, CK_SESSION_HANDLE h, CK_BYTE *s, CK_ULONG sl)
STUB(C_GenerateRandom, CK_SESSION_HANDLE h, CK_BYTE *r, CK_ULONG rl)
STUB(C_GetFunctionStatus, CK_SESSION_HANDLE h)
STUB(C_CancelFunction, CK_SESSION_HANDLE h)
STUB(C_WaitForSlotEvent, CK_FLAGS f, CK_SLOT_ID *s, void *r)
STUB(C_GetOperationState, CK_SESSION_HANDLE h, CK_BYTE *s, CK_ULONG *sl)
STUB(C_SetOperationState, CK_SESSION_HANDLE h, CK_BYTE *s, CK_ULONG sl, CK_OBJECT_HANDLE e, CK_OBJECT_HANDLE a)

#pragma GCC diagnostic pop

/* --- Function list (PKCS#11 entry point) --------------------------------- */

static CK_FUNCTION_LIST function_list = {
    .version = { 2, 40 },
    .C_Initialize = C_Initialize,
    .C_Finalize = C_Finalize,
    .C_GetInfo = C_GetInfo,
    .C_GetFunctionList = NULL, /* set below */
    .C_GetSlotList = C_GetSlotList,
    .C_GetSlotInfo = C_GetSlotInfo,
    .C_GetTokenInfo = C_GetTokenInfo,
    .C_GetMechanismList = C_GetMechanismList,
    .C_GetMechanismInfo = C_GetMechanismInfo,
    .C_InitToken = C_InitToken,
    .C_InitPIN = C_InitPIN,
    .C_SetPIN = C_SetPIN,
    .C_OpenSession = C_OpenSession,
    .C_CloseSession = C_CloseSession,
    .C_CloseAllSessions = C_CloseAllSessions,
    .C_GetSessionInfo = C_GetSessionInfo,
    .C_GetOperationState = C_GetOperationState,
    .C_SetOperationState = C_SetOperationState,
    .C_Login = C_Login,
    .C_Logout = C_Logout,
    .C_CreateObject = C_CreateObject,
    .C_CopyObject = C_CopyObject,
    .C_DestroyObject = C_DestroyObject,
    .C_GetObjectSize = C_GetObjectSize,
    .C_GetAttributeValue = C_GetAttributeValue,
    .C_SetAttributeValue = C_SetAttributeValue,
    .C_FindObjectsInit = C_FindObjectsInit,
    .C_FindObjects = C_FindObjects,
    .C_FindObjectsFinal = C_FindObjectsFinal,
    .C_EncryptInit = C_EncryptInit,
    .C_Encrypt = C_Encrypt,
    .C_EncryptUpdate = C_EncryptUpdate,
    .C_EncryptFinal = C_EncryptFinal,
    .C_DecryptInit = C_DecryptInit,
    .C_Decrypt = C_Decrypt,
    .C_DecryptUpdate = C_DecryptUpdate,
    .C_DecryptFinal = C_DecryptFinal,
    .C_DigestInit = C_DigestInit,
    .C_Digest = C_Digest,
    .C_DigestUpdate = C_DigestUpdate,
    .C_DigestKey = C_DigestKey,
    .C_DigestFinal = C_DigestFinal,
    .C_SignInit = C_SignInit,
    .C_Sign = C_Sign,
    .C_SignUpdate = C_SignUpdate,
    .C_SignFinal = C_SignFinal,
    .C_SignRecoverInit = C_SignRecoverInit,
    .C_SignRecover = C_SignRecover,
    .C_VerifyInit = C_VerifyInit,
    .C_Verify = C_Verify,
    .C_VerifyUpdate = C_VerifyUpdate,
    .C_VerifyFinal = C_VerifyFinal,
    .C_VerifyRecoverInit = C_VerifyRecoverInit,
    .C_VerifyRecover = C_VerifyRecover,
    .C_DigestEncryptUpdate = C_DigestEncryptUpdate,
    .C_DecryptDigestUpdate = C_DecryptDigestUpdate,
    .C_SignEncryptUpdate = C_SignEncryptUpdate,
    .C_DecryptVerifyUpdate = C_DecryptVerifyUpdate,
    .C_GenerateKey = C_GenerateKey,
    .C_GenerateKeyPair = C_GenerateKeyPair,
    .C_WrapKey = C_WrapKey,
    .C_UnwrapKey = C_UnwrapKey,
    .C_DeriveKey = C_DeriveKey,
    .C_SeedRandom = C_SeedRandom,
    .C_GenerateRandom = C_GenerateRandom,
    .C_GetFunctionStatus = C_GetFunctionStatus,
    .C_CancelFunction = C_CancelFunction,
    .C_WaitForSlotEvent = C_WaitForSlotEvent,
};

/* --- PKCS#11 entry point: C_GetFunctionList ------------------------------ */

CK_RV C_GetFunctionList(CK_FUNCTION_LIST **ppFunctionList)
{
    if (!ppFunctionList) return CKR_ARGUMENTS_BAD;
    function_list.C_GetFunctionList = C_GetFunctionList;
    *ppFunctionList = &function_list;
    DBG("C_GetFunctionList: OK");
    return CKR_OK;
}
