// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * (C) Copyright 2026
 * Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
 *
 * Minimal PKCS#11 type definitions (OASIS PKCS#11 v2.40 compatible)
 * Only the subset needed for the rpifwcrypto PKCS#11 module.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#ifndef PKCS11_TYPES_H
#define PKCS11_TYPES_H

#include <stdint.h>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#define NULL_PTR 0

typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_CHAR;
typedef CK_BYTE CK_UTF8CHAR;
typedef CK_BYTE CK_BBOOL;
typedef unsigned long CK_ULONG;
typedef long CK_LONG;
typedef CK_ULONG CK_FLAGS;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_OBJECT_CLASS;
typedef CK_ULONG CK_KEY_TYPE;
typedef CK_ULONG CK_ATTRIBUTE_TYPE;
typedef CK_ULONG CK_MECHANISM_TYPE;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_STATE;
typedef CK_ULONG CK_USER_TYPE;
typedef void CK_PTR CK_NOTIFY;

#define CK_TRUE  1
#define CK_FALSE 0

#define CK_INVALID_HANDLE 0

/* Return values */
#define CKR_OK                          0x00000000
#define CKR_CANCEL                      0x00000001
#define CKR_SLOT_ID_INVALID             0x00000003
#define CKR_GENERAL_ERROR               0x00000005
#define CKR_ARGUMENTS_BAD               0x00000007
#define CKR_ATTRIBUTE_TYPE_INVALID      0x00000012
#define CKR_ATTRIBUTE_VALUE_INVALID     0x00000013
#define CKR_BUFFER_TOO_SMALL            0x00000150
#define CKR_CRYPTOKI_NOT_INITIALIZED    0x00000190
#define CKR_CRYPTOKI_ALREADY_INITIALIZED 0x00000191
#define CKR_DATA_INVALID                0x00000020
#define CKR_DATA_LEN_RANGE              0x00000021
#define CKR_DEVICE_ERROR                0x00000030
#define CKR_DEVICE_MEMORY               0x00000031
#define CKR_FUNCTION_FAILED             0x00000006
#define CKR_FUNCTION_NOT_SUPPORTED      0x00000054
#define CKR_KEY_HANDLE_INVALID          0x00000060
#define CKR_MECHANISM_INVALID           0x00000070
#define CKR_MECHANISM_PARAM_INVALID     0x00000071
#define CKR_OBJECT_HANDLE_INVALID       0x00000082
#define CKR_OPERATION_ACTIVE            0x00000090
#define CKR_OPERATION_NOT_INITIALIZED   0x00000091
#define CKR_SESSION_HANDLE_INVALID      0x000000B3
#define CKR_SESSION_CLOSED              0x000000B0
#define CKR_SIGNATURE_INVALID           0x000000C0
#define CKR_SIGNATURE_LEN_RANGE         0x000000C1
#define CKR_TOKEN_NOT_PRESENT           0x000000E0
#define CKR_TOKEN_NOT_RECOGNIZED        0x000000E1

/* Object classes */
#define CKO_PUBLIC_KEY   0x00000002
#define CKO_PRIVATE_KEY  0x00000003

/* Key types */
#define CKK_EC  0x00000003

/* Attribute types */
#define CKA_CLASS              0x00000000
#define CKA_TOKEN              0x00000001
#define CKA_PRIVATE            0x00000002
#define CKA_LABEL              0x00000003
#define CKA_VALUE              0x00000011
#define CKA_KEY_TYPE           0x00000100
#define CKA_ID                 0x00000102
#define CKA_SENSITIVE          0x00000103
#define CKA_SIGN               0x00000108
#define CKA_VERIFY             0x0000010A
#define CKA_EC_PARAMS          0x00000180
#define CKA_EC_POINT           0x00000181
#define CKA_MODIFIABLE         0x00000170
#define CKA_COPYABLE           0x00000171
#define CKA_DESTROYABLE        0x00000172
#define CKA_ALWAYS_AUTHENTICATE 0x00000202
#define CKA_EXTRACTABLE        0x00000162

/* Mechanism types */
#define CKM_ECDSA              0x00001041
#define CKM_ECDSA_SHA256       0x00001044

/* Flags for C_Initialize */
#define CKF_OS_LOCKING_OK      0x00000002

/* Flags for CK_TOKEN_INFO */
#define CKF_TOKEN_INITIALIZED       0x00000400
#define CKF_LOGIN_REQUIRED          0x00000004
#define CKF_USER_PIN_INITIALIZED    0x00000008
#define CKF_PROTECTED_AUTHENTICATION_PATH 0x00000100

/* Flags for CK_SLOT_INFO */
#define CKF_TOKEN_PRESENT      0x00000001
#define CKF_HW_SLOT            0x00000004

/* Flags for CK_SESSION_INFO */
#define CKF_SERIAL_SESSION     0x00000004
#define CKF_RW_SESSION         0x00000002

/* Session states */
#define CKS_RO_PUBLIC_SESSION  0
#define CKS_RW_PUBLIC_SESSION  2

/* User types */
#define CKU_SO                 0
#define CKU_USER               1

/* Mechanism info flags */
#define CKF_SIGN               0x00000800
#define CKF_EC_F_P             0x00100000

typedef struct CK_VERSION {
    CK_BYTE major;
    CK_BYTE minor;
} CK_VERSION;

typedef struct CK_INFO {
    CK_VERSION cryptokiVersion;
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_UTF8CHAR libraryDescription[32];
    CK_VERSION libraryVersion;
} CK_INFO;

typedef struct CK_SLOT_INFO {
    CK_UTF8CHAR slotDescription[64];
    CK_UTF8CHAR manufacturerID[32];
    CK_FLAGS flags;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
} CK_SLOT_INFO;

typedef struct CK_TOKEN_INFO {
    CK_UTF8CHAR label[32];
    CK_UTF8CHAR manufacturerID[32];
    CK_UTF8CHAR model[16];
    CK_CHAR serialNumber[16];
    CK_FLAGS flags;
    CK_ULONG ulMaxSessionCount;
    CK_ULONG ulSessionCount;
    CK_ULONG ulMaxRwSessionCount;
    CK_ULONG ulRwSessionCount;
    CK_ULONG ulMaxPinLen;
    CK_ULONG ulMinPinLen;
    CK_ULONG ulTotalPublicMemory;
    CK_ULONG ulFreePublicMemory;
    CK_ULONG ulTotalPrivateMemory;
    CK_ULONG ulFreePrivateMemory;
    CK_VERSION hardwareVersion;
    CK_VERSION firmwareVersion;
    CK_CHAR utcTime[16];
} CK_TOKEN_INFO;

typedef struct CK_SESSION_INFO {
    CK_SLOT_ID slotID;
    CK_STATE state;
    CK_FLAGS flags;
    CK_ULONG ulDeviceError;
} CK_SESSION_INFO;

typedef struct CK_MECHANISM {
    CK_MECHANISM_TYPE mechanism;
    void *pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;

typedef struct CK_MECHANISM_INFO {
    CK_ULONG ulMinKeySize;
    CK_ULONG ulMaxKeySize;
    CK_FLAGS flags;
} CK_MECHANISM_INFO;

typedef struct CK_ATTRIBUTE {
    CK_ATTRIBUTE_TYPE type;
    void *pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

typedef struct CK_C_INITIALIZE_ARGS {
    void *CreateMutex;
    void *DestroyMutex;
    void *LockMutex;
    void *UnlockMutex;
    CK_FLAGS flags;
    void *pReserved;
} CK_C_INITIALIZE_ARGS;

/* Forward declare function list */
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR *CK_FUNCTION_LIST_PTR_PTR;

#endif /* PKCS11_TYPES_H */
