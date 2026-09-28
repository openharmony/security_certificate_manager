/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CM_TYPE_H
#define CM_TYPE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/* Error code definitions split into cm_error_code.h (to cap single-header
 * line count); re-exported here, values and compatibility unchanged */
#include "cm_error_code.h"

#ifdef __cplusplus
extern "C" {
#endif
#ifndef CM_API_PUBLIC
    #if defined(WIN32) || defined(_WIN32) || defined(__CYGWIN__) || defined(__ICCARM__) /* __ICCARM__ for iar */
        #define CM_API_EXPORT
    #else
        #define CM_API_EXPORT __attribute__ ((visibility("default")))
    #endif
#else
    #define CM_API_EXPORT __attribute__ ((visibility("default")))
#endif

#define MAX_LEN_CERTIFICATE      8196
#define MAX_LEN_CERTIFICATE_P7B  (1024 * 300)
#define MAX_LEN_UKEY_CERT_IMPORT  10240

#define MAX_LEN_CERTIFICATE_CHAIN    (3 * MAX_LEN_CERTIFICATE)

#define MAX_SUFFIX_LEN           16
#define MAX_COUNT_CERTIFICATE    256
#define MAX_COUNT_CERTIFICATE_ALL  512
#define MAX_P7B_INSTALL_COUNT    256
#define MAX_LEN_URI              256
#define MAX_AUTH_LEN_URI         256
#define MAX_LEN_CERT_ALIAS       129    /* include 1 byte: the terminator('\0') */
#define MAX_LEN_SUBJECT_NAME     1025   /* include 1 byte: the terminator('\0') */
#define MAX_LEN_PACKGE_NAME      64
#define MAX_LEN_MAC_KEY          64
#define MAX_UINT32_LEN           16
#define MAX_LEN_CERT_TYPE        8
#define MAX_LEN_PRI_CRED_ALIAS   33     /* include 1 byte: the terminator('\0') */
#define MAX_COUNT_UKEY_CERTIFICATE 36

#define MAX_LEN_ISSUER_NAME             256
#define MAX_LEN_SERIAL                  64
#define MAX_LEN_NOT_BEFORE              32
#define MAX_LEN_NOT_AFTER               32
#define MAX_LEN_FINGER_PRINT_SHA256     128
#define MAX_LEN_APP_CERT 20480
#define MAX_LEN_APP_CERT_PASSWD 33   /* 32位密码 + 1位结束符 */
#define MAX_LEN_CRED_PRI_KEY     4096

#define CERT_MAX_PATH_LEN       256
#define CM_ARRAY_SIZE(arr) ((sizeof(arr)) / (sizeof((arr)[0])))
#define INIT_INVALID_VALUE      0xFFFFFFFF

#define CERT_STATUS_ENABLED    ((uint32_t) 0)
#define CERT_STATUS_DISABLED   ((uint32_t) 1)

#define ERROR_LEVEL 0

/*
 * Align to 4-tuple
 * Before calling this function, ensure that the size does not overflow after 3 is added.
 */
#define ALIGN_SIZE(size) ((((uint32_t)(size) + 3) >> 2) << 2)

#define CM_BITS_PER_BYTE 8
#define CM_KEY_BYTES(keySize) (((keySize) + CM_BITS_PER_BYTE - 1) / CM_BITS_PER_BYTE)
#define MAX_OUT_BLOB_SIZE (5 * 1024 * 1024)

#define CM_CREDENTIAL_STORE             0
#define CM_SYSTEM_TRUSTED_STORE         1
#define CM_USER_TRUSTED_STORE           2
#define CM_PRI_CREDENTIAL_STORE         3
#define CM_SYS_CREDENTIAL_STORE         4
#define CM_STORE_CHECK(a) \
    (((a) != CM_CREDENTIAL_STORE) && ((a) != CM_PRI_CREDENTIAL_STORE) && ((a) != CM_SYS_CREDENTIAL_STORE))
#define CM_LEVEL_CHECK(a) \
    (((a) != CM_AUTH_STORAGE_LEVEL_EL1) && ((a) != CM_AUTH_STORAGE_LEVEL_EL2) && ((a) != CM_AUTH_STORAGE_LEVEL_EL4))
#define CM_CRED_FORMAT_CHECK(a) (((a) != FILE_P12) && ((a) != CHAIN_KEY))
#define CM_DETECT_ALIAS_CHECK(a) (((a) != DEFAULT_FORMAT) && ((a) != SHA256_FORMAT))

#define CA_STORE_PATH_SYSTEM              "/etc/security/certificates"
#define CA_STORE_PATH_SYSTEM_SM           "/etc/security/certificates_gm"
#define SYSTEM_CA_STORE_GM                "/system/etc/security/certificates_gm/"
#define CA_STORE_PATH_USER_SANDBOX_BASE   "/data/certificates/user_cacerts/"
#define CA_STORE_PATH_USER_SERVICE_BASE   "/data/service/el1/public/cert_manager_service/certificates/user_open/"

enum CmKeyDigest {
    CM_DIGEST_NONE = 0,
    CM_DIGEST_MD5 = 1,
    CM_DIGEST_SM3 = 2,
    CM_DIGEST_SHA1 = 10,
    CM_DIGEST_SHA224 = 11,
    CM_DIGEST_SHA256 = 12,
    CM_DIGEST_SHA384 = 13,
    CM_DIGEST_SHA512 = 14,
};

enum CmKeyPurpose {
    CM_KEY_PURPOSE_ENCRYPT = 1,                   /* Usable with RSA, EC, AES, and SM4 keys. */
    CM_KEY_PURPOSE_DECRYPT = 2,                   /* Usable with RSA, EC, AES, and SM4 keys. */
    CM_KEY_PURPOSE_SIGN = 4,                      /* Usable with RSA, EC keys. */
    CM_KEY_PURPOSE_VERIFY = 8,                    /* Usable with RSA, EC keys. */
    CM_KEY_PURPOSE_DERIVE = 16,                   /* Usable with EC keys. */
    CM_KEY_PURPOSE_WRAP = 32,                     /* Usable with wrap key. */
    CM_KEY_PURPOSE_UNWRAP = 64,                   /* Usable with unwrap key. */
    CM_KEY_PURPOSE_MAC = 128,                     /* Usable with mac. */
    CM_KEY_PURPOSE_AGREE = 256,                   /* Usable with agree. */
};

enum CmKeyPadding {
    CM_PADDING_NONE = 0,
    CM_PADDING_OAEP = 1,
    CM_PADDING_PSS = 2,
    CM_PADDING_PKCS1_V1_5 = 3,
    CM_PADDING_PKCS5 = 4,
    CM_PADDING_PKCS7 = 5,
};

enum CMErrorCode { /* temp use */
    CMR_OK = 0,
    CMR_ERROR = -1,
};

enum CmTagType {
    CM_TAG_TYPE_INVALID = 0 << 28,
    CM_TAG_TYPE_INT = 1 << 28,
    CM_TAG_TYPE_UINT = 2 << 28,
    CM_TAG_TYPE_ULONG = 3 << 28,
    CM_TAG_TYPE_BOOL = 4 << 28,
    CM_TAG_TYPE_BYTES = 5 << 28,
};

enum CmTag {
    /* Inner-use TAGS used for ipc serialization */
    CM_TAG_PARAM0_BUFFER = CM_TAG_TYPE_BYTES | 30001,
    CM_TAG_PARAM1_BUFFER = CM_TAG_TYPE_BYTES | 30002,
    CM_TAG_PARAM2_BUFFER = CM_TAG_TYPE_BYTES | 30003,
    CM_TAG_PARAM3_BUFFER = CM_TAG_TYPE_BYTES | 30004,
    CM_TAG_PARAM4_BUFFER = CM_TAG_TYPE_BYTES | 30005,
    CM_TAG_PARAM0_UINT32 = CM_TAG_TYPE_UINT | 30006,
    CM_TAG_PARAM1_UINT32 = CM_TAG_TYPE_UINT | 30007,
    CM_TAG_PARAM2_UINT32 = CM_TAG_TYPE_UINT | 30008,
    CM_TAG_PARAM3_UINT32 = CM_TAG_TYPE_UINT | 30009,
    CM_TAG_PARAM4_UINT32 = CM_TAG_TYPE_UINT | 30010,
    CM_TAG_PARAM0_BOOL = CM_TAG_TYPE_BOOL | 30011,
    CM_TAG_PARAM1_BOOL = CM_TAG_TYPE_BOOL | 30012,
    CM_TAG_PARAM2_BOOL = CM_TAG_TYPE_BOOL | 30013,
    CM_TAG_PARAM3_BOOL = CM_TAG_TYPE_BOOL | 30014,
    CM_TAG_PARAM4_BOOL = CM_TAG_TYPE_BOOL | 30015,
    CM_TAG_PARAM0_NULL = CM_TAG_TYPE_BYTES | 30016,
    CM_TAG_PARAM1_NULL = CM_TAG_TYPE_BYTES | 30017,
    CM_TAG_PARAM2_NULL = CM_TAG_TYPE_BYTES | 30018,
    CM_TAG_PARAM3_NULL = CM_TAG_TYPE_BYTES | 30019,
    CM_TAG_PARAM4_NULL = CM_TAG_TYPE_BYTES | 30020,
};

enum CmCertificatePurpose {
    CM_CERT_PURPOSE_DEFAULT = 0,
    CM_CERT_PURPOSE_ALL = 1,
    CM_CERT_PURPOSE_SIGN = 2,
    CM_CERT_PURPOSE_ENCRYPT = 3,
};

enum CmPermissionState {
    CM_PERMISSION_DENIED = 0,
    CM_PERMISSION_GRANTED = 1,
};

#define CM_PARAM_BUFFER_NULL_INTERVAL ((CM_TAG_PARAM0_NULL) - (CM_TAG_PARAM0_BUFFER))

enum CmSendType {
    CM_SEND_TYPE_ASYNC = 0,
    CM_SEND_TYPE_SYNC,
};

struct CmMutableBlob {
    uint32_t size;
    uint8_t *data;
};

struct CmContext {
    uint32_t userId;
    uint32_t uid;
    char packageName[MAX_LEN_PACKGE_NAME];
};

struct CmBlob {
    uint32_t size;
    uint8_t *data;
};

struct CertBlob {
    struct CmBlob uri[MAX_COUNT_CERTIFICATE_ALL];
    struct CmBlob certAlias[MAX_COUNT_CERTIFICATE_ALL];
    struct CmBlob subjectName[MAX_COUNT_CERTIFICATE_ALL];
};

struct CmAppCertInfo {
    struct CmBlob appCert;
    struct CmBlob appCertPwd;
};

struct CertListAbtInfo {
    uint32_t uriSize;
    char uri[MAX_LEN_URI];
    uint32_t aliasSize;
    char certAlias[MAX_LEN_CERT_ALIAS];
    uint32_t status;
    uint32_t subjectNameSize;
    char subjectName[MAX_LEN_SUBJECT_NAME];
};

struct CertAbstract {
    char uri[MAX_LEN_URI];
    char certAlias[MAX_LEN_CERT_ALIAS];
    bool status;
    char subjectName[MAX_LEN_SUBJECT_NAME];
};

struct CertList {
    uint32_t certsCount;
    struct CertAbstract *certAbstract;
};

struct CertAbtInfo {
    uint32_t aliasSize;
    char certAlias[MAX_LEN_CERT_ALIAS];
    uint32_t status;
    uint32_t certsize;
    uint8_t certData[MAX_LEN_CERTIFICATE];
};

struct CertInfo {
    char uri[MAX_LEN_URI];
    char certAlias[MAX_LEN_CERT_ALIAS];
    bool status;
    char issuerName[MAX_LEN_ISSUER_NAME];
    char subjectName[MAX_LEN_SUBJECT_NAME];
    char serial[MAX_LEN_SERIAL];
    char notBefore[MAX_LEN_NOT_BEFORE];
    char notAfter[MAX_LEN_NOT_AFTER];
    char fingerprintSha256[MAX_LEN_FINGER_PRINT_SHA256];
    struct CmBlob certInfo;
};

struct CertFile {
    const struct CmBlob *fileName;
    const struct CmBlob *path;
};

struct CertFileInfo {
    struct CmBlob fileName;
    struct CmBlob path;
};

struct CMApp {
    uint32_t userId;
    uint32_t uid;
    const char *packageName;
    struct CmBlob *appId; // for attestation
};

struct Credential {
    uint32_t isExist;
    char type[MAX_LEN_SUBJECT_NAME];
    char alias[MAX_LEN_CERT_ALIAS];
    char keyUri[MAX_LEN_URI];
    uint32_t certNum;
    uint32_t keyNum;
    struct CmBlob credData;
    enum CmCertificatePurpose certPurpose;
};

struct CredentialDetailList {
    uint32_t credentialCount;
    struct Credential *credential;
};

struct CredentialAbstract {
    char type[MAX_LEN_SUBJECT_NAME];
    char alias[MAX_LEN_CERT_ALIAS];
    char keyUri[MAX_LEN_URI];
};

struct CredentialList {
    uint32_t credentialCount;
    struct CredentialAbstract *credentialAbstract;
};

struct AppCert {
    uint32_t certCount;
    uint32_t keyCount;
    uint32_t certSize;
    uint8_t appCertdata[MAX_LEN_CERTIFICATE_CHAIN];
};

struct CmParam {
    uint32_t tag;
    union {
        bool boolParam;
        int32_t int32Param;
        uint32_t uint32Param;
        uint64_t uint64Param;
        struct CmBlob blob;
    };
};

struct CmParamOut {
    uint32_t tag;
    union {
        bool *boolParam;
        int32_t *int32Param;
        uint32_t *uint32Param;
        uint64_t *uint64Param;
        struct CmBlob *blob;
    };
};

struct CmParamSet {
    uint32_t paramSetSize;
    uint32_t paramsCnt;
    struct CmParam params[];
};

struct CmAppUidList {
    uint32_t appUidCount;
    uint32_t *appUid;
};

struct CmSignatureSpec {
    uint32_t purpose;
    uint32_t padding;
    uint32_t digest;
};

enum CmAuthStorageLevel {
    CM_AUTH_STORAGE_LEVEL_EL1 = 1,
    CM_AUTH_STORAGE_LEVEL_EL2 = 2,
    CM_AUTH_STORAGE_LEVEL_EL4 = 4,
};

enum CredFormat {
    FILE_P12,
    // cert chain and private key
    CHAIN_KEY,
};

// There is Chinese for the alias in the lake
enum AliasTransFormat {
    DEFAULT_FORMAT,
    SHA256_FORMAT,
};

struct CmAppCertParam {
    struct CmBlob *appCert;
    struct CmBlob *appCertPwd;
    struct CmBlob *certAlias;
    uint32_t store;
    uint32_t userId;
    enum CmAuthStorageLevel level;
    enum CredFormat credFormat;
    // In lake cred format is certChain + privKey
    struct CmBlob *appCertPrivKey;
    enum AliasTransFormat aliasFormat;
};

struct CertName {
    struct CmBlob *displayName;
    struct CmBlob *objectName;
    struct CmBlob *subjectName;
};

enum CmCertType {
    CM_CA_CERT_SYSTEM = 0,
    CM_CA_CERT_USER = 1,
};

enum CmCertScope {
    CM_ALL_USER = 0,
    CM_CURRENT_USER = 1,
    CM_GLOBAL_USER = 2,
};

enum CmCertFileFormat {
    PEM_DER = 0,
    P7B = 1,
};

struct UserCAProperty {
    uint32_t userId;
    enum CmCertScope scope;
};

struct CmInstallCertInfo {
    const struct CmBlob *userCert;
    const struct CmBlob *certAlias;
    uint32_t userId;
};

struct CertUriList {
    uint32_t certCount;
    struct CmBlob *uriList;
};

struct InstallUserCertParams {
    struct CmContext *cmContext;
    struct CmBlob *userCert;
    struct CmBlob *certAlias;
    struct CmBlob *outData;
    uint32_t status;
};

struct UkeyInfo {
    enum CmCertificatePurpose certPurpose;
};

/* Opaque caller data delivered (base64-encoded) to custom dialogs only (spec D9/D19). */
#define CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE 2048

struct UkeyAuthRequest {
    struct CmBlob keyUri; /* ukey credential uri, max 256 bytes */
    uint32_t timeoutDuration; /* auth timeout in seconds, 0 = default (server: 300s);
                                  server clamps explicit values to [3min, 10min] */
    struct CmBlob customData; /* raw caller data, max CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE bytes;
                                  size 0 / NULL data = absent; never persisted or logged */
};

/* UKey driver dialog extension info (aligned with d.ts UkeyAuthDialogInfo,
 * spec v4 D24/v4.1: abilityName capped at 256 bytes, see
 * CM_UKEY_ABILITY_NAME_MAX_LEN):
 * input of openAuthDialogForUkeyProvider; the bundle is resolved server-side
 * from the IPC token (not declarable) */
struct UkeyAuthDialogInfo {
    struct CmBlob abilityName; /* driver dialog extension name, non-empty, max 256 bytes, NUL-terminated */
    uint32_t abilityType;      /* enum value, CM_UKEY_ABILITY_TYPE_UIEXTENSION only */
};

static inline bool CmIsAdditionOverflow(uint32_t a, uint32_t b)
{
    return (UINT32_MAX - a) < b;
}

static inline int32_t CmCheckBlob(const struct CmBlob *blob)
{
    if ((blob == NULL) || (blob->data == NULL) || (blob->size == 0)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

static inline int32_t CmCheckInstallCertInfo(const struct CmInstallCertInfo *installCertInfo)
{
    if (installCertInfo == NULL || CmCheckBlob(installCertInfo->certAlias) != CM_SUCCESS ||
        CmCheckBlob(installCertInfo->userCert) != CM_SUCCESS) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* CM_TYPE_H */
