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

#define MAX_LEN_ISSUER_NAME             256
#define MAX_LEN_SERIAL                  64
#define MAX_LEN_NOT_BEFORE              32
#define MAX_LEN_NOT_AFTER               32
#define MAX_LEN_FINGER_PRINT_SHA256     128
#define MAX_LEN_APP_CERT 20480
#define MAX_LEN_APP_CERT_PASSWD 33   /* 32位密码 + 1位结束符 */

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

enum CmErrorCode {
    CM_SUCCESS = 0,
    CM_FAILURE = -1,

    CMR_ERROR_NOT_PERMITTED = -2,
    CMR_ERROR_NOT_SUPPORTED = -3,
    CMR_ERROR_STORAGE = -4,
    CMR_ERROR_NOT_FOUND = -5,
    CMR_ERROR_NULL_POINTER = -6,
    CMR_ERROR_INVALID_ARGUMENT = -7,
    CMR_ERROR_MAKE_DIR_FAIL = -8,
    CMR_ERROR_INVALID_OPERATION = -9,
    CMR_ERROR_OPEN_FILE_FAIL = -10,
    CMR_ERROR_READ_FILE_ERROR = -11,
    CMR_ERROR_WRITE_FILE_FAIL = -12,
    CMR_ERROR_REMOVE_FILE_FAIL = -13,
    CMR_ERROR_CLOSE_FILE_FAIL = -14,
    CMR_ERROR_MALLOC_FAIL = -15,
    CMR_ERROR_NOT_EXIST = -16,
    CMR_ERROR_ALREADY_EXISTS = -17,
    CMR_ERROR_INSUFFICIENT_DATA = -18,
    CMR_ERROR_BUFFER_TOO_SMALL = -19,
    CMR_ERROR_INVALID_CERT_FORMAT = -20,
    CMR_ERROR_PARAM_NOT_EXIST = -21,
    CMR_ERROR_SESSION_REACHED_LIMIT = -22,
    CMR_ERROR_PERMISSION_DENIED = -23,
    CMR_ERROR_AUTH_CHECK_FAILED = -24,
    CMR_ERROR_KEY_OPERATION_FAILED = -25,
    CMR_ERROR_NOT_SYSTEMP_APP = -26,
    CMR_ERROR_MAX_CERT_COUNT_REACHED = -27,
    CMR_ERROR_ALIAS_LENGTH_REACHED_LIMIT = -28,
    CMR_ERROR_GET_ADVSECMODE_PARAM_FAIL = -29,
    CMR_ERROR_DEVICE_ENTER_ADVSECMODE = -30,
    CMR_ERROR_CREATE_RDB_TABLE_FAIL = -31,
    CMR_ERROR_INSERT_RDB_DATA_FAIL = -32,
    CMR_ERROR_UPDATE_RDB_DATA_FAIL = -33,
    CMR_ERROR_DELETE_RDB_DATA_FAIL = -34,
    CMR_ERROR_QUERY_RDB_DATA_FAIL = -35,
    CMR_ERROR_PASSWORD_IS_ERR = -36,

    CMR_ERROR_OPENSSL_FAIL = -37,
    CMR_ERROR_MAX_GRANT_COUNT_REACHED = -38,
    CMR_ERROR_SA_START_STATUS_INIT_FAILED = -39,
    CMR_ERROR_SA_START_HUKS_INIT_FAILED = -40,
    CMR_ERROR_SA_START_PUBLISH_FAILED = -41,
    CMR_ERROR_IPC_PARAM_SIZE_INVALID = -42,
    CMR_ERROR_GET_LOCAL_TIME_FAILED = -43,
    CMR_ERROR_MEM_OPERATION_COPY = -44,
    CMR_ERROR_MEM_OPERATION_PRINT = -45,
    CMR_ERROR_FILE_OPEN_DIR = -46,
    CMR_ERROR_FILE_STAT = -47,
    CMR_ERROR_CERT_COUNT_MISMATCH = -48,
    CMR_ERROR_GET_CERT_STATUS = -49,
    CMR_ERROR_GET_CERT_SUBJECT_ITEM = -50,

    /* invalid argument */
    CMR_ERROR_INVALID_ARGUMENT_BEGIN = -10000,
    CMR_ERROR_INVALID_PARAMSET_ARG = -10001,
    CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE = -10002,
    CMR_ERROR_INVALID_ARGUMENT_SCOPE = -10003,
    CMR_ERROR_INVALID_ARGUMENT_USER_ID = -10004,
    CMR_ERROR_INVALID_ARGUMENT_UID = -10005,
    CMR_ERROR_INVALID_ARGUMENT_URI = -10006,
    CMR_ERROR_INVALID_ARGUMENT_STATUS = -10007,
    CMR_ERROR_INVALID_ARGUMENT_APP_CERT = -10008,
    CMR_ERROR_INVALID_ARGUMENT_APP_PWD = -10009,
    CMR_ERROR_INVALID_ARGUMENT_ALIAS = -10010,
    CMR_ERROR_INVALID_ARGUMENT_SIGN_SPEC = -10011,
    CMR_ERROR_INVALID_ARGUMENT_HANDLE = -10012,
    CMR_ERROR_INVALID_ARGUMENT_END = -19999,

    /* key operation failed */
    CMR_ERROR_KEY_OPERATION_BEGIN = -20000,
    CMR_ERROR_KEY_IMPORT_PARAM_FAILED = -20001,
    CMR_ERROR_KEY_IMPORT_FAILED = -20002,
    CMR_ERROR_KEY_DELETE_PARAM_FAILED = -20003,
    CMR_ERROR_KEY_DELETE_FAILED = -20004,
    CMR_ERROR_KEY_MAC_PARAM_FAILED = -20005,
    CMR_ERROR_KEY_MAC_INIT_FAILED = -20006,
    CMR_ERROR_KEY_MAC_FINISH_FAILED = -20007,
    CMR_ERROR_KEY_GENERATE_PARAM_FAILED = -20008,
    CMR_ERROR_KEY_GENERATE_FAILED = -20009,
    CMR_ERROR_KEY_INIT_PARAM_FAILED = -20010,
    CMR_ERROR_KEY_INIT_FAILED = -20011,
    CMR_ERROR_KEY_PROCESS_PARAM_FAILED = -20012,
    CMR_ERROR_KEY_UPDATE_FAILED = -20013,
    CMR_ERROR_KEY_FINISH_FAILED = -20014,
    CMR_ERROR_KEY_ABORT_FAILED = -20015,
    CMR_ERROR_KEY_CHECK_EXIST_PARAM_FAILED = -20016,
    CMR_ERROR_KEY_CHECK_EXIST_FAILED = -20017,
    CMR_ERROR_KEY_OPERATION_END = -29999,

    /* auth check failed */
    CMR_ERROR_AUTH_FAILED_BEGIN = -30000,
    CMR_ERROR_AUTH_FAILED_MAC_FAILED = -30001,
    CMR_ERROR_AUTH_FAILED_MAC_MISMATCH = -30002,
    CMR_ERROR_AUTH_FAILED_END = -39999,
};

enum CMDialogErrorCode {
    CMR_DIALOG_ERROR_INSTALL_FAILED = -5,

    CMR_DIALOG_ERROR_INTERNAL = -1000,
    CMR_DIALOG_ERROR_OPERATION_CANCELS = -1001,
    CMR_DIALOG_ERROR_PARSE_CERT_FAILED = -1002,
    CMR_DIALOG_ERROR_NOT_ENTERPRISE_DEVICE = -1003,
    CMR_DIALOG_ERROR_ADVANCED_SECURITY = -1004,
    CMR_DIALOG_ERROR_INCORRECT_FORMAT = -1005,
    CMR_DIALOG_ERROR_MAX_QUANTITY_REACHED = -1006,
    CMR_DIALOG_ERROR_SA_INTERNAL_ERROR = -1007,
    CMR_DIALOG_ERROR_NOT_EXIST = -1008,
    CMR_DIALOG_ERROR_NOT_SUPPORTED = -1009,
    CMR_DIALOG_ERROR_PARAM_INVALID = -1010,
    CMR_DIALOG_ERROR_PERMISSION_DENIED = 1011, /* UIExtension will return 1011 if permission check failed */
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

struct CmAppCertParam {
    struct CmBlob *appCert;
    struct CmBlob *appCertPwd;
    struct CmBlob *certAlias;
    uint32_t store;
    uint32_t userId;
    enum CmAuthStorageLevel level;
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
