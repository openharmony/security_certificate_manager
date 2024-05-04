/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cert_manager_storage.h"

#include <openssl/x509.h>
#include <unistd.h>

#include "cert_manager_file_operator.h"
#include "cert_manager_mem.h"
#include "cert_manager_uri.h"
#include "cm_log.h"
#include "cm_type.h"
#include "securec.h"

int32_t GetRootPath(uint32_t store, char *rootPath, uint32_t pathLen)
{
    errno_t ret;

    /* keep \0 at end */
    switch (store) {
        case CM_CREDENTIAL_STORE:
            ret = memcpy_s(rootPath, pathLen - 1, CREDNTIAL_STORE, strlen(CREDNTIAL_STORE));
            break;
        case CM_SYSTEM_TRUSTED_STORE:
            ret = memcpy_s(rootPath, pathLen - 1, SYSTEM_CA_STORE, strlen(SYSTEM_CA_STORE));
            break;
        case CM_USER_TRUSTED_STORE:
            ret = memcpy_s(rootPath, pathLen - 1, USER_CA_STORE, strlen(USER_CA_STORE));
            break;
        case CM_PRI_CREDENTIAL_STORE:
            ret = memcpy_s(rootPath, pathLen - 1, PRI_CREDNTIAL_STORE, strlen(PRI_CREDNTIAL_STORE));
            break;
        case CM_SYS_CREDENTIAL_STORE:
            ret = memcpy_s(rootPath, pathLen - 1, SYS_CREDNTIAL_STORE, strlen(SYS_CREDNTIAL_STORE));
            break;
        default:
            return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (ret != EOK) {
        CM_LOG_E("copy path failed, store = %u", store);
        return CMR_ERROR_INVALID_OPERATION;
    }

    return CM_SUCCESS;
}

int32_t ConstructUserIdPath(const struct CmContext *context, uint32_t store,
    char *userIdPath, uint32_t pathLen)
{
    char rootPath[CERT_MAX_PATH_LEN] = { 0 };
    int32_t ret = GetRootPath(store, rootPath, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    CM_LOG_I("root path: %s", rootPath);

    if (snprintf_s(userIdPath, pathLen, pathLen - 1, "%s%u", rootPath, context->userId) < 0) {
        CM_LOG_E("construct user id path failed");
        return CMR_ERROR_INVALID_OPERATION;
    }

    CM_LOG_I("userId path: %s", userIdPath);

    ret = CmMakeDir(userIdPath);
    if (ret == CMR_ERROR_MAKE_DIR_FAIL) {
        CM_LOG_E("mkdir userId path failed");
        return ret;
    } /* ret may be CMR_ERROR_ALREADY_EXISTS */

    return CM_SUCCESS;
}

int32_t ConstructUidPath(const struct CmContext *context, uint32_t store,
    char *uidPath, uint32_t pathLen)
{
    char userIdPath[CERT_MAX_PATH_LEN] = { 0 };
    int32_t ret = ConstructUserIdPath(context, store, userIdPath, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (snprintf_s(uidPath, pathLen, pathLen - 1, "%s/%u", userIdPath, context->uid) < 0) {
        CM_LOG_E("construct uid path failed");
        return CMR_ERROR_INVALID_OPERATION;
    }

    ret = CmMakeDir(uidPath);
    if (ret == CMR_ERROR_MAKE_DIR_FAIL) {
        CM_LOG_E("mkdir uid path failed");
        return ret;
    } /* ret may be CMR_ERROR_ALREADY_EXISTS */

    return CM_SUCCESS;
}

int32_t ConstructAuthListPath(const struct CmContext *context, uint32_t store,
    char *authListPath, uint32_t pathLen)
{
    char uidPath[CERT_MAX_PATH_LEN] = { 0 };
    int32_t ret = ConstructUidPath(context, store, uidPath, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (snprintf_s(authListPath, pathLen, pathLen - 1, "%s/%s", uidPath, "authlist") < 0) {
        CM_LOG_E("construct authlist failed");
        return CMR_ERROR_INVALID_OPERATION;
    }

    ret = CmMakeDir(authListPath);
    if (ret == CMR_ERROR_MAKE_DIR_FAIL) {
        CM_LOG_E("mkdir auth list path failed");
        return ret;
    } /* ret may be CMR_ERROR_ALREADY_EXISTS */

    return CM_SUCCESS;
}

int32_t CmStorageGetBuf(const char *path, const char *fileName, struct CmBlob *storageBuf)
{
    uint32_t fileSize = CmFileSize(path, fileName);
    if (fileSize > MAX_OUT_BLOB_SIZE) {
        CM_LOG_E("file size[%u] invalid", fileSize);
        return CMR_ERROR_INVALID_OPERATION;
    }

    if (fileSize == 0) {
        CM_LOG_E("file is not exist");
        return CMR_ERROR_NOT_EXIST;
    }

    uint8_t *data = (uint8_t *)CMMalloc(fileSize);
    if (data == NULL) {
        CM_LOG_E("malloc file buffer failed");
        return CMR_ERROR_MALLOC_FAIL;
    }

    uint32_t readSize = CmFileRead(path, fileName, 0, data, fileSize);
    if (readSize == 0) {
        CM_LOG_E("read file size 0 invalid");
        CMFree(data);
        return CMR_ERROR_NOT_EXIST;
    }

    storageBuf->data = data;
    storageBuf->size = fileSize;
    return CM_SUCCESS;
}

int32_t CmStorageGetAppCert(const struct CmContext *context, uint32_t store,
    const struct CmBlob *keyUri, struct CmBlob *certBlob)
{
    uint32_t uid = 0;
    int32_t ret = CertManagerGetUidFromUri(keyUri, &uid);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    struct CmContext uriContext = { context->userId, uid, { 0 } };
    char uidPath[CERT_MAX_PATH_LEN] = { 0 };
    ret = ConstructUidPath(&uriContext, store, uidPath, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    return CmStorageGetBuf(uidPath, (const char *)keyUri->data, certBlob);
}

int32_t CmGetCertFilePath(const struct CmContext *context, uint32_t store, struct CmMutableBlob *pathBlob)
{
    char pathPtr[CERT_MAX_PATH_LEN] = {0};

    if ((pathBlob == NULL) || (pathBlob->data == NULL)) {
        CM_LOG_E("Null pointer failure");
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = ConstructUidPath(context, store, pathPtr, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get file path faild");
        return CM_FAILURE;
    }

    char *path = (char *)pathBlob->data;
    if (sprintf_s(path, CERT_MAX_PATH_LEN, "%s", pathPtr) < 0) {
        return CM_FAILURE;
    }
    pathBlob->size = strlen(path) + 1;

    return CM_SUCCESS;
}

/**
 * @brief Construct the absolute path to the {confRootDir} directory
 *
 * @param[out] confRootDir The buffer that holds the absolute path of the {confRootDir} directory
 * @param[in] dirLen Maximum length of the confRootDir buffer
 * @return int32_t result
 * @retval 0 success
 * @retval <0 failure
 */
static int32_t GetCertConfRootDir(char *confRootDir, uint32_t dirLen)
{
    int32_t ret = CM_SUCCESS;
    mode_t mode = 0;

    if (confRootDir == NULL) {
        CM_LOG_E("Input params invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (dirLen < sizeof(CERT_BACKUP_CONFIG_ROOT_DIR)) {
        CM_LOG_E("dirLen(%u) is too small for save user cert backup config file root path", dirLen);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    /* Create the root directory for storing user backup config files */
    mode = S_IRWXU; /* The permission on the user_config directory should be 0700 */
    ret = CmUserBakupMakeDir(CERT_BACKUP_CONFIG_ROOT_DIR, (const mode_t *)&mode);
    if (ret != CMR_OK) {
        CM_LOG_E("Create CERT_BACKUP_CONFIG_ROOT_DIR failed, err code: %d", ret);
        return CMR_ERROR_MAKE_DIR_FAIL;
    }

    if (snprintf_s(confRootDir, dirLen, dirLen - 1, "%s", CERT_BACKUP_CONFIG_ROOT_DIR) < 0) {
        CM_LOG_E("Construct confRootDir failed");
        return CM_FAILURE;
    }

    return CM_SUCCESS;
}

int32_t CmGetCertConfUserIdDir(uint32_t userId, char *confUserIdDir, uint32_t dirLen)
{
    if (confUserIdDir == NULL) {
        CM_LOG_E("Input params invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CM_SUCCESS;
    char rootPath[CERT_MAX_PATH_LEN] = { 0 };
    ret = GetCertConfRootDir(rootPath, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get user cert root path failed");
        return CM_FAILURE;
    }

    char pathTmp[CERT_MAX_PATH_LEN] = { 0 };
    /* Concatenate the {confRootDir}/{userid} directory */
    if (snprintf_s(pathTmp, CERT_MAX_PATH_LEN, CERT_MAX_PATH_LEN - 1, "%s/%u", rootPath, userId) < 0) {
        CM_LOG_E("Construct userIdPath failed, rootPath: %s, userId: %u", rootPath, userId);
        return CM_FAILURE;
    }
    /* Create the {confRootDir}/{userid} directory */
    ret = CmUserBakupMakeDir(pathTmp, NULL);
    if (ret != CMR_OK) {
        CM_LOG_E("Create userIdPath failed, err code: %d", ret);
        return CMR_ERROR_MAKE_DIR_FAIL;
    }

    if (snprintf_s(confUserIdDir, dirLen, dirLen - 1, "%s", pathTmp) < 0) {
        CM_LOG_E("Failed to construct confUserIdDir");
        return CM_FAILURE;
    }

    return CM_SUCCESS;
}

int32_t CmGetCertConfUidDir(uint32_t userId, uint32_t uid, char *certConfUidDir, uint32_t dirLen)
{
    if (certConfUidDir == NULL) {
        CM_LOG_E("Input params invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CM_SUCCESS;
    char confUserIdDir[CERT_MAX_PATH_LEN] = { 0 };
    ret = CmGetCertConfUserIdDir(userId, confUserIdDir, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Construct confUserIdDir(userId: %u) failed", userId);
        return CM_FAILURE;
    }

    char pathTmp[CERT_MAX_PATH_LEN] = { 0 };
    /* Concatenate the {confRootDir}/{userid}/{uid} directory  */
    if (snprintf_s(pathTmp, CERT_MAX_PATH_LEN, CERT_MAX_PATH_LEN - 1, "%s/%u", confUserIdDir, uid) < 0) {
        CM_LOG_E("Construct uidPath failed, uid: %u", uid);
        return CM_FAILURE;
    }
    /* Create the {confRootDir}/{userid}/{uid} directory */
    ret = CmUserBakupMakeDir(pathTmp, NULL);
    if (ret != CMR_OK) {
        CM_LOG_E("Create uidPath failed, err code: %d", ret);
        return CMR_ERROR_MAKE_DIR_FAIL;
    }

    if (snprintf_s(certConfUidDir, dirLen, dirLen - 1, "%s", pathTmp) < 0) {
        CM_LOG_E("Failed to construct certConfUidDir");
        return CM_FAILURE;
    }

    return CM_SUCCESS;
}

int32_t CmGetCertConfPath(uint32_t userId, uint32_t uid, const struct CmBlob *certUri, char *confFilePath,
                          uint32_t confFilePathLen)
{
    if ((CmCheckBlob(certUri) != CM_SUCCESS) || (confFilePath == NULL) || (confFilePathLen == 0)) {
        CM_LOG_E("input params is invaild");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CM_SUCCESS;
    char certConfUidDir[CERT_MAX_PATH_LEN] = { 0 };
    ret = CmGetCertConfUidDir(userId, uid, certConfUidDir, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get user cert root path failed");
        return CM_FAILURE;
    }

    if (snprintf_s(confFilePath, confFilePathLen, confFilePathLen - 1, "%s/%.*s%s", certConfUidDir, certUri->size,
                   certUri->data, CERT_CONFIG_FILE_SUFFIX) < 0) {
        CM_LOG_E("Failed to construct user cert config file path");
        return CM_FAILURE;
    }
    return CM_SUCCESS;
}

/**
 * @brief Get the user certificate backup file root directory
 *
 * @param[out] certBackupRootDir Save the buffer of the user certificate backup file root directory
 * @param[in] dirLen Maximum length of the certBackupRootDir buffer
 * @return int32_t result
 * @retval 0 success
 * @retval <0 failure
 */
static int32_t GetCertBackupRootDir(char *certBackupRootDir, uint32_t dirLen)
{
    if (certBackupRootDir == NULL) {
        CM_LOG_E("Input params invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (dirLen < sizeof(CERT_BACKUP_ROOT_DIR)) {
        CM_LOG_E("dirLen(%u) is too small for save user cert backup root path", dirLen);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    int32_t ret = CM_SUCCESS;
    mode_t mode = 0;
    /* Create the root directory for storing user backup files */
    mode = S_IRWXU | S_IXOTH; /* The permission on the user_open directory should be 0701 */
    ret = CmUserBakupMakeDir(CERT_BACKUP_ROOT_DIR, (const mode_t *)&mode);
    if (ret != CMR_OK) {
        CM_LOG_E("Create CERT_BACKUP_ROOT_DIR failed, err code: %d", ret);
        return CMR_ERROR_MAKE_DIR_FAIL;
    }

    if (snprintf_s(certBackupRootDir, dirLen, dirLen - 1, "%s", CERT_BACKUP_ROOT_DIR) < 0) {
        CM_LOG_E("Construct certBackupRootDir failed");
        return CM_FAILURE;
    }

    return CM_SUCCESS;
}

int32_t CmGetCertBackupDir(uint32_t userId, char *certBackupDir, uint32_t certBackupDirLen)
{
    int32_t ret = CM_SUCCESS;
    char rootPath[CERT_MAX_PATH_LEN] = { 0 };

    ret = GetCertBackupRootDir(rootPath, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get user cert root path failed");
        return ret;
    }

    char userIdPath[CERT_MAX_PATH_LEN] = { 0 };
    /* Concatenate the {userId} directory for the certificate backup */
    if (snprintf_s(userIdPath, CERT_MAX_PATH_LEN, CERT_MAX_PATH_LEN - 1, "%s/%u", rootPath, userId) < 0) {
        CM_LOG_E("Construct userIdPath failed");
        return CMR_ERROR_INVALID_OPERATION;
    }
    /* Create the {userId} directory for the certificate backup */
    ret = CmUserBakupMakeDir(userIdPath, NULL);
    if (ret != CMR_OK) {
        CM_LOG_E("Create userIdPath failed, err code: %d", ret);
        return CMR_ERROR_MAKE_DIR_FAIL;
    }

    if (snprintf_s(certBackupDir, certBackupDirLen, certBackupDirLen - 1, "%s", userIdPath) < 0) {
        CM_LOG_E("Construct certBackupDir failed");
        return CMR_ERROR_INVALID_OPERATION;
    }
    return CM_SUCCESS;
}

/**
 * @brief Get the minimum serial number of the backup file available for the user CA certificate
 *
 * @param[in] certSubjectNameHash hash value of a CA certificate SubjectName
 * @return int Get the minimum serial number or error code
 * @retval >=0 Get the minimum serial number
 * @retval <0 Error code
 */
static int32_t CmGetCertMinSeqNum(uint32_t userId, unsigned long certSubjectNameHash)
{
    int32_t ret = CM_SUCCESS;
    char certBackupDir[CERT_MAX_PATH_LEN] = { 0 };

    ret = CmGetCertBackupDir(userId, certBackupDir, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Construct userCertBackupDirPath failed");
        return ret;
    }

    int32_t sequenceNumber = CM_FAILURE;
    char backupFileSearchPath[CERT_MAX_PATH_LEN] = { 0 };
    for (int32_t seq = 0; seq < MAX_COUNT_CERTIFICATE; seq++) {
        if (snprintf_s(backupFileSearchPath, CERT_MAX_PATH_LEN, CERT_MAX_PATH_LEN - 1,
                       "%s/" CERT_BACKUP_FILENAME_FORMAT, certBackupDir, certSubjectNameHash, seq) < 0) {
            CM_LOG_E("Call snprintf_s return failed");
            return CM_FAILURE;
        }

        if (access(backupFileSearchPath, F_OK) == 0) {
            CM_LOG_D("backupFileSearchPath is exist");
            continue;
        } else {
            CM_LOG_D("backupFileSearchPath is not exist");
            sequenceNumber = seq;
            break;
        }
    }

    CM_LOG_D("Get sequenceNumber(%d)", sequenceNumber);
    return sequenceNumber;
}

int32_t CmGetCertBackupFileName(const X509 *userCertX509, uint32_t userId, char *certBackupFileName,
                                uint32_t certBackupFileNameLen)
{
    if (userCertX509 == NULL || certBackupFileName == NULL) {
        CM_LOG_E("Input params invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int sequenceNumber = 0;
    unsigned long certSubjectNameHash = 0;

    /* Calculate the hash value of CA certificate subject_name */
    certSubjectNameHash = X509_NAME_hash(X509_get_subject_name(userCertX509));

    sequenceNumber = CmGetCertMinSeqNum(userId, certSubjectNameHash);
    if (sequenceNumber < 0) {
        CM_LOG_E("Get User Cert Min Useable SequenceNumber failed");
        return CM_FAILURE;
    }

    if (snprintf_s(certBackupFileName, certBackupFileNameLen, certBackupFileNameLen - 1, CERT_BACKUP_FILENAME_FORMAT,
                   certSubjectNameHash, sequenceNumber) < 0) {
        CM_LOG_E("Call snprintf_s return failed");
        return CMR_ERROR_INVALID_OPERATION;
    }
    return CM_SUCCESS;
}

int32_t CmGetCertBackupFilePath(const X509 *userCertX509, uint32_t userId, char *backupFilePath,
                                uint32_t backupFilePathLen)
{
    if (userCertX509 == NULL || backupFilePath == NULL) {
        CM_LOG_E("Input params invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CM_SUCCESS;
    char certBackupDir[CERT_MAX_PATH_LEN] = { 0 };
    ret = CmGetCertBackupDir(userId, certBackupDir, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Construct userCertBackupDirPath failed");
        return ret;
    }

    char certBackupFileName[CERT_MAX_PATH_LEN] = { 0 };
    ret = CmGetCertBackupFileName(userCertX509, userId, certBackupFileName, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get certBackupFileName failed");
        return ret;
    }

    if (snprintf_s(backupFilePath, backupFilePathLen, backupFilePathLen - 1, "%s/%s", certBackupDir,
                   certBackupFileName) < 0) {
        CM_LOG_E("Call snprintf_s return failed");
        ret = CMR_ERROR_INVALID_OPERATION;
    }
    return ret;
}
