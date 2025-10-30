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

#include "cert_manager.h"

#include <unistd.h>
#include <libgen.h>

#include "cert_manager_auth_mgr.h"
#include "cert_manager_file.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_key_operation.h"
#include "cert_manager_mem.h"
#include "cert_manager_permission_check.h"
#include "cert_manager_status.h"
#include "cert_manager_storage.h"
#include "cert_manager_uri.h"
#include "cert_manager_query.h"
#include "cert_manager_ukey_operation.h"
#include "cm_cert_property_rdb.h"
#include "cert_manager_crypto_operation.h"
#include "cm_log.h"
#include "cm_type.h"
#include "cm_x509.h"
#include "cm_util.h"

#include "securec.h"

#include "hks_api.h"

#define MAX_PATH_LEN                        256

#ifdef __cplusplus
extern "C" {
#endif

static bool g_hksInitialized = false;

int32_t CertManagerInitialize(void)
{
    int32_t ret;
    if (!g_hksInitialized) {
        ret = HksInitialize();
        if (ret != HKS_SUCCESS) {
            CM_LOG_E("HUKS init failed, ret = %d", ret);
            return CMR_ERROR_SA_START_HUKS_INIT_FAILED;
        }
        g_hksInitialized = true;
    }

    if (CmMakeDir(CERT_DIR) == CMR_ERROR_MAKE_DIR_FAIL) {
        CM_LOG_E("Failed to create folder\n");
        return CMR_ERROR_MAKE_DIR_FAIL;
    }

    ret = CreateCertPropertyRdb();
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ret = CertManagerStatusInit();
    if (ret != CM_SUCCESS) {
        return (ret == CM_FAILURE) ? CMR_ERROR_SA_START_STATUS_INIT_FAILED : ret;
    }

    return CM_SUCCESS;
}

static int32_t GetFilePath(const struct CmContext *context, uint32_t store, char *pathPtr,
    char *suffix, uint32_t *suffixLen)
{
    int32_t ret;

    if (context == NULL) {
        CM_LOG_E("Null pointer failture");
        return CMR_ERROR_NULL_POINTER;
    }

    if (suffix == NULL || suffixLen == NULL) {
        CM_LOG_E("NULL pointer failure");
        return CMR_ERROR_NULL_POINTER;
    }

    switch (store) {
        case CM_CREDENTIAL_STORE:
            ret = sprintf_s(pathPtr, MAX_PATH_LEN, "%s%u", CREDNTIAL_STORE, context->userId);
            break;
        case CM_USER_TRUSTED_STORE:
            ret = sprintf_s(pathPtr, MAX_PATH_LEN, "%s%u", USER_CA_STORE, context->userId);
            break;
        case CM_PRI_CREDENTIAL_STORE:
            ret = sprintf_s(pathPtr, MAX_PATH_LEN, "%s%u", PRI_CREDNTIAL_STORE, context->userId);
            break;
        case CM_SYS_CREDENTIAL_STORE:
            ret = sprintf_s(pathPtr, MAX_PATH_LEN, "%s%u", SYS_CREDNTIAL_STORE, context->userId);
            break;
        case CM_SYSTEM_TRUSTED_STORE:
            ret = sprintf_s(pathPtr, MAX_PATH_LEN, "%s", SYSTEM_CA_STORE);
            break;
        default:
            return CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE;
    }

    if (ret < 0) {
        CM_LOG_E("Construct file Path failed ret: %d", ret);
        return CMR_ERROR_MEM_OPERATION_PRINT;
    }

    // construct file suffix
    if (store != CM_SYSTEM_TRUSTED_STORE) {
        ret = sprintf_s(suffix, MAX_SUFFIX_LEN, "%u", context->uid);
        if (ret < 0) {
            CM_LOG_E("Construct file suffix failed ret: %d", ret);
            return CMR_ERROR_MEM_OPERATION_PRINT;
        }
    }

    *suffixLen = (uint32_t)strlen(suffix);
    return CMR_OK;
}

static int32_t CmGetFilePath(const struct CmContext *context, uint32_t store, struct CmMutableBlob *pathBlob)
{
    char pathPtr[MAX_PATH_LEN] = {0};
    uint32_t suffixLen = 0;
    char suffixBuf[MAX_SUFFIX_LEN] = {0};

    if ((pathBlob == NULL) || (pathBlob->data == NULL) || (pathBlob->size == 0)) {
        CM_LOG_E("Null pointer failure");
        return CMR_ERROR_NULL_POINTER;
    }
    int32_t ret = GetFilePath(context, store, pathPtr, suffixBuf, &suffixLen);
    if (ret != CMR_OK) {
        CM_LOG_E("Get file path failed");
        return ret;
    }

    /* Create folder if it does not exist */
    if (CmMakeDir(pathPtr) == CMR_ERROR_MAKE_DIR_FAIL) {
        CM_LOG_E("Failed to create path folder");
        return CMR_ERROR_MAKE_DIR_FAIL;
    }

    if (pathBlob->size - 1 < strlen(pathPtr) + suffixLen) {
        CM_LOG_E("Failed to copy path");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    char *path = (char *)pathBlob->data;
    if (suffixLen == 0) {
        if (sprintf_s(path, MAX_PATH_LEN, "%s", pathPtr) < 0) {
            return CMR_ERROR_MEM_OPERATION_PRINT;
        }
    } else {
        if (sprintf_s(path, MAX_PATH_LEN, "%s/%s", pathPtr, suffixBuf) < 0) {
            return CMR_ERROR_MEM_OPERATION_PRINT;
        }
    }

    pathBlob->size = strlen(path) + 1;
    if (CmMakeDir(path) == CMR_ERROR_MAKE_DIR_FAIL) {
        CM_LOG_E("Failed to create folder");
        return CMR_ERROR_MAKE_DIR_FAIL;
    }
    return CMR_OK;
}

static int32_t FindObjectCert(const struct CmBlob *certUri, const struct CmMutableBlob *fNames, uint32_t certCount)
{
    for (uint32_t i = 0; i < certCount; i++) {
        if (fNames[i].data == NULL) {
            CM_LOG_E("Corrupted file name at index: %u", i);
            return CMR_ERROR_STORAGE;
        }
        /* Check if url is matching with the cert filename */
        if ((certUri->size <= fNames[i].size) && (memcmp(certUri->data, fNames[i].data, certUri->size) == 0)) {
            return CM_SUCCESS;
        }
    }
    return CMR_ERROR_NOT_FOUND;
}

static int32_t GetGmSystemCaCertPath(struct CmMutableBlob *path)
{
    if ((path == NULL) || (path->data == NULL) || (path->size == 0)) {
        CM_LOG_E("Null pointer failure");
        return CMR_ERROR_NULL_POINTER;
    }

    /* get gm system ca cert path */
    char *pathStr = (char *)path->data;
    if (sprintf_s(pathStr, path->size, "%s", SYSTEM_CA_STORE_GM) < 0) {
        CM_LOG_E("sprintf gm system ca path failed");
        return CMR_ERROR_MEM_OPERATION_PRINT;
    }

    path->size = strlen(pathStr) + 1;
    return CM_SUCCESS;
}

int32_t CertManagerFindCertFileNameByUri(const struct CmContext *context, const struct CmBlob *certUri,
    uint32_t store, bool isGmSysCert, struct CmMutableBlob *path)
{
    ASSERT_ARGS(context && certUri && certUri->data);

    int32_t ret;
    if (!isGmSysCert) {
        ret = CmGetFilePath(context, store, path);
    } else {
        if (CmIsDirExist(SYSTEM_CA_STORE_GM) != CM_SUCCESS) {
            return CMR_ERROR_NOT_FOUND;
        }
        ret = GetGmSystemCaCertPath(path);
    }
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed obtain path for store %x\n", store);
        return ret;
    }

    struct CmMutableBlob fileNames = { 0, NULL };
    ret = CertManagerGetFilenames(&fileNames, (char *)path->data);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed obtain filenames from path");
        return ret;
    }

    struct CmMutableBlob *fNames = (struct CmMutableBlob *)fileNames.data;
    ret = FindObjectCert(certUri, fNames, fileNames.size);
    FreeFileNames(fNames, fileNames.size);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("No cert matched, err: %d", ret);
    }
    return ret;
}

int32_t CmRemoveAppCert(const struct CmContext *context, const struct CmBlob *keyUri,
    const uint32_t store)
{
    ASSERT_ARGS(context && keyUri && keyUri->data && keyUri->size);

    enum CmAuthStorageLevel level;
    int32_t ret = GetRdbAuthStorageLevel(keyUri, &level);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get rdb auth storage level failed, ret = %d", ret);
        return ret;
    }
    if (level == ERROR_LEVEL) {
        level = CM_AUTH_STORAGE_LEVEL_EL1;
        CM_LOG_I("Remove cred level is ERROR_LEVEL, change to default level el1");
    }

    if (store == CM_CREDENTIAL_STORE) {
        ret = CmAuthDeleteAuthInfo(context, keyUri, level);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("delete auth info failed when remove app certificate."); /* ignore ret code, only record log */
        }
    }

    ret = DeleteCertProperty((char *)keyUri->data);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed delete cert: %s rdbData", (char *)keyUri->data);
        return ret;
    }

    char pathBuf[CERT_MAX_PATH_LEN] = {0};
    struct CmMutableBlob path = { sizeof(pathBuf), (uint8_t*) pathBuf };

    ret = CmGetFilePath(context, store, &path);
    if (ret != CMR_OK) {
        CM_LOG_E("Failed obtain path for store %u", store);
        return ret;
    }
    ret = CertManagerFileRemove(pathBuf, (char *)keyUri->data);
    if (ret != CMR_OK) {
        CM_LOG_E("CertManagerFileRemove failed ret: %d", ret);
        return ret;
    }
    ret = CmKeyOpDeleteKey(keyUri, level);
    if (ret != CM_SUCCESS) { /* ignore the return of deleteKey */
        CM_LOG_E("CertManagerKeyRemove failed, ret: %d", ret);
    }

    return CMR_OK;
}

static void ClearAuthInfo(const struct CmContext *context, const struct CmBlob *keyUri, const uint32_t store,
    enum CmAuthStorageLevel level)
{
    if (store != CM_CREDENTIAL_STORE) {
        return;
    }

    int32_t ret = CmAuthDeleteAuthInfo(context, keyUri, level);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("delete auth info failed."); /* ignore ret code, only record log */
    }
}

static int32_t CmAppCertGetFilePath(const struct CmContext *context, const uint32_t store, struct CmBlob *path)
{
    int32_t ret = CM_FAILURE;

    switch (store) {
        case CM_CREDENTIAL_STORE :
            ret = sprintf_s((char*)path->data, MAX_PATH_LEN, "%s%u/%u", CREDNTIAL_STORE, context->userId, context->uid);
            break;
        case CM_PRI_CREDENTIAL_STORE :
            ret = sprintf_s((char*)path->data, MAX_PATH_LEN, "%s%u", PRI_CREDNTIAL_STORE, context->userId);
            break;
        case CM_SYS_CREDENTIAL_STORE:
            ret = sprintf_s((char *)path->data, MAX_PATH_LEN, "%s%u", SYS_CREDNTIAL_STORE, context->userId);
            break;
        case CM_USER_TRUSTED_STORE:
            ret = sprintf_s((char *)path->data, MAX_PATH_LEN, "%s%u", USER_CA_STORE, context->userId);
            break;
        default:
            return CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE;
    }
    if (ret < 0) {
        return CMR_ERROR_MEM_OPERATION_PRINT;
    }
    return CM_SUCCESS;
}

static int32_t CmAppCertWithUidGetFilePath(const struct CmContext *context, const uint32_t store, struct CmBlob *path)
{
    int32_t ret = CM_FAILURE;

    switch (store) {
        case CM_CREDENTIAL_STORE :
            ret = sprintf_s((char*)path->data, MAX_PATH_LEN, "%s%u/%u",
                CREDNTIAL_STORE, context->userId, context->uid);
            break;
        case CM_PRI_CREDENTIAL_STORE :
            ret = sprintf_s((char*)path->data, MAX_PATH_LEN, "%s%u/%u",
                PRI_CREDNTIAL_STORE, context->userId, context->uid);
            break;
        case CM_SYS_CREDENTIAL_STORE:
            ret = sprintf_s((char *)path->data, MAX_PATH_LEN, "%s%u/%u",
                SYS_CREDNTIAL_STORE, context->userId, context->uid);
            break;
        case CM_USER_TRUSTED_STORE:
            ret = sprintf_s((char *)path->data, MAX_PATH_LEN, "%s%u/%u",
                USER_CA_STORE, context->userId, context->uid);
            break;
        default:
            return CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE;
    }
    if (ret < 0) {
        return CMR_ERROR_MEM_OPERATION_PRINT;
    }
    return CM_SUCCESS;
}

void CmFreeFileNames(struct CmBlob *fileNames, const uint32_t fileSize)
{
    if (fileNames == NULL) {
        CM_LOG_E("CmFreeFileNames fileNames is null");
        return;
    }

    for (uint32_t i = 0; i < fileSize; i++) {
        if (fileNames[i].data != NULL) {
            CMFree(fileNames[i].data);
            fileNames[i].size = 0;
        }
    }
}

int32_t CmGetUri(const char *filePath, struct CmBlob *uriBlob)
{
    if ((filePath == NULL) || (uriBlob == NULL) || (uriBlob->data == NULL)) {
        CM_LOG_E("CmGetUri param is null");
        return CM_FAILURE;
    }

    uint32_t filePathLen = strlen(filePath);
    if ((filePathLen == 0) || (filePathLen > CM_MAX_FILE_NAME_LEN)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t i = (int32_t)(filePathLen - 1);
    for (; i >= 0; i--) {
        if (filePath[i] == '/') {
            break;
        }
    }

    int32_t index = i + 1; /* index range: 0 to filePathLen */
    uint32_t uriLen = filePathLen - (uint32_t)index + 1; /* include '\0' at end, range: 1 to filePathLen + 1 */
    if (memcpy_s(uriBlob->data, uriBlob->size, &filePath[index], uriLen) != EOK) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    uriBlob->size = uriLen;

    return CM_SUCCESS;
}

static int32_t GetUriAndDeleteRdbData(const char *filePath, struct CmBlob *uriBlob, enum CmAuthStorageLevel *level)
{
    int32_t ret = CmGetUri(filePath, uriBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get uri failed");
        return ret;
    }

    ret = GetRdbAuthStorageLevel(uriBlob, level);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get rdb auth storage level failed, ret = %d", ret);
        return ret;
    }
    if (*level == ERROR_LEVEL) {
        *level = CM_AUTH_STORAGE_LEVEL_EL1;
        CM_LOG_I("Delete rdb level is ERROR_LEVEL, change to default level el1");
    }

    ret = DeleteCertProperty((char *)uriBlob->data);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed delete cert: %s rdbData", (char *)uriBlob->data);
        return ret;
    }
    return CM_SUCCESS;
}

static int32_t CmRemoveSpecifiedAppCert(const struct CmContext *context, const uint32_t store)
{
    uint32_t fileCount = 0;
    int32_t ret = CM_SUCCESS;
    char pathBuf[CERT_MAX_PATH_LEN] = {0};
    char uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob fileNames[MAX_COUNT_CERTIFICATE];
    struct CmBlob path = { sizeof(pathBuf), (uint8_t*)pathBuf };
    struct CmBlob uriBlob = { sizeof(uriBuf), (uint8_t*)uriBuf };
    uint32_t len = MAX_COUNT_CERTIFICATE * sizeof(struct CmBlob);
    (void)memset_s(fileNames, len, 0, len);

    do {
        ret = CmAppCertGetFilePath(context, store, &path);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Get file path for store:%u failed", store);
            break;
        }

        if (store == CM_CREDENTIAL_STORE) {
            ret = CmUidLayerGetFileCountAndNames(pathBuf, fileNames, MAX_COUNT_CERTIFICATE, &fileCount);
        } else {
            ret = CmUserIdLayerGetFileCountAndNames(pathBuf, fileNames, MAX_COUNT_CERTIFICATE, &fileCount);
        }
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Get file count and names from path failed");
            break;
        }

        for (uint32_t i = 0; i < fileCount; i++) {
            if (CertManagerFileRemove(NULL, (char *)fileNames[i].data) != CM_SUCCESS) {
                CM_LOG_E("App cert %u remove failed", i);
                continue;
            }

            uriBlob.size = sizeof(uriBuf);
            (void)memset_s(uriBuf, uriBlob.size, 0, uriBlob.size);
            enum CmAuthStorageLevel level;
            if (GetUriAndDeleteRdbData((char *)fileNames[i].data, &uriBlob, &level) != CM_SUCCESS) {
                CM_LOG_E("Get uri failed");
                continue;
            }

            int32_t retCode = CmKeyOpDeleteKey(&uriBlob, level);
            if (retCode != CM_SUCCESS) { /* ignore the return of deleteKey */
                CM_LOG_E("App key %u remove failed ret: %d", i, retCode);
            }
            ClearAuthInfo(context, &uriBlob, store, level);
        }
    } while (0);
    CmFreeFileNames(fileNames, MAX_COUNT_CERTIFICATE);
    return ret;
}

int32_t CmRemoveAllAppCert(const struct CmContext *context)
{
    if (!CmHasPrivilegedPermission() || !CmHasCommonPermission() || !CmHasSystemAppPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }
    if (!CmIsSystemApp()) {
        CM_LOG_E("remove app cert: caller is not system app");
        return CMR_ERROR_NOT_SYSTEMP_APP;
    }

    /* Only public and private credential removed can be returned */
    /* remove pubic credential app cert */
    int32_t ret = CmRemoveSpecifiedAppCert(context, CM_CREDENTIAL_STORE);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("remove pubic credential app cert failed");
    }

    /* remove private credential app cert */
    ret = CmRemoveSpecifiedAppCert(context, CM_PRI_CREDENTIAL_STORE);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("remove private credential app cert failed");
    }

    /* remove system credential app cert */
    ret = CmRemoveSpecifiedAppCert(context, CM_SYS_CREDENTIAL_STORE);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("remove system credential app cert failed");
    }

    return ret;
}

int32_t CmServiceGetAppCertList(const struct CmContext *context, uint32_t store, struct CmBlob *fileNames,
    const uint32_t fileSize, uint32_t *fileCount)
{
    char pathBuf[CERT_MAX_PATH_LEN] = {0};
    struct CmBlob path = { sizeof(pathBuf), (uint8_t*)pathBuf };

    int32_t ret = CmAppCertGetFilePath(context, store, &path);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get file path for store:%u failed", store);
        return CM_FAILURE;
    }

    if (store == CM_CREDENTIAL_STORE) {
        ret = CmUidLayerGetFileCountAndNames(pathBuf, fileNames, fileSize, fileCount);
    } else {
        ret = CmUserIdLayerGetFileCountAndNames(pathBuf, fileNames, fileSize, fileCount);
    }
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get file count and names from path failed ret:%d", ret);
        return ret;
    }

    return CM_SUCCESS;
}

int32_t CmServiceGetAppCertListByUid(const struct CmContext *context, uint32_t store, struct CmBlob *fileNames,
    const uint32_t fileSize, uint32_t *fileCount)
{
    char pathBuf[CERT_MAX_PATH_LEN] = {0};
    struct CmBlob path = { sizeof(pathBuf), (uint8_t*)pathBuf };

    int32_t ret = CmAppCertWithUidGetFilePath(context, store, &path);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get file path for store:%u failed", store);
        return CM_FAILURE;
    }

    ret = CmUidLayerGetFileCountAndNames(pathBuf, fileNames, fileSize, fileCount);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get file count and names from path failed ret:%d", ret);
        return ret;
    }

    return CM_SUCCESS;
}

int32_t CmServiceGetUkeyCertList(const struct CmBlob *ukeyProvider, uint32_t certPurpose, uint32_t paramsCount,
    struct CmBlob *certificateList)
{
    int32_t ret = CmGetUkeyCertListByHksCertInfoSet(ukeyProvider, certPurpose, paramsCount, certificateList);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmGetUkeyCertListByHksCertInfoSet failed, ret = %d", ret);
        return CM_FAILURE;
    }
    return CM_SUCCESS;
}

int32_t CmServiceGetUkeyCert(const struct CmBlob *ukeyCertIndex, uint32_t certPurpose, uint32_t paramsCount,
    struct CmBlob *certificateList)
{
    int32_t ret = CmGetUkeyCertByHksCertInfoSet(ukeyCertIndex, certPurpose, paramsCount, certificateList);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmGetUkeyCertByHksCertInfoSet failed, ret = %d", ret);
        return CM_FAILURE;
    }
    return CM_SUCCESS;
}

int32_t CmServiceGetCallingAppCertList(const struct CmContext *context, uint32_t store, struct CmBlob *fileNames,
    const uint32_t fileSize, uint32_t *fileCount)
{
    char pathBuf[CERT_MAX_PATH_LEN] = {0};
    struct CmBlob path = { sizeof(pathBuf), (uint8_t*)pathBuf };

    int32_t ret = CmAppCertWithUidGetFilePath(context, store, &path);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get file path for store:%u failed", store);
        return CM_FAILURE;
    }

    ret = CmUidLayerGetFileCountAndNames(pathBuf, fileNames, fileSize, fileCount);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get file count and names from path failed ret:%d", ret);
        return ret;
    }

    return CM_SUCCESS;
}

int32_t GetCertOrCredCount(const struct CmContext *context, const uint32_t store, uint32_t *certCount)
{
    if (context == NULL || certCount == NULL) {
        CM_LOG_E("null pointer");
        return CMR_ERROR_NULL_POINTER;
    }
    uint32_t fileCount = 0;
    struct CmBlob fileNames[MAX_COUNT_CERTIFICATE];
    uint32_t len = MAX_COUNT_CERTIFICATE * sizeof(struct CmBlob);
    (void)memset_s(fileNames, len, 0, len);

    int32_t ret = CmServiceGetAppCertList(context, store, fileNames, MAX_COUNT_CERTIFICATE, &fileCount);
    CmFreeFileNames(fileNames, MAX_COUNT_CERTIFICATE);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get app cert list");
        return ret;
    }

    *certCount = fileCount;
    return CM_SUCCESS;
}

int32_t CmCheckCertCount(const struct CmContext *context, const uint32_t store, const char *fileName)
{
    if (context == NULL || fileName == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CM_FAILURE;
    do {
        uint32_t certCount = 0;
        int32_t retVal = GetCertOrCredCount(context, store, &certCount);
        if (retVal != CM_SUCCESS) {
            CM_LOG_E("Failed obtain cert count for store:%u", store);
            break;
        }
        if (certCount < MAX_COUNT_CERTIFICATE) {
            ret = CM_SUCCESS;
            break;
        }

        char pathBuf[CERT_MAX_PATH_LEN] = {0};
        retVal = ConstructUidPath(context, store, pathBuf, sizeof(pathBuf));
        if (retVal != CM_SUCCESS) {
            CM_LOG_E("Failed obtain path for store:%u", store);
            break;
        }

        char fullFileName[CM_MAX_FILE_NAME_LEN] = {0};
        if (snprintf_s(fullFileName, CM_MAX_FILE_NAME_LEN, CM_MAX_FILE_NAME_LEN - 1, "%s/%s", pathBuf, fileName) < 0) {
            CM_LOG_E("mkdir full name failed");
            ret = CMR_ERROR_MEM_OPERATION_PRINT;
            break;
        }

        if (access(fullFileName, F_OK) == 0) {
            ret = CM_SUCCESS;
            break;
        }
    } while (0);
    return ret;
}

static int32_t ConstructCertUri(const struct CmContext *context, const struct CmBlob *certAlias,
    struct CmBlob *certUri)
{
    struct CmBlob commonUri = { 0, NULL };
    int32_t ret;
    do {
        ret = CmConstructCommonUri(context, CM_URI_TYPE_CERTIFICATE, certAlias, &commonUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("construct cert uri get common uri failed");
            break;
        }

        if (certUri->size < commonUri.size) {
            CM_LOG_E("out cert uri size[%u] too small", certUri->size);
            ret = CMR_ERROR_BUFFER_TOO_SMALL;
            break;
        }

        if (memcpy_s(certUri->data, certUri->size, commonUri.data, commonUri.size) != EOK) {
            CM_LOG_E("copy cert uri failed");
            ret = CMR_ERROR_MEM_OPERATION_COPY;
            break;
        }

        certUri->size = commonUri.size;
    } while (0);

    CM_FREE_PTR(commonUri.data);
    return ret;
}

int32_t CmWriteUserCert(const struct CmContext *context, struct CmMutableBlob *pathBlob,
    const struct CmBlob *userCert, const struct CmBlob *certAlias, struct CmBlob *certUri)
{
    if (certAlias->size > MAX_LEN_CERT_ALIAS) {
        CM_LOG_E("alias size[%u] is too large", certAlias->size);
        return CMR_ERROR_ALIAS_LENGTH_REACHED_LIMIT;
    }

    int32_t ret;
    do {
        ret = ConstructCertUri(context, certAlias, certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get cert uri failed");
            break;
        }

        if (certUri->size > MAX_LEN_URI) {
            CM_LOG_E("uri size is too large");
            ret = CMR_ERROR_INVALID_ARGUMENT;
            break;
        }

        ret = CmCheckCertCount(context, CM_USER_TRUSTED_STORE, (char *)certUri->data);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("cert count beyond maxcount, can't install");
            ret = CMR_ERROR_MAX_CERT_COUNT_REACHED;
            break;
        }

        if (CmFileWrite((char*)pathBlob->data, (char *)certUri->data, 0, userCert->data, userCert->size) != CMR_OK) {
            CM_LOG_E("Failed to write certificate");
            ret = CMR_ERROR_WRITE_FILE_FAIL;
            break;
        }
    } while (0);
    return ret;
}

int32_t CmGetDisplayNameByURI(const struct CmBlob *uri, const char *object, struct CmBlob *displayName)
{
    if ((CmCheckBlob(uri) != CM_SUCCESS) || (object == NULL) ||
        (CmCheckBlob(displayName) != CM_SUCCESS)) {
        CM_LOG_E("input param is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    int32_t ret = CM_SUCCESS;
    struct CertProperty certProperty;
    (void)memset_s(&certProperty, sizeof(struct CertProperty), 0, sizeof(struct CertProperty));
    ret = QueryCertProperty((char *)uri->data, &certProperty);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to query certProperty, ret=%d", ret);
        return ret;
    }
    const char *temp = NULL;
    if (strlen(certProperty.uri) != 0) {
        temp = (const char *)certProperty.alias;
    } else {
        temp = object;
    }
    if (memcpy_s(displayName->data, displayName->size, temp, strlen(temp) + 1) != CM_SUCCESS) {
        CM_LOG_E("Failed to copy displayName->data");
        ret = CMR_ERROR_MEM_OPERATION_COPY;
    }
    displayName->size = strlen(temp) + 1;
    return ret;
}

static const char* GetCertType(uint32_t store)
{
    switch (store) {
        case CM_USER_TRUSTED_STORE:
            return "c";

        case CM_CREDENTIAL_STORE:
            return "ak";

        case CM_PRI_CREDENTIAL_STORE:
            return "ak";

        case CM_SYS_CREDENTIAL_STORE:
            return "sk";

        default:
            return NULL;
    }
    return NULL;
}

int32_t RdbInsertCertProperty(const struct CertPropertyOri *propertyOri)
{
    struct CertProperty certProp;
    (void)memset_s(&certProp, sizeof(struct CertProperty), 0, sizeof(struct CertProperty));
    certProp.userId = (int32_t)propertyOri->context->userId;
    certProp.uid = (int32_t)propertyOri->context->uid;
    certProp.level = propertyOri->level;

    const char *certType = GetCertType(propertyOri->store);
    if (certType == NULL) {
        CM_LOG_E("Type does not support installation");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    certProp.certStore = (int32_t)propertyOri->store;
    if (memcpy_s(certProp.certType, MAX_LEN_CERT_TYPE, certType, strlen(certType)) != EOK) {
        CM_LOG_E("memcpy certType fail");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }

    if (memcpy_s(certProp.uri, MAX_LEN_URI, (char *)propertyOri->uri->data, propertyOri->uri->size) != EOK) {
        CM_LOG_E("memcpy uri fail");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    if (memcpy_s(certProp.alias, MAX_LEN_CERT_ALIAS, (char *)propertyOri->alias->data, propertyOri->alias->size)
        != EOK) {
        CM_LOG_E("memcpy subjectName fail");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    if (memcpy_s(certProp.subjectName, MAX_LEN_SUBJECT_NAME, (char *)propertyOri->subjectName->data,
        propertyOri->subjectName->size) != EOK) {
        CM_LOG_E("memcpy subjectName fail");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }

    int32_t ret = InsertCertProperty(&certProp);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to InsertCertProperty");
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CmStoreUserCert(const char *path, const struct CmBlob *userCert, const char *userCertName)
{
    int32_t ret = CM_SUCCESS;
    if (CmUserBackupFileWrite(path, userCertName, 0, userCert->data, userCert->size) != CMR_OK) {
        CM_LOG_E("Failed to write certificate");
        ret = CMR_ERROR_WRITE_FILE_FAIL;
    }
    return ret;
}

int32_t CmGenerateSaConf(const char *userCertConfigPath, const char *userCertBakupDirPath, const char *userCertName)
{
    int32_t ret = CM_SUCCESS;
    char userCertBackupFilePath[CERT_MAX_PATH_LEN] = { 0 };

    if (userCertBakupDirPath == NULL) {
        if (snprintf_s(userCertBackupFilePath, CERT_MAX_PATH_LEN, CERT_MAX_PATH_LEN - 1, "%s", userCertName) < 0) {
            CM_LOG_E("construct userCertBackupFilePath failed");
            return CMR_ERROR_MEM_OPERATION_PRINT;
        }
    } else {
        if (snprintf_s(userCertBackupFilePath, CERT_MAX_PATH_LEN, CERT_MAX_PATH_LEN - 1, "%s/%s", userCertBakupDirPath,
                       userCertName) < 0) {
            CM_LOG_E("construct userCertBackupFilePath failed");
            return CMR_ERROR_MEM_OPERATION_PRINT;
        }
    }

    if (CmFileWrite(NULL, userCertConfigPath, 0, (const uint8_t *)userCertBackupFilePath,
                    strlen(userCertBackupFilePath)) != CMR_OK) {
        CM_LOG_E("Failed to write saconf file content");
        ret = CMR_ERROR_WRITE_FILE_FAIL;
    }
    return ret;
}

int32_t CmRemoveUserCert(struct CmMutableBlob *pathBlob, const struct CmBlob *certUri)
{
    return CertManagerFileRemove((char *)pathBlob->data, (char *)certUri->data);
}

int32_t CmBackupRemove(uint32_t userId, const char *path, const struct CmBlob *certUri)
{
    if (path == NULL) {
        CM_LOG_E("input params is invaild");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t uid = 0;
    char *uidStr = basename((char *)path);
    if (CmIsNumeric(uidStr, strlen(uidStr) + 1, &uid) != CM_SUCCESS) {
        CM_LOG_E("parse string to uint32 failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    char userCertConfigFilePath[CERT_MAX_PATH_LEN] = { 0 };
    int32_t ret = CmGetCertConfPath(userId, uid, certUri, userCertConfigFilePath, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get user cert config path failed ret = %d", ret);
        return CM_FAILURE;
    }

    ret = CmRemoveBackupUserCert(NULL, NULL, userCertConfigFilePath);
    if (ret != CMR_OK) {
        CM_LOG_E("User Cert remove config and backup file failed, ret: %d", ret);
    }
    return ret;
}

static int32_t RemoveAllUserCert(const struct CmContext *context, uint32_t store, const char* path)
{
    ASSERT_ARGS(path);
    struct CmMutableBlob fileNames = { 0, NULL };
    struct CmBlob certUri = { 0, NULL };
    int32_t ret = CertManagerGetFilenames(&fileNames, path);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed obtain filenames from path");
        return ret;
    }

    struct CmMutableBlob *fNames = (struct CmMutableBlob *)fileNames.data;
    for (uint32_t i = 0; i < fileNames.size; i++) {
        certUri.data = (uint8_t *)fNames[i].data;
        certUri.size = fNames[i].size - 1;
        ret = CertManagerFileRemove(path, (char *)fNames[i].data);
        if (ret != CMR_OK) {
            CM_LOG_E("User Cert %u remove failed, ret: %d", i, ret);
            continue;
        }
        ret = CmBackupRemove(context->userId, path, &certUri);
        if (ret != CMR_OK) {
            CM_LOG_E("User Cert %u remove config and backup file failed, ret: %d", i, ret);
        }
        ret = DeleteCertProperty((char *)certUri.data);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed delete cert: %s rdbData", (char *)certUri.data);
        }
    }

    FreeFileNames(fNames, fileNames.size);
    return ret;
}

static int32_t RemoveAllUidDir(const char* path)
{
    return CM_ERROR(CmDirRemove(path));
}

static int32_t RemoveAllConfUidDir(uint32_t userId, const char *uidPath)
{
    if (uidPath == NULL) {
        CM_LOG_E("input params is invaild");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    char configUidDirPath[CERT_MAX_PATH_LEN] = { 0 };
    uint32_t uid = 0;
    char *uidStr = basename((char *)uidPath);
    if (CmIsNumeric(uidStr, strlen(uidStr) + 1, &uid) != CM_SUCCESS) {
        CM_LOG_E("parse string to uint32 failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmGetCertConfUidDir(userId, uid, configUidDirPath, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get user cert config file UidDirPath failed, ret = %d", ret);
        return ret;
    }

    ret = CmDirRemove(configUidDirPath);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Remove user cert config file configUidDirPath fail, ret = %d", ret);
    }
    return ret;
}

int32_t CmRemoveAllUserCert(const struct CmContext *context, uint32_t store, const struct CmMutableBlob *pathList)
{
    ASSERT_ARGS(pathList && pathList->data && pathList->size);
    int32_t ret = CM_SUCCESS;
    struct CmMutableBlob *path = (struct CmMutableBlob *)pathList->data;

    for (uint32_t i = 0; i < pathList->size; i++) {
        ret = RemoveAllUserCert(context, store, (char *)path[i].data);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed remove usercert at %u_th dir", i);
            continue;
        }
        ret = RemoveAllUidDir((char *)path[i].data);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Remove UidPath fail, ret = %d", ret);
            continue;
        }
        ret = RemoveAllConfUidDir(context->userId, (char *)path[i].data);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Remove all config UidPath fail, ret = %d", ret);
            continue;
        }
    }
    return ret;
}

int32_t CmRemoveBackupUserCert(const struct CmContext *context, const struct CmBlob *certUri,
                               const char *userCertConfigFilePath)
{
    int32_t ret = CM_SUCCESS;
    char userConfigFilePath[CERT_MAX_PATH_LEN] = { 0 };
    char *userConfFilePath = NULL;

    if (userCertConfigFilePath == NULL) {
        if ((context == NULL) || (CmCheckBlob(certUri) != CM_SUCCESS)) {
            CM_LOG_E("Invalid input arguments");
            return CMR_ERROR_INVALID_ARGUMENT;
        }

        ret = CmGetCertConfPath(context->userId, context->uid, certUri, userConfigFilePath, CERT_MAX_PATH_LEN);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmGetCertConfPath failed, ret = %d", ret);
            return ret;
        }
        userConfFilePath = userConfigFilePath;
    } else {
        userConfFilePath = (char *)userCertConfigFilePath;
    }

    ret = CmRmUserCert(userConfFilePath);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("RmUserCertFile failed, ret = %d", ret);
        return ret;
    }

    ret = CmRmSaConf(userConfFilePath);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("RmSaConfFile fail, ret = %d", ret);
        return ret;
    }

    return CM_SUCCESS;
}

static int32_t HandleEmptyAlias(const struct CmBlob *certData, struct CmBlob *objectName)
{
    uint8_t encodeBuf[MAX_LEN_BASE64URL_SHA256] = { 0 };
    struct CmBlob encodeTarget = { sizeof(encodeBuf), encodeBuf };

    int32_t ret = GetNameEncode(certData, &encodeTarget);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("base64urlsha256 failed");
        return ret;
    }

    if (memcpy_s(objectName->data, objectName->size, encodeTarget.data, encodeTarget.size) != EOK) {
        CM_LOG_E("memcpy object name failed");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    return ret;
}

static int32_t HandleNotEmptyAlias(const struct CmBlob *certAlias, const enum AliasTransFormat aliasFormat,
    struct CmBlob *objectName)
{
    struct CmBlob object = { certAlias->size, certAlias->data };
    int32_t ret = CM_SUCCESS;
    // if DEFAULT_FORMAT means no chinese, objectName can be target alias
    // else if SHA256_FORMAT may include chinese or other symbols, need to hash alias as objectName
    if (aliasFormat == DEFAULT_FORMAT) {
        if (memcpy_s(objectName->data, objectName->size, object.data, object.size) != EOK) {
            CM_LOG_E("memcpy object name failed");
            return CMR_ERROR_MEM_OPERATION_COPY;
        }
    } else {
        ret = GetNameEncode(&object, objectName);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmGetHash fail, ret = %d", ret);
            return ret;
        }
    }
    return ret;
}

int32_t GetObjNameFromCertData(const struct CmBlob *certData, const struct CmBlob *certAlias,
    struct CmBlob *objectName, const enum AliasTransFormat aliasFormat)
{
    if ((CmCheckBlob(certData) != CM_SUCCESS) || (CmCheckBlob(certAlias) != CM_SUCCESS) || (objectName == NULL)) {
        CM_LOG_E("input param is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (strcmp("", (char *)certAlias->data) == 0) {
        return HandleEmptyAlias(certData, objectName);
    } else {
        return HandleNotEmptyAlias(certAlias, aliasFormat, objectName);
    }
}
#ifdef __cplusplus
}
#endif
 