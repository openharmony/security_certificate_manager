/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "securec.h"

#include "cert_manager_file_operator.h"
#include "cert_manager_mem.h"
#include "cert_manager_uri.h"
#include "cm_log.h"
#include "cm_type.h"

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

    if (snprintf_s(userIdPath, pathLen, pathLen - 1, "%s/%u", rootPath, context->userId) < 0) {
        CM_LOG_E("construct user id path failed");
        return CMR_ERROR_INVALID_OPERATION;
    }

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
    if (fileSize == 0 || fileSize > MAX_OUT_BLOB_SIZE) {
        CM_LOG_E("file size[%u] invalid", fileSize);
        return CMR_ERROR_INVALID_OPERATION;
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
        return CMR_ERROR_INVALID_OPERATION;
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

