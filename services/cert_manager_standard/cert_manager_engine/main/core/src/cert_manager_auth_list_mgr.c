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

#include "cert_manager_auth_list_mgr.h"

#include "securec.h"

#include "cert_manager.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_mem.h"
#include "cert_manager_storage.h"
#include "cert_manager_uri.h"
#include "cm_log.h"
#include "cm_type.h"

#define MAX_PATH_LEN                        512
#define MAX_AUTH_COUNT                      256
#define AUTH_LIST_VERSON                    0

static int32_t CheckAuthListFileSizeValid(const struct CmBlob *originList, uint32_t *authCount)
{
    if (originList->size < (sizeof(uint32_t) + sizeof(uint32_t))) { /* version and count size */
        CM_LOG_E("invalid authlist size[%u]", originList->size);
        return CMR_ERROR_INVALID_OPERATION;
    }

    uint32_t count = 0;
    (void)memcpy_s(&count, sizeof(count), originList->data + sizeof(uint32_t), sizeof(count));
    if (count > MAX_OUT_BLOB_SIZE) {
        CM_LOG_E("invalid auth count[%u]", count);
        return CMR_ERROR_INVALID_OPERATION;
    }

    uint32_t size = sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) * count;
    if (originList->size != size) {
        CM_LOG_E("invalid auth list file size[%u], count[%u]", originList->size, count);
        return CMR_ERROR_INVALID_OPERATION;
    }

    *authCount = count;
    return CM_SUCCESS;
}

static bool IsUidExist(const struct CmBlob *list, uint32_t count, uint32_t targetUid, uint32_t *position)
{
    uint32_t uid;
    uint32_t offset = sizeof(uint32_t) + sizeof(uint32_t);
    for (uint32_t i = 0; i < count; ++i) {
        (void)memcpy_s(&uid, sizeof(uint32_t), list->data + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        if (uid == targetUid) {
            *position = offset;
            return true;
        }
    }
    return false;
}

static int32_t CopyBlob(const struct CmBlob *originList, struct CmBlob *outList)
{
    uint8_t *data = (uint8_t *)CMMalloc(originList->size);
    if (data == NULL) {
        CM_LOG_E("out data malloc failed");
        return CMR_ERROR_MALLOC_FAIL;
    }

    (void)memcpy_s(data, originList->size, originList->data, originList->size);

    outList->data = data;
    outList->size = originList->size;
    return CM_SUCCESS;
}

static int32_t InsertUid(const struct CmBlob *originList, uint32_t uid, struct CmBlob *addedList)
{
    uint32_t count = 0;
    int32_t ret = CheckAuthListFileSizeValid(originList, &count);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    uint32_t position = 0;
    bool isUidExist = IsUidExist(originList, count, uid, &position);
    if (isUidExist) {
        /* exist then copy origin */
        return CopyBlob(originList, addedList);
    }

    if (count >= MAX_AUTH_COUNT) {
        return CMR_ERROR_INVALID_OPERATION;
    }

    uint32_t size = originList->size + sizeof(uint32_t); /* add one uid */
    uint8_t *data = (uint8_t *)CMMalloc(size);
    if (data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }

    do {
        ret = CMR_ERROR_INVALID_OPERATION;
        if (memcpy_s(data, size, originList->data, originList->size) != EOK) {
            CM_LOG_E("copy origin list failed");
            break;
        }
        if (memcpy_s(data + originList->size, size - originList->size, &uid, sizeof(uint32_t)) != EOK) {
            CM_LOG_E("copy inserted uid failed");
            break;
        }

        /* refresh count after add */
        uint32_t countAfterAdd = count + 1;
        if (memcpy_s(data + sizeof(uint32_t), sizeof(countAfterAdd), &countAfterAdd, sizeof(countAfterAdd)) != EOK) {
            CM_LOG_E("refresh count after add failed");
            break;
        }
        ret = CM_SUCCESS;
    } while (0);
    if (ret != CM_SUCCESS) {
        CM_FREE_PTR(data);
        return ret;
    }

    addedList->data = data;
    addedList->size = size;
    return CM_SUCCESS;
}

static int32_t RemoveUid(const struct CmBlob *originList, uint32_t uid, struct CmBlob *removedList)
{
    uint32_t count = 0;
    int32_t ret = CheckAuthListFileSizeValid(originList, &count);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    uint32_t position = 0;
    bool isUidExist = IsUidExist(originList, count, uid, &position);
    if (!isUidExist) {
        /* not exist then copy origin */
        return CopyBlob(originList, removedList);
    }

    uint32_t size = originList->size - sizeof(uint32_t);  /* delete one uid */
    uint8_t *data = (uint8_t *)CMMalloc(size);
    if (data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }

    do {
        ret = CMR_ERROR_INVALID_OPERATION;
        uint32_t beforeSize = position - sizeof(uint32_t); /* positon >= 12 */
        if (memcpy_s(data, size, originList->data, beforeSize) != EOK) {
            CM_LOG_E("copy origin list before uid failed");
            break;
        }

        if (size > beforeSize) { /* has buffer after uid */
            if (memcpy_s(data + beforeSize, size - beforeSize, originList->data + position,
                originList->size - position) != EOK) {
                CM_LOG_E("copy origin list after uid failed");
                break;
            }
        }

        /* refresh count after remove */
        uint32_t countAfterRemove = count - 1; /* count > 1 */
        if (memcpy_s(data + sizeof(uint32_t), sizeof(countAfterRemove),
            &countAfterRemove, sizeof(countAfterRemove)) != EOK) {
            CM_LOG_E("refresh count after delete failed");
            break;
        }
        ret = CM_SUCCESS;
    } while (0);
    if (ret != CM_SUCCESS) {
        CM_FREE_PTR(data);
        return ret;
    }

    removedList->data = data;
    removedList->size = size;
    return CM_SUCCESS;
}

static int32_t RefreshAuthListBuf(const char *path, const char *fileName, uint32_t uid, bool isAdd,
    struct CmBlob *authList)
{
    struct CmBlob list = { 0, NULL };
    int32_t ret = CmStorageGetBuf(path, fileName, &list);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (isAdd) {
        ret = InsertUid(&list, uid, authList);
    } else {
        ret = RemoveUid(&list, uid, authList);
    }
    CM_FREE_PTR(list.data);
    return ret;
}

/*
 * auth list buffer format:
 * |--version--|--uidCount(n)--|--uid0--|--uid1--|...|--uid(n-1)--|
 * |   4Byte   |      4Byte    |  4Byte |  4Byte |...|  4Byte     |
 */
static int32_t InitAuthListBuf(uint32_t uid, struct CmBlob *authList)
{
    uint32_t count = 1;
    uint32_t version = AUTH_LIST_VERSON;
    uint32_t size = sizeof(version) + sizeof(count) + sizeof(uid) * count;
    uint8_t *data = (uint8_t *)CMMalloc(size);
    if (data == NULL) {
        CM_LOG_E("malloc file buffer failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(data, size, 0, size);

    int32_t ret = CM_SUCCESS;
    uint32_t offset = 0;
    do {
        if (memcpy_s(data + offset, size - offset, &version, sizeof(version)) != EOK) {
            CM_LOG_E("copy count failed");
            ret = CMR_ERROR_INVALID_OPERATION;
            break;
        }
        offset += sizeof(version);

        if (memcpy_s(data + offset, size - offset, &count, sizeof(count)) != EOK) {
            CM_LOG_E("copy count failed");
            ret = CMR_ERROR_INVALID_OPERATION;
            break;
        }
        offset += sizeof(count);

        if (memcpy_s(data  + offset, size - offset, &uid, sizeof(uid)) != EOK) {
            CM_LOG_E("copy uid failed");
            ret = CMR_ERROR_INVALID_OPERATION;
            break;
        }
    } while (0);
    if (ret != CM_SUCCESS) {
        CM_FREE_PTR(data);
        return ret;
    }

    authList->data = data;
    authList->size = size;
    return CM_SUCCESS;
}

static int32_t RefreshAuthList(const char *path, const char *fileName, uint32_t uid, bool isAdd)
{
    bool isAuthListExist = false;
    int32_t ret = CmIsFileExist(path, fileName);
    if (ret == CM_SUCCESS) {
        isAuthListExist = true;
    }

    if (!isAuthListExist && !isAdd) {
        CM_LOG_I("auth list file not exit when delete uid");
        return CM_SUCCESS; /* auth list file not exit when delete uid */
    }

    struct CmBlob authList = { 0, NULL };
    if (isAuthListExist) {
        ret = RefreshAuthListBuf(path, fileName, uid, isAdd, &authList);
    } else { /* auth list file not exit when add uid */
        ret = InitAuthListBuf(uid, &authList);
    }
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ret = CmFileWrite(path, fileName, 0, authList.data, authList.size);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("write file failed");
    }
    CM_FREE_PTR(authList.data);
    return ret;
}

static int32_t FormatAppUidList(const struct CmBlob *list, struct CmAppUidList *appUidList)
{
    uint32_t count = 0;
    int32_t ret = CheckAuthListFileSizeValid(list, &count);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (count == 0) {
        appUidList->appUidCount = 0;
        CM_LOG_I("auth list has no auth uid");
        return CM_SUCCESS; /* has no auth uid */
    }

    uint8_t *data = (uint8_t *)CMMalloc(count * sizeof(uint32_t));
    if (data == NULL) {
        CM_LOG_E("malloc app uid buffer failed");
        return ret = CMR_ERROR_MALLOC_FAIL;
    }

    uint32_t offsetOut = 0;
    uint32_t offset = sizeof(uint32_t) + sizeof(uint32_t);
    for (uint32_t i = 0; i < count; ++i) {
        (void)memcpy_s(data + offsetOut, sizeof(uint32_t), list->data + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        offsetOut += sizeof(uint32_t);
    }

    appUidList->appUidCount = count;
    appUidList->appUid = (uint32_t *)data;
    return CM_SUCCESS;
}

int32_t CmAddAuthUid(const struct CmContext *context, const struct CmBlob *uri, uint32_t uid)
{
    int32_t ret = CmCheckCredentialExist(context, uri);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    char authListPath[MAX_PATH_LEN] = { 0 };
    ret = ConstructAuthListPath(context, CM_CREDENTIAL_STORE, authListPath, MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ret = RefreshAuthList(authListPath, (char *)uri->data, uid, true);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("refresh auth list failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmRemoveAuthUid(const struct CmContext *context, const struct CmBlob *uri, uint32_t uid)
{
    char authListPath[MAX_PATH_LEN] = { 0 };
    int32_t ret = ConstructAuthListPath(context, CM_CREDENTIAL_STORE, authListPath, MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ret = RefreshAuthList(authListPath, (char *)uri->data, uid, false);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("refresh auth list failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmGetAuthList(const struct CmContext *context, const struct CmBlob *uri, struct CmAppUidList *appUidList)
{
    char authListPath[MAX_PATH_LEN] = { 0 };
    int32_t ret = ConstructAuthListPath(context, CM_CREDENTIAL_STORE, authListPath, MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    /* auth list file not exist */
    ret = CmIsFileExist(authListPath, (char *)uri->data);
    if (ret != CM_SUCCESS) {
        CM_LOG_I("auth list file not exist.");
        appUidList->appUidCount = 0;
        return CM_SUCCESS;
    }

    struct CmBlob list = { 0, NULL };
    ret = CmStorageGetBuf(authListPath, (char *)uri->data, &list);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ret = FormatAppUidList(&list, appUidList);
    CM_FREE_PTR(list.data);
    return ret;
}

int32_t CmDeleteAuthListFile(const struct CmContext *context, const struct CmBlob *uri)
{
    char authListPath[MAX_PATH_LEN] = { 0 };
    int32_t ret = ConstructAuthListPath(context, CM_CREDENTIAL_STORE, authListPath, MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ret = CmIsFileExist(authListPath, (char *)uri->data);
    if (ret != CM_SUCCESS) { /* auth list file not exist */
        return CM_SUCCESS;
    }

    ret = CmFileRemove(authListPath, (char *)uri->data);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("remove file failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmCheckIsAuthUidExist(const struct CmContext *context, const struct CmBlob *uri,
    uint32_t targetUid, bool *isInAuthList)
{
    *isInAuthList = false;

    char authListPath[MAX_PATH_LEN] = { 0 };
    int32_t ret = ConstructAuthListPath(context, CM_CREDENTIAL_STORE, authListPath, MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ret = CmIsFileExist(authListPath, (char *)uri->data);
    if (ret != CM_SUCCESS) { /* auth list file not exist */
        return CM_SUCCESS;
    }

    struct CmBlob list = { 0, NULL };
    ret = CmStorageGetBuf(authListPath, (char *)uri->data, &list);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    uint32_t count = 0;
    ret = CheckAuthListFileSizeValid(&list, &count);
    if (ret != CM_SUCCESS) {
        CM_FREE_PTR(list.data);
        return ret;
    }

    uint32_t position = 0;
    *isInAuthList = IsUidExist(&list, count, targetUid, &position);
    CM_FREE_PTR(list.data);

    return CM_SUCCESS;
}

int32_t CmRemoveAuthUidByUserId(uint32_t userId, uint32_t targetUid, const struct CmBlob *uri)
{
    uint32_t uid = 0;
    int32_t ret = CertManagerGetUidFromUri(uri, &uid);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    struct CmContext context = { userId, uid, { 0 } };
    return CmRemoveAuthUid(&context, uri, targetUid);
}

int32_t CmGetAuthListByUserId(uint32_t userId, const struct CmBlob *uri, struct CmAppUidList *appUidList)
{
    uint32_t uid = 0;
    int32_t ret = CertManagerGetUidFromUri(uri, &uid);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    struct CmContext context = { userId, uid, { 0 } };
    return CmGetAuthList(&context, uri, appUidList);
}

int32_t CmDeleteAuthListFileByUserId(uint32_t userId, const struct CmBlob *uri)
{
    uint32_t uid = 0;
    int32_t ret = CertManagerGetUidFromUri(uri, &uid);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    struct CmContext context = { userId, uid, { 0 } };
    return CmDeleteAuthListFile(&context, uri);
}

int32_t CmCheckIsAuthUidExistByUserId(uint32_t userId, uint32_t targetUid,
    const struct CmBlob *uri, bool *isInAuthList)
{
    uint32_t uid = 0;
    int32_t ret = CertManagerGetUidFromUri(uri, &uid);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    struct CmContext context = { userId, uid, { 0 } };
    return CmCheckIsAuthUidExist(&context, uri, targetUid, isInAuthList);
}

int32_t CmCheckCredentialExist(const struct CmContext *context, const struct CmBlob *uri)
{
    char uidPath[MAX_PATH_LEN] = { 0 };
    int32_t ret = ConstructUidPath(context, CM_CREDENTIAL_STORE, uidPath, MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    char *fileName = (char *)uri->data;
    ret = CmIsFileExist(uidPath, fileName);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Credential file not exist.");
    }
    return ret;
}

