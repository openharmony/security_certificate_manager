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

#include "cert_manager_status.h"

#include <pthread.h>

#include "securec.h"

#include "cert_manager.h"
#include "cert_manager_crypto_operation.h"
#include "cert_manager_file.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_key_operation.h"
#include "cert_manager_mem.h"
#include "cm_log.h"
#include "cm_type.h"
#include "rbtree.h"
#include "cert_manager_uri.h"
#include "cert_manager_storage.h"

#define HEADER_LEN (4 + CM_INTEGRITY_TAG_LEN + CM_INTEGRITY_SALT_LEN)
#define APPLICATION_TRUSTED_STORE      2
#define ENCODED_INT_COUNT              3

#define MAX_NAME_DIGEST_LEN            64
#define RB_TREE_KEY_LEN                4

#define MAX_STATUS_TREE_MALLOC_SIZE    (5 * 1024 * 1024)   /* max 5M tree file size */

#ifdef __cplusplus
extern "C" {
#endif

/* red-black tree to store disabled certificate file names. */
static struct RbTree g_trees[] = { {0}, {0}, {0} };
static const uint32_t g_treeCount = 3;

static const char *g_statusFiles[] = {
    CERT_STATUS_SYSTEM_STORE,
    CERT_STATUS_USER_STORE,
    CERT_STATUS_APPLICATION_STORE,
};

static pthread_rwlock_t g_treeLocks[] = {
    PTHREAD_RWLOCK_INITIALIZER,
    PTHREAD_RWLOCK_INITIALIZER,
    PTHREAD_RWLOCK_INITIALIZER,
};

static pthread_rwlock_t g_fileLocks[] = {
    PTHREAD_RWLOCK_INITIALIZER,
    PTHREAD_RWLOCK_INITIALIZER,
    PTHREAD_RWLOCK_INITIALIZER,
};

static pthread_rwlock_t g_statusLock = PTHREAD_RWLOCK_INITIALIZER;

struct CertEnableStatus {
    bool getter;
    uint32_t *oldStatus;
    uint32_t status;
};

struct TreeNode {
    uint32_t store;
    bool *found;
    RbTreeKey key;
};

static int32_t Ikhmac(uint8_t *data, uint32_t len, uint8_t *mac)
{
    struct CmBlob dataBlob = { .size = len, .data = data };
    struct CmBlob macBlob = { .size = CM_INTEGRITY_TAG_LEN, .data = mac };

    char aliasData[] = CM_INTEGRITY_KEY_URI;
    struct CmBlob alias = { strlen(aliasData), (uint8_t *)aliasData };
    return CmKeyOpCalcMac(&alias, &dataBlob, &macBlob, CM_AUTH_STORAGE_LEVEL_EL1);
}

static void FreeStatus(struct CertStatus *cs)
{
    if (cs != NULL) {
        if (cs->fileName != NULL) {
            CMFree(cs->fileName);
        }
        CMFree(cs);
    }
}

static int GetStoreIndex(uint32_t store)
{
    switch (store) {
        case CM_SYSTEM_TRUSTED_STORE:
            return 0;
        case CM_USER_TRUSTED_STORE:
            return 1;
        case CM_PRI_CREDENTIAL_STORE:
            return APPLICATION_TRUSTED_STORE;
        default:
            CM_LOG_W("No index for store %u\n", store);
            return -1;
    }
}

static int EncodeStatus(RbTreeValue value, uint8_t *buf, uint32_t *size)
{
    /* each cert status struct is encoded as (userId | uid | status | fileName)
       Note that fileName is null terminated */

    struct CertStatus *cs = (struct CertStatus *) value;
    if (cs == NULL) {
        CM_LOG_E("Unexpected NULL value.\n");
        return CMR_ERROR;
    }

    /* encode 3 integers and a string */
    uint32_t sz = 3 * sizeof(uint32_t) + strlen(cs->fileName) + 1;

    if (buf == NULL) {
        /* only return the required size */
        *size = sz;
        return CMR_OK;
    }

    if (*size < sz) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    uint8_t *s = buf;
    uint32_t r = *size;

    if (memcpy_s(s, r, &cs->userId, sizeof(uint32_t)) != EOK) {
        CM_LOG_W("Failed to cs->userId ");
        return CMR_ERROR;
    }
    s += sizeof(uint32_t);
    r -= sizeof(uint32_t);

    if (memcpy_s(s, r, &cs->uid, sizeof(uint32_t)) != EOK) {
        CM_LOG_W("Failed to cs->uid ");
        return CMR_ERROR;
    }
    s += sizeof(uint32_t);
    r -= sizeof(uint32_t);

    if (memcpy_s(s, r, &cs->status, sizeof(uint32_t)) != EOK) {
        CM_LOG_W("Failed to cs->status ");
        return CMR_ERROR;
    }
    s += sizeof(uint32_t);
    r -= sizeof(uint32_t);

    if (memcpy_s(s, r, cs->fileName, strlen(cs->fileName) + 1) != EOK) {
        CM_LOG_W("Failed to cs->fileName ");
        return CMR_ERROR;
    }

    *size = sz;
    return CMR_OK;
}

static void DecodeFreeStatus(RbTreeValue *value)
{
    if (value == NULL || *value == NULL) {
        return;
    }

    /* value is used internally, it can ensure that the type conversion is safe */
    FreeStatus((struct CertStatus *)*value);
    *value = NULL;
}

static int DecodeStatus(RbTreeValue *value, const uint8_t *buf, uint32_t size)
{
    /* each cert status struct is encoded as (userId | uid | status | fileName)
       Note that fileName is null terminated
       Require 3 integers and at least 1 character */
    if (buf == NULL || size < ENCODED_INT_COUNT * sizeof(uint32_t) + 1) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    if (buf[size - 1] != '\0') {
        CM_LOG_E("Unexpected cert status value");
        return CMR_ERROR;
    }

    struct CertStatus *cs = (struct CertStatus *)CMMalloc(sizeof(struct CertStatus));
    if (cs == NULL) {
        CM_LOG_E("Failed to allocate memory");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(cs, sizeof(struct CertStatus), 0, sizeof(struct CertStatus));

    const uint8_t *s = buf;

    int32_t ret = CM_FAILURE;
    do {
        if (memcpy_s(&cs->userId, sizeof(uint32_t), s, sizeof(uint32_t)) != EOK) {
            break;
        }
        s += sizeof(uint32_t);

        if (memcpy_s(&cs->uid, sizeof(uint32_t), s, sizeof(uint32_t)) != EOK) {
            break;
        }
        s += sizeof(uint32_t);

        if (memcpy_s(&cs->status, sizeof(uint32_t), s, sizeof(uint32_t)) != EOK) {
            break;
        }
        s += sizeof(uint32_t);
        ret = CM_SUCCESS;
    } while (0);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy to cs failed");
        CMFree(cs);
        return ret;
    }

    cs->fileName = strdup((char *)s);
    if (cs->fileName == NULL) {
        CM_LOG_E("strdup to cs->fileName failed");
        CMFree(cs);
        return CMR_ERROR_MALLOC_FAIL;
    }
    *value = cs;
    return CMR_OK;
}

static int32_t ReadFile(const char *file, uint8_t **bufptr, uint32_t *size)
{
    uint32_t sz = 0;
    int32_t rc = CMR_OK;
    uint8_t *buf = NULL;
    uint32_t nb = 0;

    sz = CertManagerFileSize(CERT_STATUS_DIR, file);
    if (sz == 0) {
        CM_LOG_D("Status file not found\n");
        goto finally;
    }

    if (sz < HEADER_LEN) {
        CM_LOG_W("Status file size too small. Must be at least %u bytes.\n", HEADER_LEN);
        rc = CMR_ERROR_STORAGE;
        goto finally;
    }

    buf = CMMalloc(sz);
    if (buf == NULL) {
        CM_LOG_W("Failed to allocate memory.\n");
        rc = CMR_ERROR_MALLOC_FAIL;
        goto finally;
    }
    nb = CertManagerFileRead(CERT_STATUS_DIR, file, 0, buf, sz);
    if (nb != sz) {
        CM_LOG_W("Failed to read status file: %u bytes expected but only has %u\n", sz, nb);
        rc = CMR_ERROR_STORAGE;
        goto finally;
    }

finally:
    if (rc != CMR_OK) {
        FREE_PTR(buf);
    } else {
        *bufptr = buf;
        *size = sz;
    }
    return rc;
}

static int32_t LoadTreeStatus(struct RbTree *tree, pthread_rwlock_t *treeLock, uint8_t *buf, uint32_t sz)
{
    int32_t rc = CMR_OK;
    if (buf == NULL || sz == 0) {
        /* file does not exist or is empty */
        CM_LOG_D("Status file does not exist or is empty.");
        return CMR_OK;
    }

    uint32_t ver = DECODE_UINT32(buf);
    /* currently version 1 (with value 0) is supported */
    if (ver != VERSION_1) {
        CM_LOG_W("Unsupported version: %u\n", ver);
        return CMR_ERROR;
    }

    uint8_t *tag = buf + sizeof(uint32_t);
    uint8_t *data = tag + CM_INTEGRITY_TAG_LEN;
    uint32_t dataLen = sz - sizeof(uint32_t) - CM_INTEGRITY_TAG_LEN;
    uint8_t mac[CM_INTEGRITY_TAG_LEN] = {0};

    ASSERT_FUNC(Ikhmac(data, dataLen, mac));
    if (memcmp(mac, tag, CM_INTEGRITY_TAG_LEN)) {
        CM_LOG_W("Status file MAC mismatch.\n");
        return CMR_ERROR;
    }

    data += CM_INTEGRITY_SALT_LEN;
    dataLen -= CM_INTEGRITY_SALT_LEN;
    if (dataLen > 0) {
        pthread_rwlock_wrlock(treeLock);
        rc = RbTreeDecode(tree, DecodeStatus, DecodeFreeStatus, data, dataLen);
        pthread_rwlock_unlock(treeLock);

        if (rc != CMR_OK) {
            CM_LOG_E("Failed to decode status tree: %d", rc);
            return rc;
        }
    }
    CM_LOG_D("Status loaded for store");
    return rc;
}

static int32_t LoadStatus(uint32_t store)
{
    uint32_t sz = 0;
    int32_t rc = CMR_OK;
    uint8_t *buf = NULL;

    int storeIndex = GetStoreIndex(store);
    if (storeIndex < 0) {
        return CMR_ERROR;
    }
    struct RbTree *tree = &g_trees[storeIndex];
    const char *file = g_statusFiles[storeIndex];
    pthread_rwlock_t *fileLock = &g_fileLocks[storeIndex];
    pthread_rwlock_t *treeLock = &g_treeLocks[storeIndex];

    pthread_rwlock_rdlock(fileLock);
    rc = ReadFile(file, &buf, &sz);
    pthread_rwlock_unlock(fileLock);

    if (rc != CMR_OK) {
        CM_LOG_E("Failed to read status file: %d", rc);
        return rc;
    }

    rc = LoadTreeStatus(tree, treeLock, buf, sz);

    if (buf != NULL) {
        CMFree(buf);
    }
    return rc;
}

static int32_t EncodeTree(struct RbTree *tree, uint8_t **bufptr, uint32_t *size)
{
    uint32_t sz = 0;
    int32_t rc = RbTreeEncode(tree, EncodeStatus, NULL, &sz);
    if (rc != CM_SUCCESS) {
        CM_LOG_E("get rbtree encode length failed, ret = %d", rc);
        return rc;
    }
    if (sz > MAX_STATUS_TREE_MALLOC_SIZE) {
        CM_LOG_E("invalid encode tree size[%u]", sz);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    sz += HEADER_LEN;
    uint8_t *buf = (uint8_t *)CMMalloc(sz);
    if (buf == NULL) {
        CM_LOG_E("Failed to allocate memory.\n");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(buf, sz, 0, sz);

    ENCODE_UINT32(buf, VERSION_1);

    uint8_t *salt = buf + sizeof(uint32_t) + CM_INTEGRITY_TAG_LEN;
    struct CmBlob r = { CM_INTEGRITY_SALT_LEN, salt };
    (void)CmGetRandom(&r); /* ignore retcode */

    uint8_t *data = buf + HEADER_LEN;
    uint32_t dataLen = sz - HEADER_LEN;
    rc = RbTreeEncode(tree, EncodeStatus, data, &dataLen);
    if (rc != CM_SUCCESS) {
        CM_LOG_E("encode status tree failed, ret = %d", rc);
        FREE_PTR(buf);
        return rc;
    }

    *bufptr = buf;
    *size = sz;
    return rc;
}

static int32_t WriteStatus(uint32_t store)
{
    int storeIndex = GetStoreIndex(store);
    if (storeIndex < 0) {
        return CMR_ERROR;
    }
    struct RbTree *tree = &g_trees[storeIndex];
    const char *file = g_statusFiles[storeIndex];
    pthread_rwlock_t *fileLock = &g_fileLocks[storeIndex];
    pthread_rwlock_t *treeLock = &g_treeLocks[storeIndex];

    int32_t rc = CMR_OK;
    uint8_t *buf = NULL;
    uint32_t sz = 0;

    pthread_rwlock_rdlock(treeLock);
    rc = EncodeTree(tree, &buf, &sz);
    pthread_rwlock_unlock(treeLock);

    if (rc != CMR_OK) {
        CM_LOG_E("Failed to encode status tree: %d", rc);
        goto finally;
    }

    uint8_t *tag = buf + sizeof(uint32_t);
    uint8_t *data = tag + CM_INTEGRITY_TAG_LEN;
    uint32_t dataLen = sz - sizeof(uint32_t) - CM_INTEGRITY_TAG_LEN;

    TRY_FUNC(Ikhmac(data, dataLen, tag), rc);

    pthread_rwlock_wrlock(fileLock);
    rc = CertManagerFileWrite(CERT_STATUS_DIR, file, 0, buf, sz);
    pthread_rwlock_unlock(fileLock);
    if (rc != CMR_OK) {
        CM_LOG_E("Failed to write status file: %d", rc);
    }

finally:
    if (buf != NULL) {
        CMFree(buf);
    }
    return rc;
}

static void FreeTreeNodeValue(RbTreeKey key, RbTreeValue value, const void *context)
{
    (void)key;
    (void)context;
    if (value != NULL) {
        /* value is used internally, it can ensure that the type conversion is safe */
        FreeStatus((struct CertStatus *)value);
    }
}

static void DestroyTree(uint32_t store)
{
    int storeIndex = GetStoreIndex(store);
    if (storeIndex < 0) {
        return;
    }
    struct RbTree *tree = &g_trees[storeIndex];
    pthread_rwlock_t *treeLock = &g_treeLocks[storeIndex];

    pthread_rwlock_wrlock(treeLock);
    RbTreeDestroyEx(tree, FreeTreeNodeValue);
    pthread_rwlock_unlock(treeLock);
}

static void DestroyStatusTree(void)
{
    DestroyTree(CM_SYSTEM_TRUSTED_STORE);
    DestroyTree(CM_USER_TRUSTED_STORE);
    DestroyTree(CM_PRI_CREDENTIAL_STORE);
}

int32_t CertManagerStatusInit(void)
{
    int rc = CMR_OK;
    if (CmMakeDir(CERT_STATUS_DIR) == CMR_ERROR_MAKE_DIR_FAIL) {
        CM_LOG_E("Failed to create folder\n");
        return CMR_ERROR_WRITE_FILE_FAIL;
    }

    pthread_rwlock_wrlock(&g_statusLock);
    for (uint32_t i = 0; i < g_treeCount; i++) {
        TRY_FUNC(RbTreeNew(&g_trees[i]), rc);
    }

    char aliasData[] = CM_INTEGRITY_KEY_URI;
    struct CmBlob alias = { strlen(aliasData), (uint8_t *)aliasData };
    TRY_FUNC(CmKeyOpGenMacKeyIfNotExist(&alias), rc);
    TRY_FUNC(LoadStatus(CM_SYSTEM_TRUSTED_STORE), rc);
    TRY_FUNC(LoadStatus(CM_USER_TRUSTED_STORE), rc);
    TRY_FUNC(LoadStatus(CM_PRI_CREDENTIAL_STORE), rc);

finally:
    if (rc != CM_SUCCESS) {
        DestroyStatusTree();
    }
    pthread_rwlock_unlock(&g_statusLock);
    return rc;
}

static RbTreeKey GetRbTreeKeyFromName(const char *name)
{
    /* use the first 4 bytes of file name (exluding the first bit) as the key */
    uint32_t len = strlen(name);
    if (len == 0) {
        return 0;
    }

    len = (len < RB_TREE_KEY_LEN) ? len : RB_TREE_KEY_LEN;
    uint8_t temp[RB_TREE_KEY_LEN] = {0};
    if (memcpy_s(temp, RB_TREE_KEY_LEN, name, len) != EOK) {
        return 0;
    }

    return DECODE_UINT32(temp) & 0x7fffffff;
}

static RbTreeKey GetRbTreeKeyFromNameBlob(const struct CmBlob *name)
{
    /* name size is ensured bigger than 4; use the first 4 bytes of file name (exluding the first bit) as the key */
    return DECODE_UINT32(name->data) & 0x7fffffff;
}

static RbTreeKey GetRbTreeKey(uint32_t store, const char *fn)
{
    if (store == CM_SYSTEM_TRUSTED_STORE) {
        return GetRbTreeKeyFromName(fn);
    }

    uint8_t tempBuf[MAX_NAME_DIGEST_LEN] = {0};
    struct CmBlob nameDigest = { sizeof(tempBuf), tempBuf };
    struct CmBlob certName = { (uint32_t)strlen(fn) + 1, (uint8_t *)fn };
    (void)CmGetHash(&certName, &nameDigest); /* ignore return code: nameDigest is 0 */

    return GetRbTreeKeyFromNameBlob(&nameDigest);
}

static uint32_t GetCertStatusNode(const struct RbTreeNode *node)
{
    if (node == NULL) {
        /* not in the cache. by .default certificate is enabled. */
        return CERT_STATUS_ENABLED;
    }

    struct CertStatus *cs = node->value;
    if (cs == NULL) {
        return CERT_STATUS_ENABLED;
    }
    return cs->status;
}

static int32_t SetCertStatusNode(const struct CmContext *ctx, struct RbTree *tree,
    struct RbTreeNode *node, const char *name, uint32_t status)
{
    if (node != NULL) {
        /* found a matching node */
        struct CertStatus *cs = node->value;
        if (cs == NULL) {
            CM_LOG_E("No status attached to tree node !!\n");
            return CMR_ERROR;
        }

        if (status == CERT_STATUS_ENABLED) {
            /* the default status is ENABLED. hence, we just delete it from the tree */
            FreeStatus(cs);
            node->value = NULL;
            return RbTreeDelete(tree, node);
        }

        /* for other status values, just overwrite */
        cs->status = status;
        return CMR_OK;
    } else {
        /* no match was found, insert a new node */
        struct CertStatus *cs = CMMalloc(sizeof(struct CertStatus));
        if (cs == NULL) {
            CM_LOG_E("Unable to allocate memory!!\n");
            return CMR_ERROR_MALLOC_FAIL;
        }
        cs->userId = ctx->userId;
        cs->uid = ctx->uid;
        cs->fileName = strdup(name);
        if (cs->fileName == NULL) {
            CM_LOG_E("strdup to cs->fileName failed\n");
            CMFree(cs);
            return CMR_ERROR_MALLOC_FAIL;
        }
        cs->status = status;
        int rc = RbTreeInsert(tree, GetRbTreeKeyFromName(name), cs);
        if (rc != CMR_OK) {
            CM_LOG_E("Failed to insert new node: %d\n", rc);
            CMFree(cs->fileName);
            CMFree(cs);
        }
        return rc;
    }
}

static int32_t SetUserCertStatusNode(const struct CertStatus *valInfo, struct RbTree *tree,
    struct RbTreeNode *node, const char *name, uint32_t store)
{
    uint32_t status = valInfo->status;

    if (node != NULL) {
        /* found a matching node */
        struct CertStatus *cStatus = node->value;
        if (cStatus == NULL) {
            CM_LOG_E("No status attached to tree node !!\n");
            return CMR_ERROR;
        }

        if (status == CERT_STATUS_ENABLED) {
            /* the default status is ENABLED. hence, we just delete it from the tree */
            FreeStatus(cStatus);
            node->value = NULL;
            return RbTreeDelete(tree, node);
        }

        /* for other status values, just overwrite */
        cStatus->status = status;
        return CMR_OK;
    } else {
        /* no match was found, insert a new node */
        struct CertStatus *cStatus = CMMalloc(sizeof(struct CertStatus));
        if (cStatus == NULL) {
            CM_LOG_E("Unable to allocate memory!!\n");
            return CMR_ERROR_MALLOC_FAIL;
        }
        cStatus->userId = valInfo->userId;
        cStatus->uid = valInfo->uid;
        cStatus->fileName = strdup(name);
        if (cStatus->fileName == NULL) {
            CM_LOG_E("strdup to cs->fileName failed\n");
            CMFree(cStatus);
            return CMR_ERROR_MALLOC_FAIL;
        }
        cStatus->status = status;
        int rc = RbTreeInsert(tree, GetRbTreeKey(store, name), cStatus);
        if (rc != CMR_OK) {
            CM_LOG_E("Failed to insert new node: %d\n", rc);
            CMFree(cStatus->fileName);
            CMFree(cStatus);
        }
        return rc;
    }
}


/* return true if the status matches the filename and the caller */
static bool StatusMatch(const struct CmContext *context, const struct CertStatus *cs,
    uint32_t store, const char *fileName)
{
    if (context == NULL || cs == NULL || fileName == NULL) {
        CM_LOG_E("Paramset is NULL");
        return false;
    }

    if (strcmp(cs->fileName, fileName)) {
        /* file name must always match */
        return false;
    }

    if (store == CM_USER_TRUSTED_STORE) {
        /* for user store, the user ID must match the caller */
        if (cs->userId != context->userId) {
            return false;
        }
    } else if (store == CM_PRI_CREDENTIAL_STORE) {
        /* for application store, the user ID and app UID must match the caller */
        if (cs->userId != context->userId ||
                cs->uid != context->uid) {
            return false;
        }
    }
    return true;
}

static int32_t CertManagerFindMatchedFile(const struct CmContext *context, struct RbTreeNode **treeNode,
    struct RbTree *tree, struct TreeNode tempPara, const char *fn)
{
    uint32_t store = tempPara.store;
    bool *found = tempPara.found;
    RbTreeKey key = tempPara.key;
    struct RbTreeNode *node = *treeNode;

    while (node != NULL && node != tree->nil) {
        struct CertStatus *cs = node->value;
        if (cs == NULL) {
            /* shouldn't happen */
            CM_LOG_E("No value set to status node.\n");
            return CMR_ERROR;
        }

        if (StatusMatch(context, cs, store, fn)) {
            /* match found */
            *found = true;
            break;
        }

        if (node->right != tree->nil && RbTreeNodeKey(node->right) == key) {
            node = node->right;
        } else if (node->left != tree->nil && RbTreeNodeKey(node->left) == key) {
            node = node->left;
        } else {
            /* no match possible */
            break;
        }
    }
    *treeNode = node;
    return CMR_OK;
}

static int32_t CertManagerStatus(const struct CmContext *context, struct RbTree *tree,
    struct CertEnableStatus certStatus, uint32_t store, const char *fn)
{
    int rc = CMR_OK;
    bool found = false;
    struct RbTreeNode *node = NULL;
    bool getter = certStatus.getter;
    uint32_t status = certStatus.status;
    uint32_t *oldStatus = certStatus.oldStatus;
    RbTreeKey key = GetRbTreeKey(store, fn);

    rc = RbTreeFindNode(&node, key, tree);
    if (rc != CMR_OK && rc != CMR_ERROR_NOT_FOUND) {
        /* someting is wrong */
        CM_LOG_W("Failed to search in the status cache");
        return rc;
    }

    /* furthrt check if the actual file name matched. */
    struct TreeNode tempPara = {store, &found, key};
    rc = CertManagerFindMatchedFile(context, &node, tree, tempPara, fn);
    if (rc != CMR_OK) {
        CM_LOG_W("Failed to search file name");
        return rc;
    }

    if (!found) {
        node = NULL;
    }

    *oldStatus = GetCertStatusNode(node);
    if (!getter && *oldStatus != status) {
        CM_LOG_D("start setting status");
        if (store == CM_SYSTEM_TRUSTED_STORE) {
            ASSERT_FUNC(SetCertStatusNode(context, tree, node, fn, status));
        } else {
            struct CertStatus valueInfo = { context->userId, context->uid, status, NULL };
            ASSERT_FUNC(SetUserCertStatusNode(&valueInfo, tree, node, fn, store));
        }
    }
    return rc;
}

static int32_t CertManagerStatusFile(const struct CmContext *context, struct CertFile certFile,
    uint32_t store, const uint32_t status, uint32_t *stp)
{
    ASSERT_ARGS(context && certFile.path && certFile.fileName);
    ASSERT_ARGS(certFile.path->size && certFile.path->data && certFile.fileName->size && certFile.fileName->data);
    ASSERT_ARGS((status <= CERT_STATUS_MAX || stp != NULL));

    int rc = CMR_OK;
    uint32_t oldStatus = 0;
    bool getter = (stp != NULL);
    int storeIndex = GetStoreIndex(store);
    if (storeIndex < 0) {
        return CMR_ERROR;
    }
    pthread_rwlock_t *lock = &g_treeLocks[storeIndex];
    struct RbTree *tree = &g_trees[storeIndex];

    char fn[MAX_LEN_URI] = {0};
    if (memcpy_s(fn, MAX_LEN_URI, certFile.fileName->data, certFile.fileName->size) != EOK) {
        CM_LOG_E("copy filename error");
        return CMR_ERROR;
    }

    if (getter) {
        pthread_rwlock_rdlock(lock);
    } else {
        pthread_rwlock_wrlock(lock);
    }
    struct CertEnableStatus certStatus = {getter, &oldStatus, status};
    rc = CertManagerStatus(context, tree, certStatus, store, fn);

    pthread_rwlock_unlock(lock);
    if (rc != CMR_OK && rc != CMR_ERROR_NOT_FOUND) {
        /* error occured */
        return rc;
    }
    if (getter) {
        *stp = oldStatus;
    } else if (oldStatus != status) {
        /* setter */
        ASSERT_FUNC(WriteStatus(store));
    }
    return CMR_OK;
}

int32_t SetcertStatus(const struct CmContext *context, const struct CmBlob *certUri,
    uint32_t store, uint32_t status, uint32_t *stp)
{
    char pathBuf[CERT_MAX_PATH_LEN] = {0};
    struct CmMutableBlob path = { sizeof(pathBuf), (uint8_t *) pathBuf };
    struct CertFile certFile = { 0, 0 };
    int32_t ret = CertManagerFindCertFileNameByUri(context, certUri, store, false, &path);
    if (ret != CMR_OK) {
        /*
         * If the store type is not CM_SYSTEM_TRUSTED_STORE, ret is returned.
         * Otherwise, try to obtain the gm system ca path.
         */
        CM_LOG_E("CertManagerFindCertFileNameByUri error = %d", ret);
        if (store != CM_SYSTEM_TRUSTED_STORE) {
            return ret;
        }

        path.size = sizeof(pathBuf); /* clear path data and size */
        (void)memset_s(path.data, path.size, 0, path.size);
        ret = CertManagerFindCertFileNameByUri(context, certUri, store, true, &path);
        if (ret != CMR_OK) {
            CM_LOG_E("CertManagerFindCertFileNameByUri gm system ca error = %d", ret);
            return ret;
        }
    }
    certFile.path = &(CM_BLOB(&path));
    certFile.fileName = &(CM_BLOB(certUri));

    return CertManagerStatusFile(context, certFile, store, status, stp);
}

int32_t CmSetStatusEnable(const struct CmContext *context, struct CmMutableBlob *pathBlob,
    const struct CmBlob *certUri, uint32_t store)
{
    struct CertFile certFile = { 0, 0 };
    certFile.path = &(CM_BLOB(pathBlob));
    certFile.fileName = &(CM_BLOB(certUri));

    return CertManagerStatusFile(context, certFile, store, CERT_STATUS_ENANLED, NULL);
}

int32_t CmGetCertStatus(const struct CmContext *context, struct CertFileInfo *cFile,
    uint32_t store, uint32_t *status)
{
    struct CertFile certFile = { NULL, NULL };
    certFile.path = &(cFile->path);
    certFile.fileName = &(cFile->fileName);

    return CertManagerStatusFile(context, certFile, store, CERT_STATUS_INVALID, status);
}

int32_t CmGetCertConfigStatus(const char *fileName, uint32_t *status)
{
    if (fileName == NULL || status == NULL) {
        CM_LOG_E("Check param invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    struct CMUri uriObj = { 0 };
    int32_t ret = CertManagerUriDecode(&uriObj, fileName);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to decode uri, ret = %d", ret);
        return ret;
    }
    char confFilePath[CERT_MAX_PATH_LEN] = { 0 };
    if (sprintf_s(confFilePath, CERT_MAX_PATH_LEN, "%s/%s/%s/%s%s", CERT_BACKUP_CONFIG_ROOT_DIR, uriObj.user,
        uriObj.app, fileName, CERT_CONFIG_FILE_SUFFIX) < 0) {
        CM_LOG_E("Failed sprintf conf file path");
        (void)CertManagerFreeUri(&uriObj);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    (void)CertManagerFreeUri(&uriObj);

    ret = CmIsFileExist(NULL, confFilePath);
    if (ret != CM_SUCCESS) {
        CM_LOG_I("Cert config file not exist");
        *status = CERT_STATUS_DISABLED;
    } else {
        CM_LOG_I("Cert config file exist");
        *status = CERT_STATUS_ENABLED;
    }
    return CM_SUCCESS;
}
#ifdef __cplusplus
}
#endif
