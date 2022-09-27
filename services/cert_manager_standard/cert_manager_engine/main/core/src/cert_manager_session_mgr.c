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

#include "cert_manager_session_mgr.h"
#include "cert_manager_mem.h"
#include "cm_log.h"

#include <pthread.h>
#include <stdio.h>

#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"

#include "securec.h"

#define MAX_OPERATIONS_COUNT 15

static struct DoubleList g_sessionList = { &g_sessionList, &g_sessionList };
static uint32_t g_sessionCount = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static void DeleteHuksInitInfo(const struct CmBlob *handle)
{
    struct HksParamSet *paramSet = NULL;
    if (HksInitParamSet(&paramSet) != HKS_SUCCESS) {
        return;
    }

    (void)HksAbort((const struct HksBlob *)handle, paramSet);
    HksFreeParamSet(&paramSet);
}

static void FreeSessionNode(struct CmSessionNode **node)
{
    if ((node == NULL) || (*node == NULL)) {
        return;
    }

    CM_FREE_PTR((*node)->handle.data);
    CM_FREE_PTR((*node)->info.uri.data);
    CM_FREE_PTR(*node);
}

/* Need to lock before calling RemoveAndFreeSessionNode */
static void RemoveAndFreeSessionNode(struct CmSessionNode **sessionNode)
{
    if ((sessionNode == NULL) || (*sessionNode == NULL)) {
        return;
    }

    CmRemoveNodeFromList(&(*sessionNode)->listHead);
    FreeSessionNode(sessionNode);
}

/* Need to lock before calling DeleteFirstAbortableSession */
static int32_t DeleteFirstAbortableSession(void)
{
    struct CmSessionNode *sessionNode = NULL;

    CM_DLIST_ITER(sessionNode, &g_sessionList) {
        if (sessionNode->abortable) {
            DeleteHuksInitInfo(&(sessionNode->handle));
            RemoveAndFreeSessionNode(&sessionNode);
            --g_sessionCount;
            CM_LOG_I("delete session count: %u", g_sessionCount);
            return CM_SUCCESS;
        }
    }

    return CMR_ERROR_NOT_FOUND;
}

static int32_t AddSessionNode(struct CmSessionNode *sessionNode)
{
    pthread_mutex_lock(&g_lock);

    if (g_sessionCount >= MAX_OPERATIONS_COUNT) {
        CM_LOG_I("maximum number of sessions reached: delete oldest session.");
        if (DeleteFirstAbortableSession() != CM_SUCCESS) {
            pthread_mutex_unlock(&g_lock);
            CM_LOG_E("not found abortable session");
            return CMR_ERROR_SESSION_REACHED_LIMIT;
        }
    }

    CmAddNodeAtListTail(&g_sessionList, &sessionNode->listHead);
    ++g_sessionCount;
    CM_LOG_I("add session count:%u", g_sessionCount);
    pthread_mutex_unlock(&g_lock);

    return HKS_SUCCESS;
}

static int32_t ConstructSessionInfo(const struct CmSessionNodeInfo *info, struct CmSessionNode *node)
{
    uint32_t size = info->uri.size;
    uint8_t *data = (uint8_t *)CMMalloc(size);
    if (data == NULL) {
        CM_LOG_E("malloc uri data failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(data, size, info->uri.data, size);

    node->info.userId = info->userId;
    node->info.uid = info->uid;
    node->info.uri.data = data;
    node->info.uri.size = size;
    return CM_SUCCESS;
}

static int32_t ConstructHandle(const struct CmBlob *handle, struct CmSessionNode *node)
{
    uint32_t size = handle->size;
    uint8_t *data = (uint8_t *)CMMalloc(size);
    if (data == NULL) {
        CM_LOG_E("malloc handle data failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(data, size, handle->data, size);

    node->handle.data = data;
    node->handle.size = size;
    return CM_SUCCESS;
}

int32_t CmCreateSession(const struct CmSessionNodeInfo *info, const struct CmBlob *handle, bool abortable)
{
    struct CmSessionNode *node = (struct CmSessionNode *)CMMalloc(sizeof(struct CmSessionNode));
    if (node == NULL) {
        CM_LOG_E("malloc session node failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(node, sizeof(struct CmSessionNode), 0, sizeof(struct CmSessionNode));

    int32_t ret;
    do {
        ret = ConstructSessionInfo(info, node);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("construct session info failed, ret = %d", ret);
            break;
        }

        ret = ConstructHandle(handle, node);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("construct handle failed, ret = %d", ret);
            break;
        }

        node->abortable = abortable;

        ret = AddSessionNode(node);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("add session node failed, ret = %d", ret);
            break;
        }
    } while (0);
    if (ret != CM_SUCCESS) {
        FreeSessionNode(&node);
    }

    return ret;
}

static bool IsSameBlob(const struct CmBlob *blob1, const struct CmBlob *blob2)
{
    if (blob1->size != blob2->size) {
        return false;
    }
    if (memcmp(blob1->data, blob2->data, blob1->size) != 0) {
        return false;
    }
    return true;
}

static bool IsSameCaller(const struct CmSessionNodeInfo *info, const struct CmSessionNode *node)
{
    return (info->uid == node->info.uid) && (info->userId == node->info.userId);
}

struct CmSessionNode *CmQuerySession(const struct CmSessionNodeInfo *info, const struct CmBlob *handle)
{
    struct CmSessionNode *node = NULL;
    pthread_mutex_lock(&g_lock);
    CM_DLIST_ITER(node, &g_sessionList) {
        if (IsSameBlob(handle, &(node->handle)) && IsSameCaller(info, node)) {
            pthread_mutex_unlock(&g_lock);
            return node;
        }
    }
    pthread_mutex_unlock(&g_lock);

    return NULL;
}

void CmDeleteSession(const struct CmBlob *handle)
{
    struct CmSessionNode *node = NULL;
    pthread_mutex_lock(&g_lock);
    CM_DLIST_ITER(node, &g_sessionList) {
        if (IsSameBlob(handle, &(node->handle))) {
            RemoveAndFreeSessionNode(&node);
            --g_sessionCount;
            CM_LOG_I("delete session count: %u", g_sessionCount);
            pthread_mutex_unlock(&g_lock);
            return;
        }
    }
    pthread_mutex_unlock(&g_lock);
}

static bool IsNeedDelete(enum CmSessionDeleteType deleteType, const struct CmSessionNodeInfo *info,
    const struct CmSessionNode *node)
{
    switch (deleteType) {
        case DELETE_SESSION_BY_USERID:
            return info->userId == node->info.userId;
        case DELETE_SESSION_BY_UID:
            return IsSameCaller(info, node);
        case DELETE_SESSION_BY_URI:
            return IsSameBlob(&(info->uri), &(node->info.uri));
        case DELETE_SESSION_BY_ALL:
            return IsSameCaller(info, node) && IsSameBlob(&(info->uri), &(node->info.uri));
        default:
            return false;
    }
}

static void DeleteSessionNode(enum CmSessionDeleteType deleteType, const struct CmSessionNodeInfo *info,
    struct CmSessionNode **nodeSession)
{
    struct CmSessionNode *node = *nodeSession;
    if (IsNeedDelete(deleteType, info, node)) {
        DeleteHuksInitInfo(&(node->handle));
        RemoveAndFreeSessionNode(nodeSession);
        --g_sessionCount;
        CM_LOG_I("delete session count = %u", g_sessionCount);
    }
}

void CmDeleteSessionByNodeInfo(enum CmSessionDeleteType deleteType, const struct CmSessionNodeInfo *info)
{
    struct CmSessionNode *node = NULL;

    pthread_mutex_lock(&g_lock);
    CM_DLIST_SAFT_ITER(node, &g_sessionList) {
        if (node != NULL) {
            DeleteSessionNode(deleteType, info, &node);
        }
    }
    pthread_mutex_unlock(&g_lock);
}

