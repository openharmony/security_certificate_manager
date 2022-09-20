/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "cm_type.h"
#include "cm_log.h"
#include "cert_manager_status.h"
#include <dirent.h>
#include "hks_type.h"
#include "hks_api.h"
#include "hks_param.h"
#include "cert_manager_file_operator.h"
#include "securec.h"
#include "cert_manager.h"
#include "cm_event_process.h"

int32_t CmTraversalDirActionCredential(const char *filePath, const char *fileName)
{
    CM_LOG_I("CmTraversalDirActionCredential: fileName is:%s", fileName);
    int32_t ret = remove(filePath);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("App cert delete faild, ret: %d", ret);
        return ret;
    }

    struct CmBlob keyUri = { strlen(fileName) + 1, (uint8_t *)fileName };

    /* ignore the return of HksDeleteKey */
    ret = HksDeleteKey(&HKS_BLOB(&keyUri), NULL);
    if (ret != HKS_SUCCESS && ret != HKS_ERROR_NOT_EXIST) {
        CM_LOG_I("App key delete failed ret: %d", ret);
    }

    return CM_SUCCESS;
}

int32_t CmTraversalDirActionUserCa(struct CmContext *context, const char *filePath, const char *fileName,
    const uint32_t store)
{
    uint32_t status = CERT_STATUS_ENABLED;
    struct CmBlob certUri = { strlen(fileName), (uint8_t *)fileName };
    int32_t ret = remove(filePath);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("User cert delete faild, ret: %d", ret);
        return ret;
    }

    CM_LOG_I("CmTraversalDirActionUserCa: fileName is:%s", fileName);
    CM_LOG_I("CmTraversalDirActionUserCa: uid is %u userId is %u", context->uid, context->userId);

    ret = SetcertStatus(context, &certUri, store, status, NULL);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("User set status faild, ret: %d", ret);
        return ret;
    }

    return CM_SUCCESS;
}

int32_t CmTraversalDirAction(struct CmContext *context, const char *filePath,
    const char *fileName, const uint32_t store)
{
    int32_t ret = CM_SUCCESS;

    switch (store) {
        case CM_CREDENTIAL_STORE :
        case CM_PRI_CREDENTIAL_STORE :
            ret = CmTraversalDirActionCredential(filePath, fileName);
            break;
        case CM_USER_TRUSTED_STORE :
            ret = CmTraversalDirActionUserCa(context, filePath, fileName, store);
            break;
        default:
            break;
    }
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmTraversalDirAction failed store:%u", store);
    }

    return CM_SUCCESS;
}

int32_t CmTraversalUidLayerDir(struct CmContext *context, const char *path, const uint32_t store)
{
    int32_t ret = CM_SUCCESS;
    char uidPath[CM_MAX_FILE_NAME_LEN] = {0};
    /* do nothing when dir is not exist */
    if (CmIsDirExist(path) != CMR_OK) {
        CM_LOG_I("Dir is not exist:%s", path);
        return CM_SUCCESS;
    }
    DIR *dir = opendir(path);
    if (dir  == NULL) {
        CM_LOG_E("open dir failed");
        return CMR_ERROR_OPEN_FILE_FAIL;
    }
    struct dirent *dire = readdir(dir);
    while (dire != NULL) {
        if (strncpy_s(uidPath, sizeof(uidPath), path, strlen(path)) != EOK) {
            closedir(dir);
            return CMR_ERROR_INVALID_OPERATION;
        }

        if (uidPath[strlen(uidPath) - 1] != '/') {
            if (strncat_s(uidPath, sizeof(uidPath), "/", strlen("/")) != EOK) {
                closedir(dir);
                return CMR_ERROR_INVALID_OPERATION;
            }
        }

        if (strncat_s(uidPath, sizeof(uidPath), dire->d_name, strlen(dire->d_name)) != EOK) {
            closedir(dir);
            return CMR_ERROR_INVALID_OPERATION;
        }

        if ((strcmp("..", dire->d_name) != 0) && (strcmp(".", dire->d_name) != 0)) {
            ret = CmTraversalDirAction(context, uidPath, dire->d_name, store);
            if (ret != CM_SUCCESS) {
                return ret;
            }
        }
        dire = readdir(dir);
    }
    closedir(dir);
    ret = remove(path);
    return ret;
}

int32_t CmTraversalUserIdLayerDir(struct CmContext *context, const char *path, const uint32_t store)
{
    uint32_t uid;
    bool isUserDeleteEvent = (context->uid == INVALID_VALUE);
    int32_t ret = CM_SUCCESS;
    char userIdPath[CM_MAX_FILE_NAME_LEN] = {0};
    /* do nothing when dir is not exist */
    if (CmIsDirExist(path) != CMR_OK) {
        CM_LOG_I("UserId dir is not exist:%s", path);
        return CM_SUCCESS;
    }
    DIR *dir = opendir(path);
    if (dir  == NULL) {
        CM_LOG_E("Open userId dir failed");
        return CMR_ERROR_OPEN_FILE_FAIL;
    }
    struct dirent *dire = readdir(dir);
    while (dire != NULL) {
        if (strncpy_s(userIdPath, sizeof(userIdPath), path, strlen(path)) != EOK) {
            closedir(dir);
            return CMR_ERROR_INVALID_OPERATION;
        }

        if (userIdPath[strlen(userIdPath) - 1] != '/') {
            if (strncat_s(userIdPath, sizeof(userIdPath), "/", strlen("/")) != EOK) {
                closedir(dir);
                return CMR_ERROR_INVALID_OPERATION;
            }
        }

        if (strncat_s(userIdPath, sizeof(userIdPath), dire->d_name, strlen(dire->d_name)) != EOK) {
            closedir(dir);
            return CMR_ERROR_INVALID_OPERATION;
        }

        if (dire->d_type == DT_DIR && (strcmp("..", dire->d_name) != 0) && (strcmp(".", dire->d_name) != 0)) {
            uid = (uint32_t)atoi(dire->d_name);
            CM_LOG_I("CmTraversalUserIdLayerDir userId:%u, uid:%u", context->userId, uid);
            /* user delete event */
            if (isUserDeleteEvent) {
                context->uid = uid;
                ret = CmTraversalUidLayerDir(context, userIdPath, store);
            /* package delete event */
            } else if (uid == context->uid) {
                ret = CmTraversalUidLayerDir(context, userIdPath, store);
            }
        } else if (dire->d_type != DT_DIR) {
            (void)remove(userIdPath);
        }
        dire = readdir(dir);
    }
    closedir(dir);
    /* delete userId directory only in user remove event */
    if (isUserDeleteEvent) {
        ret = remove(path);
    }

    return ret;
}

int32_t CmTraversalDir(struct CmContext *context, const char *path, const uint32_t store)
{
    int32_t ret = CM_SUCCESS;
    char deletePath[CM_MAX_FILE_NAME_LEN] = { 0 };
    /* do nothing when dir is not exist */
    if (CmIsDirExist(path) != CMR_OK) {
        CM_LOG_I("Root dir is not exist:%s", path);
        return CM_SUCCESS;
    }
    DIR *dir = opendir(path);
    if (dir  == NULL) {
        CM_LOG_E("open dir failed");
        return CMR_ERROR_OPEN_FILE_FAIL;
    }
    struct dirent *dire = readdir(dir);
    while (dire != NULL) {
        if (strncpy_s(deletePath, sizeof(deletePath), path, strlen(path)) != EOK) {
            closedir(dir);
            return CMR_ERROR_INVALID_OPERATION;
        }

        if (deletePath[strlen(deletePath) - 1] != '/') {
            if (strncat_s(deletePath, sizeof(deletePath), "/", strlen("/")) != EOK) {
                closedir(dir);
                return CMR_ERROR_INVALID_OPERATION;
            }
        }

        if (strncat_s(deletePath, sizeof(deletePath), dire->d_name, strlen(dire->d_name)) != EOK) {
            closedir(dir);
            return CMR_ERROR_INVALID_OPERATION;
        }

        if (dire->d_type == DT_DIR && (strcmp("..", dire->d_name) != 0) && (strcmp(".", dire->d_name) != 0) &&
            ((uint32_t)atoi(dire->d_name) == context->userId)) {
            ret = CmTraversalUserIdLayerDir(context, deletePath, store);
        } else if (dire->d_type != DT_DIR) {
            (void)remove(deletePath);
        }
        dire = readdir(dir);
    }
    closedir(dir);

    return ret;
}

int32_t CmDeleteProcessInfo(struct CmContext *context)
{
    int32_t ret = CM_SUCCESS;
    /* Delete user ca */
    ret = CmTraversalDir(context, USER_CA_STORE, CM_USER_TRUSTED_STORE);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmDeleteUserCa faild");
    }

    /* Delete private credentail */
    ret = CmTraversalDir(context, APP_CA_STORE, CM_PRI_CREDENTIAL_STORE);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmDeletePrivateCredential faild");
    }

    /* Delete public credentail */
    ret = CmTraversalDir(context, CREDNTIAL_STORE, CM_CREDENTIAL_STORE);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmDeletePublicCredential faild");
    }
    return ret;
}
