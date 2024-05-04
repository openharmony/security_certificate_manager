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

#include "cm_event_process.h"

#include <dirent.h>
#include <sys/stat.h>

#include "securec.h"

#include "cert_manager.h"
#include "cert_manager_auth_mgr.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_key_operation.h"
#include "cert_manager_session_mgr.h"
#include "cert_manager_status.h"
#include "cert_manager_storage.h"
#include "cm_log.h"
#include "cm_type.h"

static void DeleteAuth(const struct CmContext *context, const char *fileName, bool isDeleteByUid)
{
    CM_LOG_D("isDeleteByUid:%d", isDeleteByUid);
    struct CmBlob keyUri = { strlen(fileName) + 1, (uint8_t *)fileName };

    int32_t ret;
    if (isDeleteByUid) {
        ret = CmAuthDeleteAuthInfoByUid(context->userId, context->uid, &keyUri);
    } else {
        ret = CmAuthDeleteAuthInfoByUserId(context->userId, &keyUri);
    }
    if (ret != CM_SUCCESS) {
        CM_LOG_E("delete auth info failed ret: %d", ret); /* only record logs */
    }
    return;
}

static int32_t CmTraversalDirActionCredential(const char *filePath, const char *fileName)
{
    int32_t ret = remove(filePath);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("App cert delete faild, ret: %d", ret);
        return ret;
    }

    struct CmBlob keyUri = { strlen(fileName) + 1, (uint8_t *)fileName };
    ret = CmKeyOpDeleteKey(&keyUri);
    if (ret != CM_SUCCESS) { /* ignore the return of delete key */
        CM_LOG_E("App key delete failed ret: %d", ret);
    }

    return CM_SUCCESS;
}

static int32_t CmTraversalDirActionUserCa(const struct CmContext *context, const char *filePath, const char *fileName,
    const uint32_t store)
{
    int32_t ret = remove(filePath);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("User cert delete faild, ret: %d", ret);
        return ret;
    }

    struct CmBlob certUri = { strlen(fileName) + 1, (uint8_t *)fileName }; /* include '\0' at end. */
    struct CmMutableBlob pathBlob = { strlen(filePath) + 1, (uint8_t *)filePath };
    ret = CmSetStatusEnable(context, &pathBlob, &certUri, store);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("User set status faild, ret: %d", ret);
        return ret;
    }

    return CM_SUCCESS;
}

static int32_t CmTraversalDirAction(const struct CmContext *context, const char *filePath,
    const char *fileName, const uint32_t store)
{
    int32_t ret = CM_SUCCESS;

    switch (store) {
        case CM_CREDENTIAL_STORE :
            DeleteAuth(context, fileName, false);
            __attribute__((fallthrough));
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

static int32_t GetNextLayerPath(const char *path, const char *name, char *outPath, uint32_t outPathLen)
{
    if (strncpy_s(outPath, outPathLen, path, strlen(path)) != EOK) {
        return CMR_ERROR_INVALID_OPERATION;
    }
    if (outPath[strlen(outPath) - 1] != '/') {
        if (strncat_s(outPath, outPathLen, "/", strlen("/")) != EOK) {
            return CMR_ERROR_INVALID_OPERATION;
        }
    }
    if (strncat_s(outPath, outPathLen, name, strlen(name)) != EOK) {
        return CMR_ERROR_INVALID_OPERATION;
    }
    return CM_SUCCESS;
}

static int32_t RemoveDir(const char *dirPath)
{
    struct stat fileStat;
    int32_t ret = stat(dirPath, &fileStat);
    if (ret != 0) {
        return CMR_ERROR_INVALID_OPERATION;
    }

    if (!S_ISDIR(fileStat.st_mode)) {
        return CMR_ERROR_INVALID_OPERATION;
    }

    DIR *dir = opendir(dirPath);
    if (dir  == NULL) {
        return CMR_ERROR_INVALID_OPERATION;
    }

    struct dirent *dire = readdir(dir);
    while (dire != NULL) {
        if (dire->d_type == DT_REG) { /* only care about files. */
            ret = CmFileRemove(dirPath, dire->d_name);
            if (ret != CM_SUCCESS) { /* Continue to delete remaining files */
                CM_LOG_E("remove file failed when remove authlist files, ret = %d.", ret);
            }
        }
        dire = readdir(dir);
    }
    (void)closedir(dir);
    (void)remove(dirPath);
    return CM_SUCCESS;
}

static void RemoveAuthListDir(const char *path, const uint32_t store, bool isSameUid)
{
    if (!isSameUid || (store != CM_CREDENTIAL_STORE)) {
        return;
    }

    char authListPath[CM_MAX_FILE_NAME_LEN] = {0};
    char name[] = "authlist";
    int32_t ret = GetNextLayerPath(path, name, authListPath, sizeof(authListPath));
    if (ret != CM_SUCCESS) {
        return;
    }

    RemoveDir(authListPath);
}

static void TraversalUidLayerDir(const struct CmContext *context, const char *uidPath, const char *direName,
    const uint32_t store, bool isSameUid)
{
    if (!isSameUid) {
        if (store == CM_CREDENTIAL_STORE) { /* remove deleted uid from authlist */
            DeleteAuth(context, direName, true);
        }
    } else {
        (void)CmTraversalDirAction(context, uidPath, direName, store);
    }
}

static int32_t CmTraversalUidLayerDir(const struct CmContext *context, const char *path,
    const uint32_t store, bool isSameUid)
{
    int32_t ret = CM_SUCCESS;
    /* do nothing when dir is not exist */
    if (CmIsDirExist(path) != CMR_OK) {
        CM_LOG_D("Dir is not exist");
        return CM_SUCCESS;
    }

    DIR *dir = opendir(path);
    if (dir  == NULL) {
        CM_LOG_E("open dir failed");
        return CMR_ERROR_OPEN_FILE_FAIL;
    }

    struct dirent *dire = readdir(dir);
    while (dire != NULL) {
        char uidPath[CM_MAX_FILE_NAME_LEN] = {0};
        if (GetNextLayerPath(path, dire->d_name, uidPath, sizeof(uidPath)) != CM_SUCCESS) {
            closedir(dir);
            return CMR_ERROR_INVALID_OPERATION;
        }

        if ((strcmp("..", dire->d_name) != 0) && (strcmp(".", dire->d_name) != 0) && (dire->d_type == DT_REG)) {
            TraversalUidLayerDir(context, uidPath, dire->d_name, store, isSameUid);
        }
        dire = readdir(dir);
    }
    closedir(dir);

    /* remove authList Path */
    RemoveAuthListDir(path, store, isSameUid);

    if (isSameUid) {
        ret = remove(path);
    }
    return ret;
}

static int32_t TraversalUserIdLayerDir(const struct CmContext *context, const char *userIdPath, const char *direName,
    const uint32_t store, bool isUserDeleteEvent)
{
    uint32_t uid = (uint32_t)atoi(direName);
    CM_LOG_D("CmTraversalUserIdLayerDir userId:%u, uid:%u", context->userId, uid);

    int32_t ret = CM_SUCCESS;
    if (isUserDeleteEvent) { /* user delete event */
        struct CmContext userContext = { context->userId, uid, {0} };
        ret = CmTraversalUidLayerDir(&userContext, userIdPath, store, true);
    } else { /* package delete event */
        if (uid == context->uid) {
            ret = CmTraversalUidLayerDir(context, userIdPath, store, true);
        } else if (store == CM_CREDENTIAL_STORE) {
            ret = CmTraversalUidLayerDir(context, userIdPath, store, false);
        } else {
            /* do nothing */
        }
    }
    return ret;
}

static int32_t CmTraversalUserIdLayerDir(const struct CmContext *context, const char *path, const uint32_t store)
{
    bool isUserDeleteEvent = (context->uid == INVALID_VALUE);
    int32_t ret = CM_SUCCESS;

    /* do nothing when dir is not exist */
    if (CmIsDirExist(path) != CMR_OK) {
        CM_LOG_D("UserId dir is not exist");
        return CM_SUCCESS;
    }

    DIR *dir = opendir(path);
    if (dir  == NULL) {
        CM_LOG_E("Open userId dir failed");
        return CMR_ERROR_OPEN_FILE_FAIL;
    }

    struct dirent *dire = readdir(dir);
    while (dire != NULL) {
        char userIdPath[CM_MAX_FILE_NAME_LEN] = {0};
        if (GetNextLayerPath(path, dire->d_name, userIdPath, sizeof(userIdPath)) != CM_SUCCESS) {
            closedir(dir);
            return CMR_ERROR_INVALID_OPERATION;
        }

        if (dire->d_type == DT_DIR && (strcmp("..", dire->d_name) != 0) && (strcmp(".", dire->d_name) != 0)) {
            (void)TraversalUserIdLayerDir(context, userIdPath, dire->d_name, store, isUserDeleteEvent);
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

static int32_t CmTraversalDir(const struct CmContext *context, const char *path, const uint32_t store)
{
    int32_t ret = CM_SUCCESS;
    /* do nothing when dir is not exist */
    if (CmIsDirExist(path) != CMR_OK) {
        CM_LOG_D("Root dir is not exist");
        return CM_SUCCESS;
    }

    DIR *dir = opendir(path);
    if (dir  == NULL) {
        CM_LOG_E("open dir failed");
        return CMR_ERROR_OPEN_FILE_FAIL;
    }

    struct dirent *dire = readdir(dir);
    while (dire != NULL) {
        char deletePath[CM_MAX_FILE_NAME_LEN] = { 0 };
        if (GetNextLayerPath(path, dire->d_name, deletePath, sizeof(deletePath)) != CM_SUCCESS) {
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

static int32_t CmTraversalBackupUidDir(const char *certConfigUidDirPath)
{
    if (certConfigUidDirPath == NULL) {
        CM_LOG_E("input params is invaild");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t fileCounts = 0;
    struct CmBlob fileNames[MAX_COUNT_CERTIFICATE] = { 0 };
    /* Gets all files under the certConfigUidDirPath */
    int32_t ret = CmUidLayerGetFileCountAndNames(certConfigUidDirPath, fileNames, sizeof(fileNames), &fileCounts);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get file count and names for the certConfigUidDirPath, ret = %d", ret);
        return ret;
    }

    for (uint32_t i = 0; i < fileCounts; i++) {
        struct CmBlob *certConfigFilePath = &fileNames[i];

        /* Delete user cert backup and config file */
        ret = CmRemoveBackupUserCert(NULL, NULL, (const char *)certConfigFilePath->data);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmRemoveBackupUserCert failed");
            continue;
        }
    }

    CmFreeFileNames(fileNames, fileCounts);

    return CM_SUCCESS;
}

static int32_t CmTraversalBackupUserIdDir(const char *certConfigUserIdDirPath)
{
    if (certConfigUserIdDirPath == NULL) {
        CM_LOG_E("input params is invaild");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    DIR *dir = opendir(certConfigUserIdDirPath);
    if (dir == NULL) {
        CM_LOG_E("opendir certConfigUserIdDirPath failed");
        return CM_FAILURE;
    }

    int32_t ret = CM_SUCCESS;
    struct dirent *dire = NULL;
    /* Traverse the {configRootDir}/{userid} directory */
    while ((dire = readdir(dir)) != NULL) {
        if ((strcmp(dire->d_name, ".") == 0) || (strcmp(dire->d_name, "..") == 0)) {
            continue;
        }
        char certConfigUidDirPath[CERT_MAX_PATH_LEN] = { 0 };
        if (snprintf_s(certConfigUidDirPath, CERT_MAX_PATH_LEN, CERT_MAX_PATH_LEN - 1, "%s/%s", certConfigUserIdDirPath,
                       dire->d_name) < 0) {
            CM_LOG_E("Construct certConfigUidDirPath failed");
            continue;
        }

        ret = CmTraversalBackupUidDir(certConfigUidDirPath);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmTraversalBackupUidDir failed, ret = %d", ret);
            continue;
        }

        /* Delete user cert config {configRootDir}/{userid}/{uid} directory */
        ret = CmDirRemove(certConfigUidDirPath);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Remove user certConfigUidDirPath fail, ret = %d", ret);
            continue;
        }
    };

    closedir(dir);
    return CM_SUCCESS;
}

static int32_t CmTraversalBackupUserCert(uint32_t userId)
{
    int32_t ret = CM_SUCCESS;
    char certConfigUserIdDirPath[CERT_MAX_PATH_LEN] = { 0 };
    ret = CmGetCertConfUserIdDir(userId, certConfigUserIdDirPath, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Construct certConfigUserIdDirPath(userId: %u) failed", userId);
        return CM_FAILURE;
    }

    ret = CmTraversalBackupUserIdDir(certConfigUserIdDirPath);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmTraversalBackupUserIdDir failed, ret = %d", ret);
        return CM_FAILURE;
    }

    /* Delete {configRootDir}/{userid} directory */
    ret = CmDirRemove(certConfigUserIdDirPath);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Remove user certConfigUserIdDirPath fail, ret = %d", ret);
        return CMR_ERROR_REMOVE_FILE_FAIL;
    }

    /* Delete {backupRootDir}/{userid} directory */
    char certBackupUserIdDirPath[CERT_MAX_PATH_LEN] = { 0 };
    ret = CmGetCertBackupDir(userId, certBackupUserIdDirPath, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Construct certBackupUserIdDirPath failed");
        return CM_FAILURE;
    }
    ret = CmDirRemove(certBackupUserIdDirPath);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Remove user certBackupUserIdDirPath fail, ret = %d", ret);
        return CMR_ERROR_REMOVE_FILE_FAIL;
    }

    return CM_SUCCESS;
}

static void RemoveSessionInfo(const struct CmContext *context)
{
    bool isUserDeleteEvent = (context->uid == INVALID_VALUE);

    if (isUserDeleteEvent) {
        /* remove session node by user id */
        struct CmSessionNodeInfo info = { context->userId, 0, { 0, NULL } };
        CmDeleteSessionByNodeInfo(DELETE_SESSION_BY_USERID, &info);
    } else {
        /* remove session node by uid */
        struct CmSessionNodeInfo info = { context->userId, context->uid, { 0, NULL } };
        CmDeleteSessionByNodeInfo(DELETE_SESSION_BY_UID, &info);
    }
}

int32_t CmDeleteProcessInfo(const struct CmContext *context)
{
    RemoveSessionInfo(context);

    int32_t ret = CM_SUCCESS;
    if (context->uid == INVALID_VALUE) { // user delete event
        /* Delete user ca */
        ret = CmTraversalDir(context, USER_CA_STORE, CM_USER_TRUSTED_STORE);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmDeleteUserCa faild");
        }

        /* Delete user ca backup and config */
        ret = CmTraversalBackupUserCert(context->userId);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Delete user ca backup and config file failed");
        }
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

    /* Delete system credentail*/
    ret = CmTraversalDir(context, SYS_CREDNTIAL_STORE, CM_SYS_CREDENTIAL_STORE);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmDeletePublicCredential faild");
    }

    return ret;
}
