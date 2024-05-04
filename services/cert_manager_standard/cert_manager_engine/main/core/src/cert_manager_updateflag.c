/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "cert_manager_updateflag.h"

#include <dirent.h>
#include <libgen.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "cert_manager.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_mem.h"
#include "cert_manager_service.h"
#include "cert_manager_storage.h"
#include "cert_manager_uri.h"
#include "cm_log.h"
#include "cm_x509.h"
#include "securec.h"

#ifdef __cplusplus
extern "C" {
#endif

static const char UPDATE_FLAG_DIR_PATH[] = "/data/service/el1/public/cert_manager_service/certificates/user";
static const char UPDATE_FLAG_FILE_NAME[] = "update.flag";

enum UpdateFlagEnum {
    NEED_UPDATE = '0',
    ALREADY_UPDATE = '1',
};

/**
 * @brief Get the update flag
 *
 * @param[out] updateFlag Used to return the update flag
 * @return int32_t Get results
 * @retval 0 Success
 * @retval <0 Failure
 */
static int32_t GetUpdateFlag(uint8_t *updateFlag)
{
    uint8_t updateFlagTmp = false;

    if (updateFlag == NULL) {
        CM_LOG_E("input params is invaild");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    /* Read the update flag */
    uint32_t readSize =
        CmFileRead(UPDATE_FLAG_DIR_PATH, UPDATE_FLAG_FILE_NAME, 0, &updateFlagTmp, sizeof(updateFlagTmp));
    if (readSize == 0) {
        CM_LOG_D("Read updateFlag file failed, the updateFlag counts as false");
        *updateFlag = false;
    } else if (readSize == sizeof(updateFlagTmp)) {
        *updateFlag = updateFlagTmp;
    } else {
        CM_LOG_E("Failed read UpdateFlag");
        return CMR_ERROR_INVALID_OPERATION;
    }

    return CM_SUCCESS;
}

/**
 * @brief Set the update flag
 *
 * @param[out] updateFlag Set the update flag value
 * @return int32_t Set result
 * @retval 0 Success
 * @retval <0 Failure
 */
static int32_t SetUpdateFlag(uint8_t updateFlag)
{
    /* Create an update flag directory */
    if (CmMakeDir(UPDATE_FLAG_DIR_PATH) == CMR_ERROR_MAKE_DIR_FAIL) {
        CM_LOG_E("Failed to create UPDATE_FLAG_DIR_PATH");
        return CMR_ERROR_MAKE_DIR_FAIL;
    }

    /* Writes the update flag */
    int32_t ret = CmFileWrite(UPDATE_FLAG_DIR_PATH, UPDATE_FLAG_FILE_NAME, 0, &updateFlag, sizeof(updateFlag));
    if (ret != CMR_OK) {
        CM_LOG_E("Failed to write updateFlag");
    }
    return ret;
}

int32_t IsCertNeedBackup(uint32_t userId, uint32_t uid, const struct CmBlob *certUri, bool *needUpdate)
{
    int32_t ret = CM_SUCCESS;
    char configPath[CERT_MAX_PATH_LEN] = { 0 };

    if (needUpdate == NULL) {
        CM_LOG_E("input params is invaild");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    ret = CmGetCertConfPath(userId, uid, certUri, configPath, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Construct cert config configPath failed.");
        return CMR_ERROR_INVALID_OPERATION;
    }

    do {
        ret = CmIsFileExist(NULL, (const char *)configPath);
        if (ret != CM_SUCCESS) {
            if (ret != CMR_ERROR_NOT_EXIST) {
                CM_LOG_E("check cert config file return err code: %d.", ret);
            }
            /* The cert config file does not exist or cannot be determined, need to
             * backup cert */
            *needUpdate = true;
            break;
        }
        uint32_t size = 0;
        char backupPath[CERT_MAX_PATH_LEN] = { 0 };
        size = CmFileRead(NULL, configPath, 0, (uint8_t *)backupPath, CERT_MAX_PATH_LEN - 1);
        if (size == 0) {
            CM_LOG_E("read cert backup file path from configPath failed.");
            *needUpdate = true;
            break;
        }

        ret = CmIsFileExist(NULL, (const char *)backupPath);
        if (ret == CMR_OK) {
            *needUpdate = false;
            break;
        } else if (ret != CMR_ERROR_NOT_EXIST) {
            CM_LOG_E("check cert backup file return err code: %d.", ret);
        }
        *needUpdate = true;
    } while (0);

    return CM_SUCCESS;
}

int32_t CmReadCertData(uint32_t store, const struct CmContext *context, const struct CmBlob *certUri,
                       struct CmBlob *userCertData)
{
    int32_t ret = CM_SUCCESS;
    char uriStr[CERT_MAX_PATH_LEN] = { 0 };
    char uidPath[CERT_MAX_PATH_LEN] = { 0 };

    /* Construct certificate path */
    ret = ConstructUidPath(context, store, uidPath, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (snprintf_s(uriStr, CERT_MAX_PATH_LEN, CERT_MAX_PATH_LEN - 1, "%.*s", certUri->size, certUri->data) < 0) {
        CM_LOG_E("Construct cert uri string failed.");
        return CMR_ERROR_INVALID_OPERATION;
    }

    /* Reading certificate data */
    ret = CmStorageGetBuf(uidPath, uriStr, userCertData);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get certificate data");
        return CM_FAILURE;
    }

    return CM_SUCCESS;
}

static int32_t ConvertCertDataToPem(const struct CmBlob *userCertData, const X509 *userCertX509,
    struct CmBlob *userCertPemData, bool *userCertPemDataNeedFree)
{
    if (userCertData->data[0] != '-') {
        int32_t ret = CmX509ToPEM(userCertX509, userCertPemData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmX509ToPEM fail");
            return CM_FAILURE;
        }
        *userCertPemDataNeedFree = true;
    } else {
        userCertPemData->data = userCertData->data;
        userCertPemData->size = userCertData->size;
        *userCertPemDataNeedFree = false;
    }

    return CM_SUCCESS;
}

int32_t CmConstructContextFromUri(const char *certUri, struct CmContext *context)
{
    if ((certUri == NULL) || (context == NULL)) {
        CM_LOG_E("input params is invaild");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CMUri cmUri = { 0 };
    int32_t ret = CertManagerUriDecode(&cmUri, certUri);
    if ((ret != CM_SUCCESS)) {
        CM_LOG_E("Failed to decode struct CMUri from certUri, ret = %d", ret);
        return CMR_ERROR_INVALID_OPERATION;
    }

    do {
        if ((cmUri.user == NULL) || (cmUri.app == NULL) || (cmUri.object == NULL)) {
            CM_LOG_E("cmUri.user or cmUri.app or cmUri.object is NULL error");
            ret = CMR_ERROR_INVALID_ARGUMENT;
            break;
        }
        context->userId = (uint32_t)atoi(cmUri.user);
        context->uid = (uint32_t)atoi(cmUri.app);
        if (snprintf_s(context->packageName, sizeof(context->packageName), sizeof(context->packageName) - 1, "%s",
            cmUri.object) < 0) {
            CM_LOG_E("Failed to fill context->packageName");
            ret = CMR_ERROR_INVALID_ARGUMENT;
            break;
        }
    } while (0);

    (void)CertManagerFreeUri(&cmUri);

    return ret;
}

static int32_t BackupUserCert(const X509 *userCertX509, const struct CmBlob *userCert, const struct CmContext *context,
                              const struct CmBlob *certUri)
{
    char userCertConfigFilePath[CERT_MAX_PATH_LEN] = { 0 };
    char userCertBackupFilePath[CERT_MAX_PATH_LEN] = { 0 };

    int32_t ret = CmGetCertConfPath(context->userId, context->uid, certUri, userCertConfigFilePath, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmGetCertConfPath fail");
        return CM_FAILURE;
    }

    ret = CmRemoveBackupUserCert(context, certUri, userCertConfigFilePath);
    if (ret != CMR_OK) {
        CM_LOG_E("Remove user cert config and backup file failed, ret: %d", ret);
    }

    ret = CmGetCertBackupFilePath(userCertX509, context->userId, userCertBackupFilePath, CERT_MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmGetCertBackupFilePath fail");
        return CM_FAILURE;
    }
    ret = CmGenerateSaConf(userCertConfigFilePath, NULL, userCertBackupFilePath);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("GenerateSaConf: save CertBackupFilePath fail");
        return CM_FAILURE;
    }

    ret = CmStoreUserCert(NULL, userCert, userCertBackupFilePath);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("StoreUserCert fail");
        return CM_FAILURE;
    }

    return CM_SUCCESS;
}

int32_t CmBackupUserCert(const struct CmContext *context, const struct CmBlob *certUri, const struct CmBlob *certData)
{
    if ((context == NULL) || (CmCheckBlob(certUri) != CM_SUCCESS) || (CmCheckBlob(certData) != CM_SUCCESS)) {
        CM_LOG_E("Invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    X509 *userCertX509 = InitCertContext(certData->data, certData->size);
    if (userCertX509 == NULL) {
        CM_LOG_E("Parse X509 cert fail");
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }

    int32_t ret = CM_SUCCESS;
    struct CmBlob certPemData = { 0, NULL };
    bool certPemDataNeedFree = false;
    do {
        ret = ConvertCertDataToPem(certData, userCertX509, &certPemData, &certPemDataNeedFree);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("ConvertCertDataToPem fail");
            ret = CM_FAILURE;
            break;
        }

        ret = BackupUserCert(userCertX509, (const struct CmBlob *)&certPemData, context, certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("BackupUserCert fail");
            ret = CM_FAILURE;
            break;
        }
    } while (0);

    if (certPemDataNeedFree == true)
        CM_FREE_BLOB(certPemData);

    FreeCertContext(userCertX509);

    return ret;
}

static int32_t UpdateUserCert(uint32_t userId, uint32_t uid, const char *certPath)
{
    int32_t ret = CM_SUCCESS;
    char *uriStr = NULL;
    struct CmBlob certUri = { 0 };

    if (certPath == NULL) {
        CM_LOG_E("input params is invaild");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    uriStr = basename((char *)certPath);
    certUri.data = (uint8_t *)uriStr;
    certUri.size = strlen(uriStr);

    bool needUpdate = false;
    ret = IsCertNeedBackup(userId, uid, &certUri, &needUpdate);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Check cert is need update failed, ret = %d", ret);
        return CMR_ERROR_INVALID_OPERATION;
    } else if (needUpdate == false) {
        /* No need to update */
        return CM_SUCCESS;
    }

    struct CmContext context = { 0 };
    ret = CmConstructContextFromUri((const char *)uriStr, &context);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("ConstructContextFromUri failed, ret = %d", ret);
        return CM_FAILURE;
    }

    uint32_t store = CM_USER_TRUSTED_STORE;
    struct CmBlob certificateData = { 0, NULL };
    ret = CmReadCertData(store, &context, &certUri, &certificateData);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmReadCertData failed, ret = %d", ret);
        return CM_FAILURE;
    }

    ret = CmBackupUserCert(&context, &certUri, &certificateData);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("update user certUri failed, ret = %d", ret);
        ret = CM_FAILURE;
    }

    CM_FREE_BLOB(certificateData);

    return ret;
}

static int32_t UpdateUserCerts(uint32_t userId, const char *userIdPath)
{
    DIR *dir = opendir(userIdPath);
    if (dir == NULL) {
        CM_LOG_E("opendir userIdPath failed");
        return CM_FAILURE;
    }

    struct dirent *dire = NULL;
    /* Traverse the user/{userId} directory */
    while ((dire = readdir(dir)) != NULL) {
        if ((strcmp(dire->d_name, ".") == 0) || (strcmp(dire->d_name, "..") == 0)) {
            continue;
        }
        char uidPath[CERT_MAX_PATH_LEN] = { 0 };
        if (snprintf_s(uidPath, CERT_MAX_PATH_LEN, CERT_MAX_PATH_LEN - 1, "%s/%s", userIdPath, dire->d_name) < 0) {
            CM_LOG_E("Construct userId path failed");
            continue;
        }

        int32_t ret = 0;
        uint32_t fileCounts = 0;
        struct CmBlob fileNames[MAX_COUNT_CERTIFICATE] = { 0 };
        /* Gets all files under the uidPath */
        ret = CmUidLayerGetFileCountAndNames(uidPath, fileNames, sizeof(fileNames), &fileCounts);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Get file count and names from path of userId layer failed");
            continue;
        }

        /* Traverse all files under the uidPath */
        for (uint32_t i = 0; i < fileCounts; i++) {
            struct CmBlob *certFilePath = &fileNames[i];

            uint32_t uid = 0;
            /* Update certificate file */
            uid = (uint32_t)atoi(dire->d_name);
            ret = UpdateUserCert(userId, uid, (const char *)certFilePath->data);
            if (ret != CM_SUCCESS) {
                CM_LOG_E("Failed to update cert file for the certFilePath");
                continue;
            }
        }

        CmFreeFileNames(fileNames, fileCounts);
    };

    closedir(dir);

    return CM_SUCCESS;
}

static int32_t UpdateAllUserCerts(void)
{
    DIR *dir = NULL;
    struct dirent *dire = NULL;
    uint32_t userId = 0;
    char userIdPath[CERT_MAX_PATH_LEN] = { 0 };

    /* do nothing when dir is not exist */
    if (CmIsDirExist(USER_CA_STORE) != CMR_OK) {
        CM_LOG_D("Root dir is not exist");
        return CM_SUCCESS;
    }

    if ((dir = opendir(USER_CA_STORE)) == NULL) {
        CM_LOG_E("open USER_CA_STORE dir failed");
        return CM_FAILURE;
    }

    /* Traverse the user directory */
    while ((dire = readdir(dir)) != NULL) {
        if ((dire->d_type != DT_DIR) || (strcmp(dire->d_name, ".") == 0) || (strcmp(dire->d_name, "..") == 0)) {
            /* If it is not a directory or a special directory, skip it */
            continue;
        }

        if (snprintf_s(userIdPath, CERT_MAX_PATH_LEN, CERT_MAX_PATH_LEN - 1, "%s%s", USER_CA_STORE, dire->d_name) < 0) {
            CM_LOG_E("Construct userId path failed");
            continue;
        }

        /* Updates all certificates for the specified user */
        userId = (uint32_t)atoi(dire->d_name);
        int32_t ret = UpdateUserCerts(userId, userIdPath);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to update all certificates for the userIdPath");
            continue;
        }
    };

    closedir(dir);

    return CM_SUCCESS;
}

int32_t CmBackupAllSaUserCerts(void)
{
    int32_t ret = 0;
    uint8_t updateFlag = 0;

    /* Obtain the update flag */
    ret = GetUpdateFlag(&updateFlag);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("GetUpdateFlag failed");
        return ret;
    }

    if (updateFlag == ALREADY_UPDATE) {
        CM_LOG_D("updateFlag is ALREADY_UPDATE, so not need update");
        return CM_SUCCESS;
    }

    /* Update all certificate files */
    ret = UpdateAllUserCerts();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("UpdateAllUserCerts failed");
        return ret;
    }

    /* Set the Update flag */
    ret = SetUpdateFlag(ALREADY_UPDATE);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("GetUpdateFlag failed");
        return ret;
    }

    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif