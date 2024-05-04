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

#ifndef CERT_MANAGER_STORAGE_H
#define CERT_MANAGER_STORAGE_H

#include "cm_type.h"
#include "openssl/ossl_typ.h"
#ifdef __cplusplus
extern "C" {
#endif

#define CERT_DIR            "/data/service/el1/public/cert_manager_service/certificates"
#define CREDNTIAL_STORE     "/data/service/el1/public/cert_manager_service/certificates/credential/"
#define SYSTEM_CA_STORE     "/system/etc/security/certificates/"
#define USER_CA_STORE       "/data/service/el1/public/cert_manager_service/certificates/user/"
#define PRI_CREDNTIAL_STORE "/data/service/el1/public/cert_manager_service/certificates/priv_credential/"
#define SYS_CREDNTIAL_STORE "/data/service/el1/public/cert_manager_service/certificates/sys_credential/"

#define CERT_BACKUP_ROOT_DIR "/data/service/el1/public/cert_manager_service/certificates/user_open"
#define CERT_BACKUP_CONFIG_ROOT_DIR "/data/service/el1/public/cert_manager_service/certificates/user_config"
#define CERT_BACKUP_DIR_NAME "cacerts"
#define CERT_CONFIG_FILE_SUFFIX ".config"
#define CERT_BACKUP_FILENAME_FORMAT "%lx.%d"

int32_t GetRootPath(uint32_t store, char *rootPath, uint32_t pathLen);

int32_t ConstructUserIdPath(const struct CmContext *context, uint32_t store,
    char *userIdPath, uint32_t pathLen);

int32_t ConstructUidPath(const struct CmContext *context, uint32_t store,
    char *uidPath, uint32_t pathLen);

int32_t ConstructAuthListPath(const struct CmContext *context, uint32_t store,
    char *authListPath, uint32_t pathLen);

int32_t CmStorageGetBuf(const char *path, const char *fileName, struct CmBlob *storageBuf);

int32_t CmStorageGetAppCert(const struct CmContext *context, uint32_t store,
    const struct CmBlob *keyUri, struct CmBlob *certBlob);

int32_t CmGetCertFilePath(const struct CmContext *context, uint32_t store, struct CmMutableBlob *pathBlob);

/**
 * @brief Construct the absolute path to the {confRootDir}/{userId} directory
 *
 * @param[in] userId User ID
 * @param[out] confUserIdDir The buffer that holds the absolute path of the {confRootDir}/{userId} directory
 * @param[in] dirLen Maximum length of the confUserIdDir buffer
 * @return int32_t result
 * @retval 0 success
 * @retval <0 failure
 */
int32_t CmGetCertConfUserIdDir(uint32_t userId, char *confUserIdDir, uint32_t dirLen);

/**
 * @brief Construct the absolute path to the {confRootDir}/{userId}/{uid} directory
 *
 * @param[in] userId User ID
 * @param[in] uid User identifier
 * @param[out] certConfUidDir The buffer that holds the absolute path of the {confRootDir}/{userId}/{uid} directory
 * @param[in] dirLen Maximum length of the certConfUidDir buffer
 * @return int32_t result
 * @retval 0 success
 * @retval <0 failure
 */
int32_t CmGetCertConfUidDir(uint32_t userId, uint32_t uid, char *certConfUidDir, uint32_t dirLen);

/**
 * @brief Construct the absolute path of the configuration file corresponding to the CA certificate
 *
 * @param[in] userId User ID
 * @param[in] uid User identifier
 * @param[in] certUri User certificate URI
 * @param[out] confFilePath The buffer that holds the absolute path of the certificate configuration file
 * @param[in] confFilePathLen Maximum length of the confFilePath buffer
 * @return int32_t result
 * @retval 0 success
 * @retval <0 failure
 */
int32_t CmGetCertConfPath(uint32_t userId, uint32_t uid, const struct CmBlob *certUri, char *confFilePath,
                          uint32_t confFilePathLen);

/**
 * @brief Construct the absolute path of the directory where the CA certificate backup file is stored
 *
 * @param[in] userId User ID
 * @param[out] certBackupDir The buffer that holds the absolute path of the {backupRootDir}/{userId} directory
 * @param[in] certBackupDirLen Maximum length of the certBackupDir buffer
 * @return int32_t result
 * @retval 0 success
 * @retval <0 failure
 */
int32_t CmGetCertBackupDir(uint32_t userId, char *certBackupDir, uint32_t certBackupDirLen);

/**
 * @brief Get the CA certificate backup file name
 *
 * @param[in] userCertX509 Certificate data
 * @param[in] userId User ID
 * @param[out] certBackupFileName Buffer that stores the backup file name of the user CA certificate
 * @param[in] certBackupFileNameLen Maximum length of the certBackupFileName buffer
 * @return int32_t result
 * @retval 0 success
 * @retval <0 failure
 */
int32_t CmGetCertBackupFileName(const X509 *userCertX509, uint32_t userId, char *certBackupFileName,
                                uint32_t certBackupFileNameLen);

/**
 * @brief Construct the absolute path of the CA certificate backup file
 *
 * @param[in] userCertX509 Certificate data
 * @param[in] userId User ID
 * @param[out] backupFilePath Buffer that stores the absolute path of the certificate backup file
 * @param[in] backupFilePathLen Maximum length of the backupFilePath buffer
 * @return int32_t result
 * @retval 0 success
 * @retval <0 failure
 */
int32_t CmGetCertBackupFilePath(const X509 *userCertX509, uint32_t userId, char *backupFilePath,
                                uint32_t backupFilePathLen);

#ifdef __cplusplus
}
#endif

#endif /* CERT_MANAGER_STORAGE_H */

