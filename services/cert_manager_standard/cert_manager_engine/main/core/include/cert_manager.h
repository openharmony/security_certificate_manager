/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef CERT_MANAGER_H
#define CERT_MANAGER_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CM_ERROR(rc)  (int32_t) (rc)

/* Store it in the database. */
struct CertPropertyOri {
    const struct CmContext *context;
    struct CmBlob *uri;
    struct CmBlob *alias;
    struct CmBlob *subjectName;
    uint32_t store;
    enum CmAuthStorageLevel level;
};

int32_t CertManagerInitialize(void);

int32_t CertManagerFindCertFileNameByUri(const struct CmContext *context, const struct CmBlob *certUri,
    uint32_t store, bool isGmSysCert, struct CmMutableBlob *path);

int32_t CmRemoveAppCert(const struct CmContext *context, const struct CmBlob *keyUri,
    const uint32_t store);

int32_t CmRemoveAllAppCert(const struct CmContext *context);

int32_t CmServiceGetAppCertList(const struct CmContext *context, uint32_t store, struct CmBlob *fileNames,
    const uint32_t fileSize, uint32_t *fileCount);

int32_t CmServiceGetCallingAppCertList(const struct CmContext *context, uint32_t store, struct CmBlob *fileNames,
    const uint32_t fileSize, uint32_t *fileCount);

void CmFreeFileNames(struct CmBlob *fileNames, const uint32_t fileSize);

int32_t CmGetUri(const char *filePath, struct CmBlob *uriBlob);

int32_t CmCheckCertCount(const struct CmContext *context, const uint32_t store, const char *fileName);

int32_t CmWriteUserCert(const struct CmContext *context, struct CmMutableBlob *pathBlob,
    const struct CmBlob *userCert, const struct CmBlob *certAlias, struct CmBlob *certUri);

int32_t CmStoreUserCert(const char *path, const struct CmBlob *userCert, const char *userCertName);

int32_t CmGenerateSaConf(const char *userCertConfigPath, const char *userCertBakupDirPath, const char *userCertName);

int32_t CmRemoveUserCert(struct CmMutableBlob *pathBlob, const struct CmBlob *certUri);

int32_t CmRmUserCert(const char *usrCertConfigFilepath);

int32_t CmRmSaConf(const char *usrCertConfigFilepath);

int32_t CmRemoveAllUserCert(const struct CmContext *context, uint32_t store, const struct CmMutableBlob *pathList);

/**
 * @brief Delete the certificate backup file and configuration file
 *
 * If userCertConfigFilePath != NULL, the certificate is deleted based on userCertConfigFilePath. Otherwise, the
 * certificate is deleted based on the path of the certificate configuration file created in context and certUri.
 *
 * @param context Context information
 * @param certUri Certificate uri
 * @param userCertConfigFilePath The certificate configuration file path
 * @return int32_t result
 * @retval 0 success
 * @retval <0 failure
 */
int32_t CmRemoveBackupUserCert(const struct CmContext *context, const struct CmBlob *certUri,
                               const char *userCertConfigFilePath);

int32_t CmGetDisplayNameByURI(const struct CmBlob *uri, const char *object, struct CmBlob *displayName);

int32_t RdbInsertCertProperty(const struct CertPropertyOri *propertyOri);

int32_t GetObjNameFromCertData(const struct CmBlob *certData, const struct CmBlob *certAlias,
    struct CmBlob *objectName);

int32_t GetCertOrCredCount(const struct CmContext *context, const uint32_t store, uint32_t *certCount);

#ifdef __cplusplus
}
#endif

#endif