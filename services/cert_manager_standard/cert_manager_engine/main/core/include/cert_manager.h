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

#define CERT_DIR            "/data/service/el1/public/cert_manager_service/certificates"
#define CREDNTIAL_STORE     "/data/service/el1/public/cert_manager_service/certificates/credential/"
#define SYSTEM_CA_STORE     "/system/etc/security/certificates/"
#define USER_CA_STORE       "/data/service/el1/public/cert_manager_service/certificates/user/"
#define APP_CA_STORE        "/data/service/el1/public/cert_manager_service/certificates/priv_credential/"
#define CREDENTIAL_STORE    "./certificates/credential/"

int32_t CertManagerInitialize(void);

int32_t CertManagerFindCertFileNameByUri(
    const struct CmContext *context, const struct CmBlob *certUri, uint32_t store, struct CmMutableBlob *path);

int32_t CmRemoveAppCert(const struct CmContext *context, const struct CmBlob *keyUri,
    const uint32_t store);

int32_t CmRemoveAllAppCert(const struct CmContext *context);

int32_t CmServiceGetAppCertList(const struct CmContext *context, uint32_t store, struct CmBlob *fileNames,
    const uint32_t fileSize, uint32_t *fileCount);

void CmFreeFileNames(struct CmBlob *fileNames, const uint32_t fileSize);

int32_t CmGetUri(const char *filePath, struct CmBlob *uriBlob);

int32_t CmWriteUserCert(const struct CmContext *context, struct CmMutableBlob *pathBlob,
    const struct CmBlob *userCert, const struct CmBlob *certAlias, struct CmBlob *certUri);

int32_t CmRemoveUserCert(struct CmMutableBlob *pathBlob, const struct CmBlob *certUri);

int32_t CmRemoveAllUserCert(const struct CmContext *context, uint32_t store, const struct CmMutableBlob *pathList);

#ifdef __cplusplus
}
#endif

#endif