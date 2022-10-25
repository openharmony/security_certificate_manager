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

#ifdef __cplusplus
extern "C" {
#endif

#define CERT_DIR            "/data/service/el1/public/cert_manager_service/certificates"
#define CREDNTIAL_STORE     "/data/service/el1/public/cert_manager_service/certificates/credential/"
#define SYSTEM_CA_STORE     "/system/etc/security/certificates/"
#define USER_CA_STORE       "/data/service/el1/public/cert_manager_service/certificates/user/"
#define PRI_CREDNTIAL_STORE "/data/service/el1/public/cert_manager_service/certificates/priv_credential/"

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

#ifdef __cplusplus
}
#endif

#endif /* CERT_MANAGER_STORAGE_H */

