/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CJ_CERT_MANAGER_FFI_H
#define CJ_CERT_MANAGER_FFI_H

#include "cert_manager_api.h"

struct CjCredential {
    uint32_t isExist;
    char *type;
    char *alias;
    char *keyUri;
    uint32_t certNum;
    uint32_t keyNum;
    struct CmBlob credData;
};

struct CjSignatureSpec {
    uint32_t purpose;
    uint32_t padding;
    uint32_t digest;
};

struct CjCertAbstract {
    char *uri;
    char *certAlias;
    bool status;
    char *subjectName;
};

struct CjCertInfo {
    char *uri;
    char *certAlias;
    bool status;
    char *issuerName;
    char *subjectName;
    char *serial;
    char *notBefore;
    char *notAfter;
    char *fingerprintSha256;
    struct CmBlob certInfo;
};

int32_t FfiCertManagerInstallAppCert(const struct CmBlob *appCert, const struct CmBlob *appCertPwd,
                                     const struct CmBlob *certAlias, const uint32_t store, struct CmBlob *keyUri);
int32_t FfiCertManagerUninstallAppCert(const struct CmBlob *keyUri, const uint32_t store);
int32_t FfiCertManagerGetAppCert(const struct CmBlob *keyUri, const uint32_t store, struct CjCredential *retObj);
int32_t FfiCertManagerInit(const struct CmBlob *authUri, const struct CjSignatureSpec *spec, struct CmBlob *handle);
int32_t FfiCertManagerUpdate(const struct CmBlob *handle, const struct CmBlob *inData);
int32_t FfiCertManagerFinish(const struct CmBlob *handle, const struct CmBlob *inData, struct CmBlob *outData);
int32_t FfiCertManagerAbort(const struct CmBlob *handle);
int32_t FfiCertManagerIsAuthorizedApp(const struct CmBlob *authUri);
int32_t FfiCertManagerGetUserCertList(const uint32_t store, uint32_t *retCount, struct CjCertAbstract **retObj);
int32_t FfiCertManagerGetUserCertInfo(const struct CmBlob *certUri, const uint32_t store, struct CjCertInfo *retObj);


#endif //CJ_CERT_MANAGER_FFI_H
