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

#include <string.h>

#include "cj_cert_manager_ffi.h"

int32_t FfiCertManagerInstallAppCert(const struct CmBlob *appCert, const struct CmBlob *appCertPwd,
                                     const struct CmBlob *certAlias, const uint32_t store, struct CmBlob *keyUri)
{
    return CmInstallAppCert(appCert, appCertPwd, certAlias, store, keyUri);
}

int32_t FfiCertManagerUninstallAppCert(const struct CmBlob *keyUri, const uint32_t store)
{
    return CmUninstallAppCert(keyUri, store);
}

int32_t FfiCertManagerGetAppCert(const struct CmBlob *keyUri, const uint32_t store, struct CjCredential *retObj)
{
    struct Credential credential = {0};
    credential.credData.data = malloc(MAX_LEN_CERTIFICATE_CHAIN);
    if (credential.credData.data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    credential.credData.size = MAX_LEN_CERTIFICATE_CHAIN;
    const int32_t errCode = CmGetAppCert(keyUri, store, &credential);
    if (errCode == CM_SUCCESS) {
        // When success, resource will be released by caller.
        // Caller will ensure `retObj` is always not null.
        retObj->isExist = credential.isExist;
        retObj->type = strdup(credential.type);
        retObj->alias = strdup(credential.alias);
        retObj->keyUri = strdup(credential.keyUri);
        retObj->certNum = credential.certNum;
        retObj->keyNum = credential.keyNum;
        retObj->credData.data = credential.credData.data;
        retObj->credData.size = credential.credData.size;
    } else {
        // When failed, release resource
        free(credential.credData.data);
    }
    return errCode;
}

int32_t FfiCertManagerInit(const struct CmBlob *authUri, const struct CjSignatureSpec *spec, struct CmBlob *handle)
{
    // Caller will ensure `spec` is always not null.
    const struct CmSignatureSpec cmSpec = {
        .purpose = spec->purpose,
        .padding = spec->padding,
        .digest = spec->digest,
    };
    return CmInit(authUri, &cmSpec, handle);
}

int32_t FfiCertManagerUpdate(const struct CmBlob *handle, const struct CmBlob *inData)
{
    return CmUpdate(handle, inData);
}

int32_t FfiCertManagerFinish(const struct CmBlob *handle, const struct CmBlob *inData, struct CmBlob *outData)
{
    return CmFinish(handle, inData, outData);
}

int32_t FfiCertManagerAbort(const struct CmBlob *handle)
{
    return CmAbort(handle);
}

int32_t FfiCertManagerIsAuthorizedApp(const struct CmBlob *authUri)
{
    return CmIsAuthorizedApp(authUri);
}

int32_t FfiCertManagerGetUserCertList(const uint32_t store, uint32_t *retCount, struct CjCertAbstract **retObj)
{
    struct CertList certificateList = {0};
    uint32_t buffSize = MAX_COUNT_CERTIFICATE * sizeof(struct CertAbstract);
    certificateList.certAbstract = (struct CertAbstract *) malloc(buffSize);
    if (certificateList.certAbstract == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    certificateList.certsCount = MAX_COUNT_CERTIFICATE;

    const int32_t errCode = CmGetUserCertList(store, &certificateList);
    if (errCode == CM_SUCCESS) {
        // Caller will ensure `retObj` is always not null.
        *retObj = malloc(sizeof(struct CjCertAbstract) * certificateList.certsCount);
        if (*retObj == NULL) {
            free(certificateList.certAbstract);
            return CMR_ERROR_MALLOC_FAIL;
        }
        *retCount = certificateList.certsCount;
        for (int i = 0; i < certificateList.certsCount; ++i) {
            // ATTENTION: resource will be released by caller.
            (*retObj)->uri = strdup(certificateList.certAbstract[i].uri);
            (*retObj)->certAlias = strdup(certificateList.certAbstract[i].certAlias);
            (*retObj)[i].status = certificateList.certAbstract[i].status;
            (*retObj)->subjectName = strdup(certificateList.certAbstract[i].subjectName);
        }
    }
    free(certificateList.certAbstract);
    return errCode;
}

int32_t FfiCertManagerGetUserCertInfo(const struct CmBlob *certUri, const uint32_t store, struct CjCertInfo *retObj)
{
    struct CertInfo info = {0};
    info.certInfo.data = malloc(MAX_LEN_CERTIFICATE);
    if (info.certInfo.data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    info.certInfo.size = MAX_LEN_CERTIFICATE;

    const int32_t errCode = CmGetUserCertInfo(certUri, store, &info);
    if (errCode == CM_SUCCESS) {
        // ATTENTION: resource will be released by caller.
        // Caller will ensure `retObj` is always not null.
        retObj->uri = strdup(info.uri);
        retObj->certAlias = strdup(info.certAlias);
        retObj->status = info.status;
        retObj->issuerName = strdup(info.issuerName);
        retObj->subjectName = strdup(info.subjectName);
        retObj->serial = strdup(info.serial);
        retObj->notBefore = strdup(info.notBefore);
        retObj->notAfter = strdup(info.notAfter);
        retObj->fingerprintSha256 = strdup(info.fingerprintSha256);
        retObj->certInfo.data = info.certInfo.data;
        retObj->certInfo.size = info.certInfo.size;
    } else {
        // When failed, release resource
        free(info.certInfo.data);
    }
    return errCode;
}
