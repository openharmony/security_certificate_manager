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

#include "cert_manager_type.h"
#include "cm_type.h"

#define CERT_MAX_PATH_LEN   256
#define CERT_DIR            "/data/service/el1/public/cert_manager_service/certificates"

#define CREDNTIAL_STORE     "/data/service/el1/public/cert_manager_service/certificates/credential/"
#define SYSTEM_CA_STORE     "/system/etc/security/certificates/"
#define USER_CA_STORE       "/data/service/el1/public/cert_manager_service/certificates/user/"
#define APP_CA_STORE        "/data/service/el1/public/cert_manager_service/certificates/priv_credential/"

#define CM_ERROR(rc)  (int32_t) (rc)

#define CREDENTIAL_STORE  "./certificates/credential/"

#ifdef __cplusplus
extern "C" {
#endif

void CmCertificateListFree(struct CmMutableBlob *certListData, uint32_t certListSize);

/**
 * Initialize CertManager
*/
int32_t CertManagerInitialize(void);

/**
 * List trusted certificates in the indicated trusted store or stores.
 * Memory will be allocated and should be released by CertManagerFreeTrustedCertificatesList.
 * Paras:
 * [IN] context - The context of the call.
 * [OUT] certificateList - The certificate list retrieved.
 * [IN] store - The trusted store where the certificate is to be listed.
 * Returns -CMR_OK on success.
*/
int32_t CertManagerListTrustedCertificates(
    const struct CmContext *context,
    struct CmBlob *certificateList,
    uint32_t store, struct CertBlob *certBlob, uint32_t *status);

/**
 * Get subjetc name form certificate. Memory should be allocate by the caller.
 * If the data is in subjectName is NULL, The resulting size indicated the size of the buffer required.
 * Paras:
 * [IN] context - The context of the call.
 * [IN] certificateList - The resulting certificate list.
 * [IN] store - The trusted store to be listed.
 * [OUT] subjectName - The subject name to be matched.
 * Returns -CMR_OK on success.
*/
int32_t CertManagerListCertificatesBySubjectName(
    const struct CmContext *context,
    struct CmBlob *certificateList,
    uint32_t store,
    const struct CmBlob *subjectName);

/**
 * List trusted certificates in the indicated trusted store or stores.
 * Memory will be allocated and should be released by CertManagerFreeTrustedCertificatesList.
 * Paras:
 * [IN] context - The context of the call.
 * [IN] certificate - The certificate for which the status is to set.
 * [IN] store - The trusted store where the certificate is to be considered.
 * [IN] status - The new status of the certificate.Must be one of CERT_STATUS* values.
 * Returns -CMR_OK on success.
 */
int32_t CertManagerSetCertificatesStatus(
    const struct CmContext *context,
    const struct CmBlob *certificate,
    uint32_t store,
    uint32_t status);

int32_t CertManagerFindCertFileName(
    const struct CmContext *context, const struct CmBlob *certificate, uint32_t store,
    struct CmMutableBlob *path, struct CmMutableBlob *fileName);

int32_t CertManagerFindCertFileNameByUri(
    const struct CmContext *context, const struct CmBlob *certUri, uint32_t store, struct CmMutableBlob *path);

int32_t CmGetCertificatesByUri(const struct CmContext *context, struct CmBlob *certificateList,
    uint32_t store, const struct CmBlob *nameDigest, uint32_t *status);

/**
 * Remove a trusted certificate from the indicated trusted store.
 * Params:
 * [IN] context - The context of the call.
 * [IN] certificate - The certificate data to be removed.
 * [IN] store - The trusted store where the certificate is to be removd.
 * Returns CMR_OK on success.
 */
int32_t CmRemoveAppCert(
    const struct CmContext *context,
    const struct CmBlob *certUri,
    uint32_t store);

/**
 * Import a raw key pair.
 * Pfarams:
 * [IN] context - The context of the call.
 * [IN] keypair - The raw key pair.
 * [IN] properties - Key properties for the new key pair
 * [IN] name - Name of the key pair.
 *             The length of the name cannot exceed CM_NAME_MAX_LEN.
 * Returns CMR_OK on success.
 */
int32_t CertManagerImportKeyPair(
    const struct CMApp *caller,
    const struct CmBlob *keypair,
    const struct CMKeyProperties *properties,
    const char *name);

int32_t GetFilePath(const struct CmContext *context, uint32_t store, char *pathPtr,
    char *suffix, uint32_t *suffixLen);

int32_t CmRemoveAllAppCert(const struct CmContext *context);

int32_t BuildObjUri(char **objUri, const char *name, uint32_t type, const struct CMApp *app);

int32_t CmFreeCaFileNames(struct CmMutableBlob *fileNames);

int32_t CmServiceGetAppCertList(const struct CmContext *context, uint32_t store, struct CmBlob *fileNames,
    const uint32_t fileSize, uint32_t *fileCount);

int32_t CmGetFilePath(const struct CmContext *context, uint32_t store, struct CmMutableBlob *pathBlob);

void CmFreeFileNameUri(struct CmBlob *uri, uint32_t size);

void CmFreeFileNames(struct CmBlob *fileNames, const uint32_t fileSize);

int32_t CmGetUri(const char *filePath, struct CmBlob *uriBlob);

int32_t CmWriteUserCert(const struct CmContext *context, struct CmMutableBlob *pathBlob,
    const struct CmBlob *userCert, const struct CmBlob *certAlias, struct CmBlob *certUri);

int32_t NameHashFromUri(const char *fName, struct CmMutableBlob *nameDigest);

int32_t CmRemoveUserCert(struct CmMutableBlob *pathBlob, const struct CmBlob *certUri);

int32_t CmRemoveAllUserCert(const struct CmContext *context, uint32_t store, const struct CmMutableBlob *certPathList);

int32_t BuildUserUri(char **userUri, const char *aliasName, uint32_t type, const struct CmContext *context);
#ifdef __cplusplus
}
#endif

#endif