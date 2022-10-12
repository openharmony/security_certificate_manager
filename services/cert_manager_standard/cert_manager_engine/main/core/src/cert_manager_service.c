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

#include "cert_manager_service.h"

#include "securec.h"

#include "cert_manager_auth_mgr.h"
#include "cert_manager_key_operation.h"
#include "cert_manager_mem.h"
#include "cert_manager_permission_check.h"
#include "cert_manager_storage.h"
#include "cm_log.h"
#include "cm_type.h"

#include "cert_manager_query.h"
#include "cm_ipc_serialization.h"
#include "cert_manager_status.h"
#include "cm_x509.h"
#include "cert_manager.h"
#include "cert_manager_uri.h"
#include "cm_event_process.h"

static int32_t CheckUri(const struct CmBlob *keyUri)
{
    if (CmCheckBlob(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid uri");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    for (uint32_t i = 1; i < keyUri->size; ++i) { /* from index 1 has '\0' */
        if (keyUri->data[i] == 0) {
            return CM_SUCCESS;
        }
    }
    return CMR_ERROR_INVALID_ARGUMENT;
}

static int32_t GetPublicAppCert(const struct CmContext *context, uint32_t store,
    struct CmBlob *keyUri, struct CmBlob *certBlob)
{
    struct CmBlob commonUri = { 0, NULL };
    int32_t ret = CmCheckAndGetCommonUri(context, keyUri, &commonUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("check and get common uri when get app cert failed, ret = %d", ret);
        return ret;
    }

    do {
        ret = CmStorageGetAppCert(context, store, &commonUri, certBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get app cert from storage failed, ret = %d", ret);
            break;
        }

        /* remove authinfo from uri */
        if (keyUri->size < commonUri.size) {
            CM_LOG_E("keyUri size[%u] smaller than commonUri size[%u]", keyUri->size, commonUri.size);
            ret = CMR_ERROR_INVALID_ARGUMENT;
            break;
        }
        if (memcpy_s(keyUri->data, keyUri->size, commonUri.data, commonUri.size) != EOK) {
            CM_LOG_E("copy keyUri failed");
            ret = CMR_ERROR_INVALID_OPERATION;
            break;
        }
        keyUri->size = commonUri.size;
    } while (0);

    CM_FREE_PTR(commonUri.data);
    return ret;
}

static int32_t GetPrivateAppCert(const struct CmContext *context, uint32_t store,
    const struct CmBlob *keyUri, struct CmBlob *certBlob)
{
    int32_t ret = CmCheckCallerIsProducer(context, keyUri);
    if (ret != CM_SUCCESS) {
        /* caller is not producer, check wether has ACCESS_CERT_MANAGER_INTERNAL permission */
        if (!CmHasPrivilegedPermission()) {
            CM_LOG_E("not caller and FA, permission check failed");
            return CMR_ERROR_PERMISSION_DENIED;
        }
    }

    ret = CmStorageGetAppCert(context, store, keyUri, certBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get app cert from storage failed, ret = %d", ret);
    }

    return ret;
}

int32_t CmServiceGetAppCert(const struct CmContext *context, uint32_t store,
    struct CmBlob *keyUri, struct CmBlob *certBlob)
{
    if (CheckUri(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    if (store == CM_CREDENTIAL_STORE) {
        return GetPublicAppCert(context, store, keyUri, certBlob);
    } else if (store == CM_PRI_CREDENTIAL_STORE) {
        return GetPrivateAppCert(context, store, keyUri, certBlob);
    }
    return CMR_ERROR_INVALID_ARGUMENT;
}

int32_t CmServiceGrantAppCertificate(const struct CmContext *context, const struct CmBlob *keyUri,
    uint32_t appUid, struct CmBlob *authUri)
{
    if (CheckUri(keyUri) != CM_SUCCESS || CmCheckBlob(authUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasPrivilegedPermission() || !CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    return CmAuthGrantAppCertificate(context, keyUri, appUid, authUri);
}

int32_t CmServiceGetAuthorizedAppList(const struct CmContext *context, const struct CmBlob *keyUri,
    struct CmAppUidList *appUidList)
{
    if (CheckUri(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasPrivilegedPermission() || !CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    return CmAuthGetAuthorizedAppList(context, keyUri, appUidList);
}

int32_t CmServiceIsAuthorizedApp(const struct CmContext *context, const struct CmBlob *authUri)
{
    if (CheckUri(authUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    return CmAuthIsAuthorizedApp(context, authUri);
}

int32_t CmServiceRemoveGrantedApp(const struct CmContext *context, const struct CmBlob *keyUri, uint32_t appUid)
{
    if (CheckUri(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasPrivilegedPermission() || !CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    return CmAuthRemoveGrantedApp(context, keyUri, appUid);
}

int32_t CmServiceInit(const struct CmContext *context, const struct CmBlob *authUri,
    const struct CmSignatureSpec *spec, struct CmBlob *handle)
{
    if (CheckUri(authUri) != CM_SUCCESS || CmCheckBlob(handle) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    struct CmBlob commonUri = { 0, NULL };
    int32_t ret = CmCheckAndGetCommonUri(context, authUri, &commonUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("check and get common uri failed, ret = %d", ret);
        return ret;
    }

    ret = CmKeyOpInit(context, &commonUri, spec, handle);
    CM_FREE_PTR(commonUri.data);
    return ret;
}

int32_t CmServiceUpdate(const struct CmContext *context, const struct CmBlob *handle,
    const struct CmBlob *inData)
{
    if (CmCheckBlob(handle) != CM_SUCCESS || CmCheckBlob(inData) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    return CmKeyOpProcess(SIGN_VERIFY_CMD_UPDATE, context, handle, inData, NULL);
}

int32_t CmServiceFinish(const struct CmContext *context, const struct CmBlob *handle,
    const struct CmBlob *inData, struct CmBlob *outData)
{
    if (CmCheckBlob(handle) != CM_SUCCESS) { /* inData.data and outData.data can be null */
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    return CmKeyOpProcess(SIGN_VERIFY_CMD_FINISH, context, handle, inData, outData);
}

int32_t CmServiceAbort(const struct CmContext *context, const struct CmBlob *handle)
{
    if (CmCheckBlob(handle) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    return CmKeyOpProcess(SIGN_VERIFY_CMD_ABORT, context, handle, NULL, NULL);
}

int32_t CmServiceGetCertList(const struct CmContext *context, uint32_t store, struct CmMutableBlob *certFileList)
{
    int32_t ret = CM_SUCCESS;
    struct CmMutableBlob uidPathList = { 0, NULL }; /* uid path list */

    do {
        /* get all uid path*/
        ret = CmGetCertPathList(context, store, &uidPathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertPathList fail, ret = %d", ret);
            break;
        }

        /* create certFilelist(path + name) from every uid */
        ret = CreateCertFileList(&uidPathList, certFileList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CreateCertFileList fail, ret = %d", ret);
            break;
        }
    } while (0);
    if (uidPathList.data != NULL) {
        CmFreeCertPaths(&uidPathList);
    }
    return ret;
}

static int32_t CmGetCertListPack(const struct CertBlob *certBlob, uint32_t *status, uint32_t certCount,
    struct CmBlob *certificateList)
{
    uint32_t offset = 0;
    uint32_t buffSize = sizeof(uint32_t) + (sizeof(uint32_t) + MAX_LEN_SUBJECT_NAME + sizeof(uint32_t) +
        sizeof(uint32_t) + MAX_LEN_URI + sizeof(uint32_t) + MAX_LEN_CERT_ALIAS) * MAX_COUNT_CERTIFICATE;
    if (certificateList->size < buffSize) {
        CM_LOG_E("outdata size too small");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    certificateList->size = buffSize;

    int32_t ret = CopyUint32ToBuffer(certCount, certificateList, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy cert count failed");
        return ret;
    }

    for (uint32_t i = 0; i < certCount; i++) {
        ret = CopyBlobToBuffer(&(certBlob->subjectName[i]), certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate subject failed");
            return ret;
        }
        ret = CopyUint32ToBuffer(status[i], certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate status failed");
            return ret;
        }
        ret = CopyBlobToBuffer(&(certBlob->uri[i]), certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate uri failed");
            return ret;
        }
        ret = CopyBlobToBuffer(&(certBlob->certAlias[i]), certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate certAlias failed");
            return ret;
        }
    }
    return ret;
}

int32_t CmServiceGetCertListPack(const struct CmContext *context, uint32_t store,
    const struct CmMutableBlob *certFileList, struct CmBlob *certificateList)
{
    uint32_t status[MAX_COUNT_CERTIFICATE] = {0};
    struct CertBlob certBlob;
    (void)memset_s(&certBlob, sizeof(struct CertBlob), 0, sizeof(struct CertBlob));
    int32_t ret = CmGetCertListInfo(context, store, certFileList, &certBlob, status);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmGetCertListInfo fail");
        CmFreeCertBlob(&certBlob);
        return ret;
    }

    ret = CmGetCertListPack(&certBlob, status, certFileList->size, certificateList);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmGetCertListPack fail");
        CmFreeCertBlob(&certBlob);
        return ret;
    }

    CmFreeCertBlob(&certBlob);
    return ret;
}

int32_t CmServiceGetCertInfo(const struct CmContext *context, const struct CmBlob *certUri,
    uint32_t store, struct CmBlob *certificateData, uint32_t *status)
{
    if (CmCheckBlob(certUri) != CM_SUCCESS || CheckUri(certUri) != CM_SUCCESS) {
        CM_LOG_E("input params invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CM_SUCCESS;
    struct CmMutableBlob certFileList = { 0, NULL };
    do {
        ret = CmServiceGetCertList(context, store, &certFileList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertList failed, ret = %d", ret);
            break;
        }

        uint32_t matchIndex = CmGetMatchedCertIndex(&certFileList, certUri);
        if ((matchIndex == MAX_COUNT_CERTIFICATE) || (matchIndex == certFileList.size)) {
            CM_LOG_I("certFile of certUri don't matched");
            ret = CM_SUCCESS;
            break;
        }

        struct CertFilePath *certFilePath = (struct CertFilePath *)certFileList.data;
        ret = CmGetCertStatus(context, &certFilePath[matchIndex], store, status); /* status */
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get cert status");
            ret = CM_FAILURE;
            break;
        }

        ret = CmGetCertData((char *)certFilePath[matchIndex].fileName.data,
            (char *)certFilePath[matchIndex].path.data, certificateData); /* cert data */
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get cert data");
            ret = CM_FAILURE;
            break;
        }
    } while (0);
    if (certFileList.data != NULL) {
        CmFreeCertFiles(&certFileList);
    }
    return ret;
}

int32_t CmServiceGetCertInfoPack(const struct CmBlob *certificateData, uint32_t status,
    const struct CmBlob *certUri, struct CmBlob *certificateInfo)
{
    if (certificateInfo->size == 0) {
        CM_LOG_I("cert file is not exist");
        return CM_SUCCESS;
    }

    int32_t ret = CM_SUCCESS;
    uint32_t offset = 0;
    uint32_t buffSize = sizeof(uint32_t) + MAX_LEN_CERTIFICATE + sizeof(uint32_t) +
        MAX_LEN_CERT_ALIAS + sizeof(uint32_t);
    if (certificateInfo->size < buffSize) {
        CM_LOG_E("outdata size too small");
        return CMR_ERROR_MALLOC_FAIL;
    }
    certificateInfo->size = buffSize;

    ret = CopyBlobToBuffer(certificateData, certificateInfo, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy cert data failed");
        return ret;
    }

    ret = CopyUint32ToBuffer(status, certificateInfo, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy cert status failed");
        return ret;
    }

    struct CmBlob certAlias;
    certAlias.size = MAX_LEN_CERT_ALIAS;
    certAlias.data = (uint8_t *)CMMalloc(MAX_LEN_CERT_ALIAS);
    if (certAlias.data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(certAlias.data, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS);
    ret = CmGetCertAlias((char *)certUri->data, &(certAlias));
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get cert certAlias");
        CM_FREE_BLOB(certAlias);
        return CM_FAILURE;
    }
    ret = CopyBlobToBuffer(&certAlias, certificateInfo, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy cert data failed");
        CM_FREE_BLOB(certAlias);
        return ret;
    }
    CM_FREE_BLOB(certAlias);
    return ret;
}

int32_t CmInstallUserCert(const struct CmContext *context, const struct CmBlob *userCert,
    const struct CmBlob *certAlias, struct CmBlob *certUri)
{
    if ((CmCheckBlob(userCert) != CM_SUCCESS) || (CmCheckBlob(certAlias) != CM_SUCCESS)) {
        CM_LOG_E("input params invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CM_SUCCESS;
    uint8_t pathBuf[CERT_MAX_PATH_LEN] = {0};
    struct CmMutableBlob pathBlob = { sizeof(pathBuf), pathBuf };
    uint32_t store = CM_USER_TRUSTED_STORE;
    do {
        X509 *userCertX509 = InitCertContext(userCert->data, userCert->size);
        if (userCertX509 == NULL) {
            CM_LOG_E("Parse X509 cert fail");
            ret = CMR_ERROR_INVALID_CERT_FORMAT;
            break;
        }
        FreeCertContext(userCertX509);

        ret = CmGetCertFilePath(context, store, &pathBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed obtain path for store:%d path:%s", store, pathBuf);
            break;
        }

        if (CheckUri(certAlias) != CM_SUCCESS) {
            CM_LOG_E("certalias no end");
            ret = CMR_ERROR_INVALID_ARGUMENT;
            break;
        }
        ret = CmWriteUserCert(context, &pathBlob, userCert, certAlias, certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerWriteUserCert fail");
            ret = CM_FAILURE;
            break;
        }

        ret = CmSetStatusEnable(context, &pathBlob, certUri, store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerUpdateStatusFile fail");
            ret = CM_FAILURE;
            break;
        }
    } while (0);
    return ret;
}

static int32_t CmComparisonCallerIdWithUri(const struct CmContext *context,
    const struct CmBlob *certUri)
{
    uint32_t userId;
    uint32_t uid;
    struct CMUri uriObj;
    (void)memset_s(&uriObj, sizeof(uriObj), 0, sizeof(uriObj));
    if (CheckUri(certUri) != CM_SUCCESS) {
        CM_LOG_E("cert uri no end");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CertManagerUriDecode(&uriObj, (char *)certUri->data);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uri decode failed, ret = %d", ret);
        return ret;
    }

    if (uriObj.user == NULL) {
        CM_LOG_E("uri user invalid");
        (void)CertManagerFreeUri(&uriObj);
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    userId = atoi(uriObj.user);

    if (uriObj.app == NULL) {
        CM_LOG_E("uri app invalid");
        (void)CertManagerFreeUri(&uriObj);
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    uid = atoi(uriObj.app);
    if ((context->userId == userId) && (context->uid == uid)) {
        ret = CM_SUCCESS;
    } else {
        ret =  CMR_ERROR_INVALID_ARGUMENT;
    }

    (void)CertManagerFreeUri(&uriObj);
    return ret;
}


int32_t CmUninstallUserCert(const struct CmContext *context, const struct CmBlob *certUri)
{
    if (CmCheckBlob(certUri) != CM_SUCCESS || CheckUri(certUri) != CM_SUCCESS) {
        CM_LOG_E("input params invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CM_SUCCESS;
    ASSERT_ARGS(context && certUri && certUri->data && certUri->size);
    uint8_t pathBuf[CERT_MAX_PATH_LEN] = {0};
    struct CmMutableBlob pathBlob = { sizeof(pathBuf), pathBuf };
    uint32_t store = CM_USER_TRUSTED_STORE;

    do {
        ret = CmComparisonCallerIdWithUri(context, certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CallerId don't match uri, ret = %d", ret);
            break;
        }

        ret = CmGetCertFilePath(context, store, &pathBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed obtain path for store %d", store);
            break;
        }

        ret = CmRemoveUserCert(&pathBlob, certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("RemoveUserCertFile fail, ret = %d", ret);
            break;
        }

        ret = CmSetStatusEnable(context, &pathBlob, certUri, store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UpdateStatusFile fail, ret = %d", ret);
            break;
        }
    } while (0);

    return ret;
}

int32_t CmUninstallAllUserCert(const struct CmContext *context)
{
    int32_t ret = CM_SUCCESS;
    uint32_t store = CM_USER_TRUSTED_STORE;
    struct CmMutableBlob certPathList = { 0, NULL };

    do {
        ret = CmGetCertPathList(context, store, &certPathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertPathList fail, ret = %d", ret);
            break;
        }

        ret = CmRemoveAllUserCert(context, store, &certPathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("RemoveAllUserCert fail, ret = %d", ret);
            break;
        }
    } while (0);
    if (certPathList.data != NULL) {
        CmFreeCertPaths(&certPathList);
    }
    return ret;
}

int32_t CmServiceSetCertStatus(const struct CmContext *context, const struct CmBlob *certUri,
    uint32_t store, uint32_t status)
{
    if (CmCheckBlob(certUri) != CM_SUCCESS || CheckUri(certUri) != CM_SUCCESS) {
        CM_LOG_E("input params invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return SetcertStatus(context, certUri, store, status, NULL);
}

