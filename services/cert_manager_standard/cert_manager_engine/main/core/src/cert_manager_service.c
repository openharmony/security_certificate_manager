/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>

#include "securec.h"

#include "cert_manager.h"
#include "cert_manager_app_cert_process.h"
#include "cert_manager_auth_mgr.h"
#include "cert_manager_check.h"
#include "cert_manager_key_operation.h"
#include "cert_manager_mem.h"
#include "cert_manager_permission_check.h"
#include "cert_manager_query.h"
#include "cert_manager_status.h"
#include "cert_manager_storage.h"
#include "cert_manager_uri.h"
#include "cm_event_process.h"
#include "cm_cert_property_rdb.h"
#include "cm_log.h"
#include "cm_type.h"
#include "cm_x509.h"
#include "cm_util.h"

#include "cert_manager_file_operator.h"
#include "cert_manager_updateflag.h"
#define MAX_PATH_LEN 256

static int32_t CheckPermission(bool needPriPermission, bool needCommonPermission)
{
    if (needPriPermission) {
        if (!CmHasPrivilegedPermission()) {
            CM_LOG_E("caller lacks pri permission");
            return CMR_ERROR_PERMISSION_DENIED;
        }
        if (!CmIsSystemApp()) {
            CM_LOG_E("caller is not system app");
            return CMR_ERROR_NOT_SYSTEMP_APP;
        }
    }

    if (needCommonPermission) {
        if (!CmHasCommonPermission()) {
            CM_LOG_E("caller lacks common permission");
            return CMR_ERROR_PERMISSION_DENIED;
        }
    }

    return CM_SUCCESS;
}

int32_t CmServicInstallAppCert(struct CmContext *context, const struct CmAppCertParam *certParam, struct CmBlob *keyUri)
{
    int32_t ret = CmServiceInstallAppCertCheck(certParam, context);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("service intall app cert check params failed, ret = %d", ret);
        return ret;
    }

    ret = CmInstallAppCertPro(context, certParam, keyUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmInstallAppCert fail, ret = %d", ret);
        return ret;
    }
    return ret;
}

static int32_t GetPublicAppCert(const struct CmContext *context, uint32_t store,
    struct CmBlob *keyUri, struct CmBlob *certBlob)
{
    struct CmBlob commonUri = { 0, NULL };
    int32_t ret = CmCheckAndGetCommonUri(context, store, keyUri, &commonUri);
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
            ret = CMR_ERROR_BUFFER_TOO_SMALL;
            break;
        }
        if (memcpy_s(keyUri->data, keyUri->size, commonUri.data, commonUri.size) != EOK) {
            CM_LOG_E("copy keyUri failed");
            ret = CMR_ERROR_MEM_OPERATION_COPY;
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
        ret = CheckPermission(true, false);
        if (ret != CM_SUCCESS) {
            return ret;
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
    if (store == CM_CREDENTIAL_STORE) {
        return GetPublicAppCert(context, store, keyUri, certBlob);
    } else if (store == CM_PRI_CREDENTIAL_STORE) {
        return GetPrivateAppCert(context, store, keyUri, certBlob);
    } else if (store == CM_SYS_CREDENTIAL_STORE) {
        return CmStorageGetAppCert(context, store, keyUri, certBlob);
    }
    return CMR_ERROR_INVALID_ARGUMENT;
}

int32_t CmServiceGrantAppCertificate(const struct CmContext *context, const struct CmBlob *keyUri,
    uint32_t appUid, struct CmBlob *authUri)
{
    if (CheckUri(keyUri) != CM_SUCCESS || CmCheckBlob(authUri) != CM_SUCCESS || context == NULL) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    int32_t ret = CheckPermission(true, true);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    return CmAuthGrantAppCertificate(context, keyUri, appUid, authUri);
}

int32_t CmServiceGetAuthorizedAppList(const struct CmContext *context, const struct CmBlob *keyUri,
    struct CmAppUidList *appUidList)
{
    if (CheckUri(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    int32_t ret = CheckPermission(true, true);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    return CmAuthGetAuthorizedAppList(context, keyUri, appUidList);
}

int32_t CmServiceIsAuthorizedApp(const struct CmContext *context, const struct CmBlob *authUri)
{
    if (CheckUri(authUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CheckPermission(false, true);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    return CmAuthIsAuthorizedApp(context, authUri);
}

int32_t CmServiceRemoveGrantedApp(const struct CmContext *context, const struct CmBlob *keyUri, uint32_t appUid)
{
    if (CheckUri(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    int32_t ret = CheckPermission(true, true);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    return CmAuthRemoveGrantedApp(context, keyUri, appUid);
}

static int32_t CheckAndGetStore(const struct CmContext *context, const struct CmBlob *authUri, uint32_t *store)
{
    struct CMUri uriObj;
    int32_t ret = CertManagerUriDecode(&uriObj, (char *)authUri->data);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uri decode failed, ret = %d", ret);
        return ret;
    }

    if ((uriObj.object == NULL) || (uriObj.user == NULL) || (uriObj.app == NULL)) {
        CM_LOG_E("uri format invalid");
        (void)CertManagerFreeUri(&uriObj);
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    uint32_t type = uriObj.type;
    uint32_t userId = 0;
    if (CmIsNumeric(uriObj.user, strlen(uriObj.user) + 1, &userId) != CM_SUCCESS) {
        CM_LOG_E("parse string to uint32 failed.");
        (void)CertManagerFreeUri(&uriObj);
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    (void)CertManagerFreeUri(&uriObj);
    if (type == CM_URI_TYPE_SYS_KEY) {
        if (!CmHasSystemAppPermission()) {
            CM_LOG_E("caller lacks system app cert permission");
            return CMR_ERROR_PERMISSION_DENIED;
        }

        if (context->userId != 0 && context->userId != userId) {
            CM_LOG_E("uri check userId failed");
            return CMR_ERROR_INVALID_ARGUMENT_USER_ID;
        }

        *store = CM_SYS_CREDENTIAL_STORE;
    }

    return CM_SUCCESS;
}

int32_t CmServiceInit(const struct CmContext *context, const struct CmBlob *authUri,
    const struct CmSignatureSpec *spec, struct CmBlob *handle)
{
    if (CheckUri(authUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments uri");
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    if (CmCheckBlob(handle) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments handle");
        return CMR_ERROR_INVALID_ARGUMENT_HANDLE;
    }

    int32_t ret = CheckPermission(false, true);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    uint32_t store = CM_CREDENTIAL_STORE;
    ret = CheckAndGetStore(context, authUri, &store);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("check and get store error");
        return ret;
    }

    struct CmBlob commonUri = { 0, NULL };
    ret = CmCheckAndGetCommonUri(context, store, authUri, &commonUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("check and get common uri failed, ret = %d", ret);
        return ret;
    }

    enum CmAuthStorageLevel level;
    ret = GetRdbAuthStorageLevel(&commonUri, &level);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get rdb auth storage level failed, ret = %d", ret);
        CM_FREE_PTR(commonUri.data);
        return ret;
    }

    ret = CmKeyOpInit(context, &commonUri, spec, level, handle);
    CM_FREE_PTR(commonUri.data);
    return ret;
}

int32_t CmServiceUpdate(const struct CmContext *context, const struct CmBlob *handle,
    const struct CmBlob *inData)
{
    if (CmCheckBlob(handle) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT_HANDLE;
    }

    if (CmCheckBlob(inData) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CheckPermission(false, true);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    return CmKeyOpProcess(SIGN_VERIFY_CMD_UPDATE, context, handle, inData, NULL);
}

int32_t CmServiceFinish(const struct CmContext *context, const struct CmBlob *handle,
    const struct CmBlob *inData, struct CmBlob *outData)
{
    if (CmCheckBlob(handle) != CM_SUCCESS) { /* inData.data and outData.data can be null */
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT_HANDLE;
    }

    int32_t ret = CheckPermission(false, true);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    return CmKeyOpProcess(SIGN_VERIFY_CMD_FINISH, context, handle, inData, outData);
}

int32_t CmServiceAbort(const struct CmContext *context, const struct CmBlob *handle)
{
    if (CmCheckBlob(handle) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT_HANDLE;
    }

    int32_t ret = CheckPermission(false, true);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    return CmKeyOpProcess(SIGN_VERIFY_CMD_ABORT, context, handle, NULL, NULL);
}

static int32_t DeepCopyPath(const uint8_t *srcData, uint32_t srcLen, struct CmMutableBlob *dest)
{
    uint8_t *data = (uint8_t *)CMMalloc(srcLen);
    if (data == NULL) {
        CM_LOG_E("malloc failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(data, srcLen, srcData, srcLen);

    dest->data = data;
    dest->size = srcLen;
    return CM_SUCCESS;
}

static int32_t MergeUserPathList(const struct CmMutableBlob *callerPathList,
    const struct CmMutableBlob *targetPathList, struct CmMutableBlob *pathList)
{
    uint32_t uidCount = callerPathList->size + targetPathList->size;
    if (uidCount == 0) {
        return CM_SUCCESS;
    }

    if (uidCount > MAX_COUNT_CERTIFICATE_ALL) {
        CM_LOG_E("uid count beyond MAX");
        return CMR_ERROR_MAX_CERT_COUNT_REACHED;
    }

    uint32_t memSize = sizeof(struct CmMutableBlob) * uidCount;
    struct CmMutableBlob *uidList = (struct CmMutableBlob *)CMMalloc(memSize);
    if (uidList == NULL) {
        CM_LOG_E("malloc uidList failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(uidList, memSize, 0, memSize);

    int32_t ret = CM_SUCCESS;
    struct CmMutableBlob *callerPath = (struct CmMutableBlob *)callerPathList->data;
    struct CmMutableBlob *sysServicePath = (struct CmMutableBlob *)targetPathList->data;
    for (uint32_t i = 0; i < callerPathList->size; i++) {
        ret = DeepCopyPath(callerPath[i].data, callerPath[i].size, &uidList[i]);
        if (ret != CM_SUCCESS) {
            CmFreePathList(uidList, uidCount);
            return ret;
        }
    }
    for (uint32_t i = 0; i < targetPathList->size; i++) {
        ret = DeepCopyPath(sysServicePath[i].data, sysServicePath[i].size, &uidList[i + callerPathList->size]);
        if (ret != CM_SUCCESS) {
            CmFreePathList(uidList, uidCount);
            return ret;
        }
    }

    pathList->data = (uint8_t *)uidList;
    pathList->size = uidCount;
    return CM_SUCCESS;
}

static int32_t CmGetUserCertPathList(const struct CmContext *context, const struct UserCAProperty *prop,
    uint32_t store, struct CmMutableBlob *pathList)
{
    int32_t ret = CM_SUCCESS;
    struct CmMutableBlob callerPathList = { 0, NULL };
    struct CmMutableBlob targetPathList = { 0, NULL };

    do {
        /* user: caller */
        ret = CmGetCertPathList(context, store, &callerPathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get caller certPathList fail, ret = %d", ret);
            break;
        }

        /* avoid obtain duplicate data when both the target userid and the caller's userid are same */
        if (context->userId != prop->userId) {
            /* The caller takes the specified userid for sa, otherwise 0 */
            uint32_t targetUserId = context->userId == 0 ? prop->userId : 0;
            struct CmContext targetContext = { targetUserId, context->uid, {0} };
            ret = CmGetCertPathList(&targetContext, store, &targetPathList);
            if (ret != CM_SUCCESS) {
                CM_LOG_E("get system service certPathList fail, ret = %d", ret);
                break;
            }
        }

        /* merge callerPathList and targetPathList */
        ret = MergeUserPathList(&callerPathList, &targetPathList, pathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("merge cert path list failed");
            break;
        }
    } while (0);

    if (callerPathList.data != NULL) {
        CmFreePathList((struct CmMutableBlob *)callerPathList.data, callerPathList.size);
    }
    if (targetPathList.data != NULL) {
        CmFreePathList((struct CmMutableBlob *)targetPathList.data, targetPathList.size);
    }
    return ret;
}

static int32_t CmGetSaUserCertList(const struct CmContext *context, const struct UserCAProperty *prop,
    struct CmMutableBlob *pathList)
{
    int32_t ret = CM_SUCCESS;
    struct CmContext cmContext = *context;

    if (prop->userId == INIT_INVALID_VALUE) {
        /* if target userid is invalid, obtain the certificate in the userid=0 directory */
        ret = CmGetCertPathList(&cmContext, CM_USER_TRUSTED_STORE, pathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get target invalid cert path list failed");
        }
        return ret;
    }

    if (prop->scope == CM_ALL_USER) {
        ret = CmGetUserCertPathList(&cmContext, prop, CM_USER_TRUSTED_STORE, pathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get all user cert path list failed");
            return ret;
        }
    } else {
        if (prop->scope == CM_CURRENT_USER) { /* update target userid */
            cmContext.userId = prop->userId;
        }
        ret = CmGetCertPathList(&cmContext, CM_USER_TRUSTED_STORE, pathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get current or global user cert path list failed");
            return ret;
        }
    }
    return ret;
}

static int32_t CmGetHapUserCertList(const struct CmContext *context, const struct UserCAProperty *prop,
    struct CmMutableBlob *pathList)
{
    int32_t ret = CM_SUCCESS;
    struct CmContext cmContext = *context;

    if (prop->scope == CM_ALL_USER) {
        ret = CmGetUserCertPathList(&cmContext, prop, CM_USER_TRUSTED_STORE, pathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get all user cert path list failed");
            return ret;
        }
    } else {
        if (prop->scope == CM_GLOBAL_USER) { /* Obtain only the certificate in the userid=0 directory  */
            cmContext.userId = 0;
        }
        ret = CmGetCertPathList(&cmContext, CM_USER_TRUSTED_STORE, pathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get current or global cert path list failed");
            return ret;
        }
    }
    return ret;
}

static int32_t CmServiceGetUserCACertList(const struct CmContext *context, const struct UserCAProperty *prop,
    struct CmMutableBlob *pathList)
{
    int32_t ret = CM_SUCCESS;

    if (context->userId == 0) { /* caller is sa */
        ret = CmGetSaUserCertList(context, prop, pathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get sa user cert list failed");
            return ret;
        }
    } else { /* caller is hap */
        ret = CmGetHapUserCertList(context, prop, pathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get gap user cert list failed");
            return ret;
        }
    }
    return ret;
}

int32_t CmServiceGetCertList(const struct CmContext *context, const struct UserCAProperty *prop,
    uint32_t store, struct CmMutableBlob *certFileList)
{
    uint32_t scope = prop->scope;
    if (scope != CM_ALL_USER && scope != CM_CURRENT_USER && scope != CM_GLOBAL_USER) {
        CM_LOG_E("The scope is incorrect");
        return CMR_ERROR_INVALID_ARGUMENT_SCOPE;
    }

    int32_t ret = CM_SUCCESS;
    struct CmMutableBlob pathList = { 0, NULL };

    do {
        if (store == CM_USER_TRUSTED_STORE) {
            if (context->userId != 0 && prop->userId != INIT_INVALID_VALUE) {
                /* if caller is hap, the target userid must be invalid */
                CM_LOG_E("The target userid is incorrect");
                ret = CMR_ERROR_INVALID_ARGUMENT_USER_ID;
                break;
            }
            /* get all uid path for caller and system service */
            ret = CmServiceGetUserCACertList(context, prop, &pathList);
            if (ret != CM_SUCCESS) {
                CM_LOG_E("CmServiceGetUserCACertList fail, ret = %d", ret);
                break;
            }
        } else if (store == CM_SYSTEM_TRUSTED_STORE) {
            ret = CmGetSysCertPathList(context, &pathList);
            if (ret != CM_SUCCESS) {
                CM_LOG_E("GetCertPathList fail, ret = %d", ret);
                break;
            }
        } else {
            ret = CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE;
            CM_LOG_E("Invalid store");
            break;
        }

        /* create certFilelist(path + name) from every uid */
        ret = CreateCertFileList(&pathList, certFileList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CreateCertFileList fail, ret = %d", ret);
            break;
        }
    } while (0);

    if (pathList.data != NULL) {
        CmFreePathList((struct CmMutableBlob *)pathList.data, pathList.size);
    }
    return ret;
}

static int32_t CmServiceGetSysCertInfo(const struct CmContext *context, const struct CmBlob *certUri,
    uint32_t store, struct CmBlob *certificateData, uint32_t *status)
{
    int32_t ret = CM_SUCCESS;
    struct CmMutableBlob certFileList = { 0, NULL };
    do {
        const struct UserCAProperty prop = { INIT_INVALID_VALUE, CM_ALL_USER };
        ret = CmServiceGetCertList(context, &prop, store, &certFileList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertList failed, ret = %d", ret);
            break;
        }

        uint32_t matchIndex = CmGetMatchedCertIndex(&certFileList, certUri);
        if ((matchIndex == MAX_COUNT_CERTIFICATE) || (matchIndex == certFileList.size)) {
            CM_LOG_D("certFile of certUri don't matched");
            ret = CMR_ERROR_NOT_EXIST;
            break;
        }
        *status = CERT_STATUS_ENABLED;

        struct CertFileInfo *cFileList = (struct CertFileInfo *)certFileList.data;
        ret = CmStorageGetBuf((char *)cFileList[matchIndex].path.data,
        (char *)cFileList[matchIndex].fileName.data, certificateData); /* cert data */
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get cert data");
            break;
        }
    } while (0);

    if (certFileList.data != NULL) {
        CmFreeCertFiles((struct CertFileInfo *)certFileList.data, certFileList.size);
    }
    return ret;
}

static int32_t CmServiceGetUserCertInfo(struct CmContext *context, const struct CmBlob *certUri,
    uint32_t store, struct CmBlob *certificateData, uint32_t *status)
{
    int32_t ret = CM_SUCCESS;
    char uidPath[MAX_PATH_LEN] = { 0 };
    ret = CmServiceGetUserCertInfoCheck(context, certUri, CM_URI_TYPE_CERTIFICATE, false);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to check caller and uri");
        return ret;
    }

    ret = ConstructUidPath(context, store, uidPath, MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to construct uidpath");
        return ret;
    }
    struct CmBlob path = {MAX_PATH_LEN, (uint8_t *)uidPath};
    struct CertFileInfo cFile = {*certUri, path};
    ret = CmStorageGetBuf(uidPath, (char *)cFile.fileName.data, certificateData); /* cert data */
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get cert data");
        return ret;
    }

    if (store == CM_SYS_CREDENTIAL_STORE) {
        *status = CERT_STATUS_ENABLED;
        return ret;
    }
    ret = CmGetCertConfigStatus((char *)cFile.fileName.data, status);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get cert status, ret = %d", ret);
        CM_FREE_PTR(certificateData->data);
        certificateData->size = 0;
        return CMR_ERROR_GET_CERT_STATUS;
    }
    return ret;
}

int32_t CmServiceGetCertInfo(struct CmContext *context, const struct CmBlob *certUri,
    uint32_t store, struct CmBlob *certificateData, uint32_t *status)
{
    if (CmCheckBlob(certUri) != CM_SUCCESS || CheckUri(certUri) != CM_SUCCESS) {
        CM_LOG_E("input params invalid");
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    int32_t ret = CM_SUCCESS;
    if (store == CM_SYSTEM_TRUSTED_STORE) {
        ret = CmServiceGetSysCertInfo(context, certUri, store, certificateData, status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get system cert info");
            return ret;
        }
    } else if (store == CM_USER_TRUSTED_STORE) {
        ret = CmServiceGetUserCertInfo(context, certUri, store, certificateData, status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get user cert info");
            return ret;
        }
    } else {
        CM_LOG_E("Invalid store");
        ret = CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE;
    }
    return ret;
}

int32_t CmX509ToPEM(const X509 *x509, struct CmBlob *userCertPem)
{
    int32_t ret = CM_SUCCESS;
    char *pemCert = NULL;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        CM_LOG_E("BIO_new failed!");
        return CMR_ERROR_OPENSSL_FAIL;
    }

    do {
        if (PEM_write_bio_X509(bio, (X509 *)x509) == 0) {
            CM_LOG_E("Error writing PEM");
            ret = CMR_ERROR_OPENSSL_FAIL;
            break;
        }

        long pemCertLen = BIO_get_mem_data(bio, &pemCert);
        if (pemCertLen <= 0) {
            perror("Error getting PEM data");
            ret = CMR_ERROR_OPENSSL_FAIL;
            break;
        }

        userCertPem->data = (uint8_t *)CMMalloc(pemCertLen);
        if (userCertPem->data == NULL) {
            CM_LOG_E("CMMalloc buffer failed!");
            ret = CMR_ERROR_MALLOC_FAIL;
            break;
        }
        userCertPem->size = (uint32_t)pemCertLen;
        (void)memcpy_s(userCertPem->data, userCertPem->size, pemCert, pemCertLen);
    } while (0);

    BIO_free(bio);
    return ret;
}

static int32_t TryBackupUserCert(const struct CmContext *context, const struct CmBlob *userCert,
    struct CmBlob *certUri, struct CmMutableBlob *pathBlob)
{
    int32_t ret = CmBackupUserCert(context, certUri, userCert);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmBackupUserCert fail");
        if (CmRemoveUserCert(pathBlob, certUri) != CM_SUCCESS) {
            CM_LOG_E("CmBackupUserCert fail and CmRemoveUserCert fail");
        }
        return ret;
    }
    return ret;
}

static int32_t GetUserCertNameAndPath(const struct CmContext *context, const struct CmBlob *certData,
    const struct CmBlob *certAlias, struct CertName *certName, struct CmMutableBlob *pathBlob)
{
    int32_t ret = CM_SUCCESS;
    do {
        X509 *userCertX509 = InitCertContext(certData->data, certData->size);
        if (userCertX509 == NULL) {
            CM_LOG_E("Parse X509 cert fail");
            ret = CMR_ERROR_INVALID_CERT_FORMAT;
            break;
        }

        ret = GetSubjectNameAndAlias(userCertX509, certAlias, certName->subjectName, certName->displayName);
        FreeCertContext(userCertX509);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get alias from subject name");
            break;
        }

        ret = GetObjNameFromCertData(certData, certAlias, certName->objectName);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get object name from subject name");
            break;
        }

        ret = CmGetCertFilePath(context, CM_USER_TRUSTED_STORE, pathBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed obtain path for store:%u", CM_USER_TRUSTED_STORE);
            break;
        }
    } while (0);
    return ret;
}

static int32_t GetCertFileHash(const struct CmBlob *certFileData, struct CmBlob *certFileHash)
{
    uint8_t certAliasData[] = "";
    struct CmBlob certAlias = { sizeof(certAliasData), certAliasData };
    // get cert file hash
    int ret = GetObjNameFromCertData(certFileData, &certAlias, certFileHash);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get objName from certData failed, ret = %d", ret);
    }
    return ret;
}

static int32_t FindDuplicateUserCert(const struct CmContext *context, const char *objectName,
    struct CmBlob *outUri)
{
    if (context == NULL || objectName == NULL || outUri == NULL) {
        CM_LOG_E("params null pointer");
        return CMR_ERROR_NULL_POINTER;
    }
    struct CmMutableBlob certFileList = { 0, NULL };
    const struct UserCAProperty prop = { INIT_INVALID_VALUE, CM_CURRENT_USER };
    int32_t ret = CmServiceGetCertList(context, &prop, CM_USER_TRUSTED_STORE, &certFileList);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get cert file list failed");
        return ret;
    }
    struct CertFileInfo *cFileList = (struct CertFileInfo *)certFileList.data;
    ret = CMR_ERROR_NOT_EXIST;
    for (uint32_t i = 0; i < certFileList.size; i++) {
        struct CmBlob certData = { 0, NULL };
        ret = CmStorageGetBuf((char *)cFileList[i].path.data, (char *)cFileList[i].fileName.data, &certData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get cert data failed");
            break;
        }
        uint8_t certFileHashData[MAX_LEN_CERT_ALIAS] = { 0 };
        struct CmBlob certFileHash = { sizeof(certFileHashData), certFileHashData };
        ret = GetCertFileHash(&certData, &certFileHash);
        CM_FREE_BLOB(certData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get certFileHash failed");
            break;
        }
        if (strcmp((char *)certFileHashData, objectName) != 0) {
            ret = CMR_ERROR_NOT_EXIST;
            continue;
        }
        if (memcpy_s(outUri->data, outUri->size, cFileList[i].fileName.data, cFileList[i].fileName.size) != EOK) {
            CM_LOG_E("Copy cert uri failed");
            ret = CMR_ERROR_MEM_OPERATION_COPY;
            break;
        }
        outUri->size = cFileList[i].fileName.size;
        ret = CM_SUCCESS;
        break;
    }
    if (certFileList.data != NULL) {
        CmFreeCertFiles((struct CertFileInfo *)certFileList.data, certFileList.size);
    }
    return ret;
}

int32_t CmInstallUserCert(const struct CmContext *context, const struct CmBlob *userCert,
    const struct CmBlob *certAlias, const uint32_t status, struct CmBlob *certUri)
{
    int32_t ret = CM_SUCCESS;
    uint8_t pathBuf[CERT_MAX_PATH_LEN] = { 0 };
    struct CmMutableBlob pathBlob = { sizeof(pathBuf), pathBuf };
    uint8_t subjectBuf[MAX_LEN_SUBJECT_NAME] = { 0 };
    struct CmBlob subjectName = { sizeof(subjectBuf), subjectBuf };
    uint8_t objectBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    struct CmBlob objectName = { sizeof(objectBuf), objectBuf };
    uint8_t displayBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    struct CmBlob displayName = { sizeof(displayBuf), displayBuf };
    struct CertName certName = { &displayName, &objectName, &subjectName };

    ret = GetUserCertNameAndPath(context, userCert, certAlias, &certName, &pathBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("GetUserCertNameAndPath fail");
        return ret;
    }

    ret = FindDuplicateUserCert(context, (char *)objectBuf, certUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_W("No duplicate files found");   // should continue install user cert.
    }
    // If alias is specified or there are no duplicate user cert.
    if (strcmp("", (char *)certAlias->data) > 0 || ret != CM_SUCCESS) {
        ret = CmWriteUserCert(context, &pathBlob, userCert, &objectName, certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerWriteUserCert fail");
            return ret;
        }
    }

    struct CertPropertyOri propertyOri = { context, certUri, &displayName, &subjectName,
        CM_USER_TRUSTED_STORE, CM_AUTH_STORAGE_LEVEL_EL1 };

    ret = RdbInsertCertProperty(&propertyOri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to RdbInsertCertProperty");
        return ret;
    }

    ret = TryBackupUserCert(context, userCert, certUri, &pathBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("BackupUserCert fail");
        return ret;
    }
    return ret;
}

int32_t CmInstallMultiUserCert(const struct CmContext *context, const struct CmBlob *userCert,
    const struct CmBlob *certAlias, const uint32_t status, struct CmBlob *certUri)
{
    if (context == NULL || userCert == NULL || certAlias == NULL || certUri->data == NULL ||
        certUri->size < sizeof(uint32_t)) {
        CM_LOG_E("invalid argument");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint8_t *outData = certUri->data;
    uint32_t uriListSize = 0;

    STACK_OF(X509) *certStack = InitCertStackContext(userCert->data, userCert->size);
    if (certStack == NULL) {
        CM_LOG_E("init certStack failed");
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }
    uriListSize = (int32_t)sk_X509_num(certStack);
    // check buffer size
    uint32_t capacity = (certUri->size - sizeof(uint32_t)) / MAX_LEN_URI;
    if (uriListSize > capacity) {
        CM_LOG_E("too many certs, uriListSize = %u, capacity = %u", uriListSize, capacity);
        sk_X509_pop_free(certStack, X509_free);
        return CMR_ERROR_MAX_CERT_COUNT_REACHED;
    }
    int32_t ret = CheckInstallMultiCertCount(context, (uint32_t)uriListSize);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("check install certs too many, ret = %d", ret);
        sk_X509_pop_free(certStack, X509_free);
        return ret;
    }

    // set uriListSize
    *((uint32_t *)outData) = uriListSize;
    outData += sizeof(uint32_t);

    for (uint32_t i = 0; i < uriListSize; ++i) {
        struct CmBlob certPemData = { 0, NULL };
        X509 *cert = sk_X509_value(certStack, i);
        ret = CmX509ToPEM(cert, &certPemData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmX509ToPem failed, ret = %d", ret);
            break;
        }

        // install an user cert
        struct CmBlob outUri = { MAX_LEN_URI, outData };
        ret = CmInstallUserCert(context, &certPemData, certAlias, status, &outUri);
        if (ret != CM_SUCCESS) {
            CM_FREE_BLOB(certPemData);
            CM_LOG_E("CmInstallUserCert failed, ret = %d", ret);
            break;
        }
        CM_FREE_BLOB(certPemData);
        outData += MAX_LEN_URI;
    }

    sk_X509_pop_free(certStack, X509_free);
    return ret;
}

static int32_t CmComparisonCallerIdWithUri(const struct CmContext *context,
    const struct CmBlob *certUri)
{
    struct CMUri uriObj;
    (void)memset_s(&uriObj, sizeof(uriObj), 0, sizeof(uriObj));
    if (CheckUri(certUri) != CM_SUCCESS) {
        CM_LOG_E("cert uri no end");
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    int32_t ret = CertManagerUriDecode(&uriObj, (char *)certUri->data);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uri decode failed, ret = %d", ret);
        return ret;
    }

    ret = CMR_ERROR_INVALID_ARGUMENT_URI;
    do {
        if (uriObj.user == NULL) {
            CM_LOG_E("uri user invalid");
            break;
        }
        uint32_t userId = 0;
        if (CmIsNumeric(uriObj.user, strlen(uriObj.user) + 1, &userId) != CM_SUCCESS) {
            CM_LOG_E("parse string to uint32 failed.");
            break;
        }

        if (uriObj.app == NULL) {
            CM_LOG_E("uri app invalid");
            break;
        }
        uint32_t uid = 0;
        if (CmIsNumeric(uriObj.app, strlen(uriObj.app) + 1, &uid) != CM_SUCCESS) {
            CM_LOG_E("parse string to uint32 failed.");
            break;
        }

        if ((context->userId == userId) && (context->uid == uid)) {
            ret = CM_SUCCESS;
            break;
        }

        CM_LOG_E("userid(%u)/uid(%u) mismatch, uri: userid(%u)/uid(%u)", context->userId, context->uid, userId, uid);
    } while (0);

    (void)CertManagerFreeUri(&uriObj);
    return ret;
}

int32_t CmRmUserCert(const char *usrCertConfigFilepath)
{
    int32_t ret = CM_SUCCESS;
    uint8_t usrCertBackupFilePath[CERT_MAX_PATH_LEN + 1] = { 0 };
    uint32_t size = 0;

    ret = CmIsFileExist(NULL, usrCertConfigFilepath);
    if (ret != CMR_OK) {
        return CM_SUCCESS;
    }
    size = CmFileRead(NULL, usrCertConfigFilepath, 0, usrCertBackupFilePath, CERT_MAX_PATH_LEN);
    if (size == 0) {
        CM_LOG_E("CmFileRead read size 0 invalid ,fail");
        return CMR_ERROR_READ_FILE_ERROR;
    }

    ret = CmFileRemove(NULL, (const char *)usrCertBackupFilePath);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Remove cert backup file fail");
    }
    return ret;
}

int32_t CmRmSaConf(const char *usrCertConfigFilepath)
{
    int32_t ret = CM_SUCCESS;

    ret = CmFileRemove(NULL, usrCertConfigFilepath);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmFileRemove fail");
        return ret;
    }
    return ret;
}

int32_t CmUninstallUserCert(const struct CmContext *context, const struct CmBlob *certUri)
{
    if (CmCheckBlob(certUri) != CM_SUCCESS || CheckUri(certUri) != CM_SUCCESS) {
        CM_LOG_E("input params invalid");
        return CMR_ERROR_INVALID_ARGUMENT_URI;
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

        ret = DeleteCertProperty((char *)certUri->data);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed delete cert: %s rdbData", (char *)certUri->data);
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

        ret = CmRemoveBackupUserCert(context, certUri, NULL);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmRemoveBackupUserCert fail");
            break;
        }
    } while (0);
    return ret;
}

int32_t CmUninstallAllUserCert(const struct CmContext *context)
{
    uint32_t store = CM_USER_TRUSTED_STORE;
    struct CmMutableBlob pathList = { 0, NULL };

    int32_t ret = CmGetCertPathList(context, store, &pathList);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("GetCertPathList fail, ret = %d", ret);
        return ret;
    }

    if (pathList.size == 0) {
        CM_LOG_D("the user dir is empty");
        return CM_SUCCESS;
    }

    ret = CmRemoveAllUserCert(context, store, &pathList);
    CmFreePathList((struct CmMutableBlob *)pathList.data, pathList.size);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("RemoveAllUserCert fail, ret = %d", ret);
        return ret;
    }

    return ret;
}

int32_t CmSetStatusBackupCert(
    const struct CmContext *context, const struct CmBlob *certUri, uint32_t store, uint32_t status)
{
    int32_t ret = CM_SUCCESS;

    if (status == CERT_STATUS_ENANLED) {
        bool needUpdate = false;
        ret = IsCertNeedBackup(context->userId, context->uid, certUri, &needUpdate);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Check cert is need update failed, ret = %d", ret);
            return ret;
        } else if (needUpdate == false) {
            /* No need to update */
            return CM_SUCCESS;
        }

        struct CmBlob certificateData = { 0, NULL };
        ret = CmReadCertData(store, context, certUri, &certificateData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmReadCertData failed, ret = %d", ret);
            return CM_FAILURE;
        }

        ret = CmBackupUserCert(context, certUri, &certificateData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmBackupUserCert failed, ret = %d", ret);
            ret = CM_FAILURE;
        }
        CM_FREE_BLOB(certificateData);
    } else if (status == CERT_STATUS_DISABLED) {
        ret = CmRemoveBackupUserCert(context, certUri, NULL);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmRemoveBackupUserCert fail, ret = %d", ret);
        }
    }

    return ret;
}
