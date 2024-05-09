/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "cm_log.h"
#include "cm_type.h"
#include "cm_x509.h"

#include "cert_manager_file_operator.h"
#include "cert_manager_updateflag.h"

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
    if (CheckUri(keyUri) != CM_SUCCESS || CmCheckBlob(authUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
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
        return CMR_ERROR_INVALID_ARGUMENT;
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
        return CMR_ERROR_INVALID_ARGUMENT;
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
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t type = uriObj.type;
    uint32_t userId = (uint32_t)atoi(uriObj.user);
    (void)CertManagerFreeUri(&uriObj);
    if (type == CM_URI_TYPE_SYS_KEY) {
        if (!CmHasSystemAppPermission()) {
            CM_LOG_E("caller lacks system app cert permission");
            return CMR_ERROR_PERMISSION_DENIED;
        }

        if (context->userId != 0 && context->userId != userId) {
            CM_LOG_E("uri check userId failed");
            return CMR_ERROR_INVALID_ARGUMENT;
        }

        *store = CM_SYS_CREDENTIAL_STORE;
    }

    return CM_SUCCESS;
}

int32_t CmServiceInit(const struct CmContext *context, const struct CmBlob *authUri,
    const struct CmSignatureSpec *spec, struct CmBlob *handle)
{
    if (CheckUri(authUri) != CM_SUCCESS || CmCheckBlob(handle) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
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
        return CMR_ERROR_INVALID_ARGUMENT;
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
        return CMR_ERROR_INVALID_ARGUMENT;
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
    const struct CmMutableBlob *sysServicePathList, struct CmMutableBlob *pathList)
{
    uint32_t uidCount = callerPathList->size + sysServicePathList->size;
    if (uidCount == 0) {
        return CM_SUCCESS;
    }

    if (uidCount > MAX_COUNT_CERTIFICATE) {
        CM_LOG_E("uid count beyond MAX");
        return CM_FAILURE;
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
    struct CmMutableBlob *sysServicePath = (struct CmMutableBlob *)sysServicePathList->data;
    for (uint32_t i = 0; i < callerPathList->size; i++) {
        ret = DeepCopyPath(callerPath[i].data, callerPath[i].size, &uidList[i]);
        if (ret != CM_SUCCESS) {
            CmFreePathList(uidList, uidCount);
            return ret;
        }
    }
    for (uint32_t i = 0; i < sysServicePathList->size; i++) {
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

static int32_t CmGetUserCertPathList(const struct CmContext *context, uint32_t store, struct CmMutableBlob *pathList)
{
    int32_t ret = CM_SUCCESS;
    struct CmMutableBlob callerPathList = { 0, NULL };
    struct CmMutableBlob sysServicePathList = { 0, NULL };

    do {
        /* user: caller */
        ret = CmGetCertPathList(context, store, &callerPathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get caller certPathList fail, ret = %d", ret);
            break;
        }

        /* user: system service */
        uint32_t sysServiceUserId = 0;
        struct CmContext sysServiceContext = { sysServiceUserId, context->uid, {0} };
        ret = CmGetCertPathList(&sysServiceContext, store, &sysServicePathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get system service certPathList fail, ret = %d", ret);
            break;
        }

        /* merge callerPathList and sysServicePathList */
        ret = MergeUserPathList(&callerPathList, &sysServicePathList, pathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("merge cert path list failed");
            break;
        }
    } while (0);

    if (callerPathList.data != NULL) {
        CmFreePathList((struct CmMutableBlob *)callerPathList.data, callerPathList.size);
    }
    if (sysServicePathList.data != NULL) {
        CmFreePathList((struct CmMutableBlob *)sysServicePathList.data, sysServicePathList.size);
    }
    return ret;
}

int32_t CmServiceGetCertList(const struct CmContext *context, uint32_t store, struct CmMutableBlob *certFileList)
{
    int32_t ret = CM_SUCCESS;
    struct CmMutableBlob pathList = { 0, NULL }; /* uid path list */

    do {
        if (store == CM_USER_TRUSTED_STORE) {
            /* get all uid path for caller and system service */
            ret = CmGetUserCertPathList(context, store, &pathList);
            if (ret != CM_SUCCESS) {
                CM_LOG_E("GetCertPathList fail, ret = %d", ret);
                break;
            }
        } else if (store == CM_SYSTEM_TRUSTED_STORE) {
            ret = CmGetSysCertPathList(context, &pathList);
            if (ret != CM_SUCCESS) {
                CM_LOG_E("GetCertPathList fail, ret = %d", ret);
                break;
            }
        } else {
            ret = CM_FAILURE;
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
            CM_LOG_D("certFile of certUri don't matched");
            ret = CMR_ERROR_NOT_EXIST;
            break;
        }

        struct CertFileInfo *cFileList = (struct CertFileInfo *)certFileList.data;
        ret = CmGetCertStatus(context, &cFileList[matchIndex], store, status); /* status */
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get cert status");
            ret = CM_FAILURE;
            break;
        }

        ret = CmStorageGetBuf((char *)cFileList[matchIndex].path.data,
            (char *)cFileList[matchIndex].fileName.data, certificateData); /* cert data */
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get cert data");
            ret = CM_FAILURE;
            break;
        }
    } while (0);

    if (certFileList.data != NULL) {
        CmFreeCertFiles((struct CertFileInfo *)certFileList.data, certFileList.size);
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
        return CM_FAILURE;
    }

    do {
        if (PEM_write_bio_X509(bio, (X509 *)x509) == 0) {
            CM_LOG_E("Error writing PEM");
            ret = CM_FAILURE;
            break;
        }

        long pemCertLen = BIO_get_mem_data(bio, &pemCert);
        if (pemCertLen <= 0) {
            perror("Error getting PEM data");
            ret = CM_FAILURE;
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
        return CM_FAILURE;
    }
    return ret;
}

int32_t CmInstallUserCert(const struct CmContext *context, const struct CmBlob *userCert,
    const struct CmBlob *certAlias, const uint32_t status, struct CmBlob *certUri)
{
    int32_t ret = CM_SUCCESS;
    uint8_t pathBuf[CERT_MAX_PATH_LEN] = { 0 };
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
            CM_LOG_E("Failed obtain path for store:%u", store);
            break;
        }

        ret = CmWriteUserCert(context, &pathBlob, userCert, certAlias, certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerWriteUserCert fail");
            break;
        }

        ret = SetcertStatus(context, certUri, store, status, NULL);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("SetcertStatus fail");
            break;
        }

        if (status == CERT_STATUS_ENABLED) {
            ret = TryBackupUserCert(context, userCert, certUri, &pathBlob);
            if (ret != CM_SUCCESS) {
                CM_LOG_E("BackupUserCert fail");
                break;
            }
        }
    } while (0);
    return ret;
}

static int32_t CmComparisonCallerIdWithUri(const struct CmContext *context,
    const struct CmBlob *certUri)
{
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
    uint32_t userId = (uint32_t)atoi(uriObj.user);

    if (uriObj.app == NULL) {
        CM_LOG_E("uri app invalid");
        (void)CertManagerFreeUri(&uriObj);
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    uint32_t uid = (uint32_t)atoi(uriObj.app);
    if ((context->userId == userId) && (context->uid == uid)) {
        ret = CM_SUCCESS;
    } else {
        ret =  CMR_ERROR_INVALID_ARGUMENT;
    }

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
        return CM_FAILURE;
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

        ret = CmRemoveBackupUserCert(context, certUri, NULL);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmRemoveBackupUserCert fail");
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
    uint32_t store = CM_USER_TRUSTED_STORE;
    struct CmMutableBlob pathList = { 0, NULL };

    int32_t ret = CmGetCertPathList(context, store, &pathList);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("GetCertPathList fail, ret = %d", ret);
        return ret;
    }

    ret = CmRemoveAllUserCert(context, store, &pathList);
    CmFreePathList((struct CmMutableBlob *)pathList.data, pathList.size);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("RemoveAllUserCert fail, ret = %d", ret);
        return ret;
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

int32_t CmSetStatusBackupCert(
    const struct CmContext *context, const struct CmBlob *certUri, uint32_t store, uint32_t status)
{
    int32_t ret = CM_SUCCESS;

    if (status == CERT_STATUS_ENANLED) {
        bool needUpdate = false;
        ret = IsCertNeedBackup(context->userId, context->uid, certUri, &needUpdate);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Check cert is need update failed, ret = %d", ret);
            return CMR_ERROR_INVALID_OPERATION;
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
