/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "cert_manager_api.h"

#include "systemcapability.h"

#include "cm_advsecmode_check.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_ipc_client.h"
#include "cm_type.h"

const char *HUKS_SYSCAP = "SystemCapability.Security.Huks.CryptoExtension";

CM_API_EXPORT int32_t CmGetCertList(uint32_t store, struct CertList *certificateList)
{
    CM_LOG_I("enter get certificate list");
    if (certificateList == NULL) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_NULL_POINTER;
    }

    if ((certificateList->certAbstract == NULL) || (store != CM_SYSTEM_TRUSTED_STORE)) {
        CM_LOG_E("invalid input arguments store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGetCertList(store, certificateList);
    CM_LOG_I("leave get certificate list, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetCertInfo(const struct CmBlob *certUri, uint32_t store,
    struct CertInfo *certificateInfo)
{
    CM_LOG_I("enter get certificate info");
    if ((certUri == NULL) || (certificateInfo == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_NULL_POINTER;
    }

    if ((certificateInfo->certInfo.data == NULL) || (certificateInfo->certInfo.size == 0) ||
        (store != CM_SYSTEM_TRUSTED_STORE)) {
        CM_LOG_E("invalid input arguments store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGetCertInfo(certUri, store, certificateInfo);
    CM_LOG_I("leave get certificate info, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmSetCertStatus(const struct CmBlob *certUri, const uint32_t store,
    const bool status)
{
    CM_LOG_I("enter set certificate status");
    if (certUri == NULL) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_NULL_POINTER;
    }

    if (store != CM_SYSTEM_TRUSTED_STORE) {
        CM_LOG_E("invalid input arguments store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t uStatus = status ? 0 : 1; // 0 indicates the certificate enabled status

    int32_t ret = CmClientSetCertStatus(certUri, store, uStatus);
    CM_LOG_I("leave set certificate status, result = %d", ret);
    return ret;
}

// FILE_P12 is complete p12 file, CHAIN_KEY split the file into certificate and private key
static bool CheckAppCertParams(const struct CmAppCertParam *certParam, struct CmBlob *keyUri)
{
    if (certParam == NULL || certParam->appCert == NULL || certParam->certAlias == NULL || keyUri == NULL ||
        keyUri->data == NULL || CM_LEVEL_CHECK(certParam->level) || CM_CRED_FORMAT_CHECK(certParam->credFormat)) {
        CM_LOG_E("Check generic app cert params failed");
        return false;
    }

    if (certParam->credFormat == FILE_P12) {
        if (certParam->appCertPwd == NULL || certParam->userId != INIT_INVALID_VALUE ||
            certParam->store != CM_PRI_CREDENTIAL_STORE) {
            CM_LOG_E("Check p12 file app cert params failed");
            return false;
        }
    } else {
        if (certParam->appCertPrivKey == NULL) {
            CM_LOG_E("Check cert chain and key app cert params failed");
            return false;
        }
    }
    return true;
}

// This interface can not only install private cred file
CM_API_EXPORT int32_t CmInstallAppCertEx(const struct CmAppCertParam *certParam, struct CmBlob *keyUri)
{
    CM_LOG_I("enter install app certificate extension");
    if (!CheckAppCertParams(certParam, keyUri)) {
        CM_LOG_E("check app cert params failed");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientInstallAppCert(certParam, keyUri);
    CM_LOG_I("leave install app certificate extension, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmInstallAppCert(const struct CmBlob *appCert, const struct CmBlob *appCertPwd,
    const struct CmBlob *certAlias, const uint32_t store, struct CmBlob *keyUri)
{
    CM_LOG_I("enter install app certificate");
    if (appCert == NULL || appCertPwd == NULL || certAlias == NULL ||
        keyUri == NULL || keyUri->data == NULL || CM_STORE_CHECK(store)) {
        CM_LOG_E("an error in the parameters of installing the application certificate.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    /* The public credentials are at the EL2 level. */
    enum CmAuthStorageLevel level = (store == CM_CREDENTIAL_STORE) ? CM_AUTH_STORAGE_LEVEL_EL2 :
        CM_AUTH_STORAGE_LEVEL_EL1;
    struct CmBlob privKey = { 0, NULL };
    struct CmAppCertParam certParam = { (struct CmBlob *)appCert, (struct CmBlob *)appCertPwd,
        (struct CmBlob *)certAlias, store, INIT_INVALID_VALUE, level, FILE_P12, &privKey, DEFAULT_FORMAT };

    int32_t ret = CmClientInstallAppCert(&certParam, keyUri);
    CM_LOG_I("leave install app certificate, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmUninstallAppCert(const struct CmBlob *keyUri, const uint32_t store)
{
    CM_LOG_I("enter uninstall app certificate");
    if (keyUri == NULL || CM_STORE_CHECK(store)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientUninstallAppCert(keyUri, store);
    CM_LOG_I("leave uninstall app certificate, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmUninstallAllAppCert(void)
{
    CM_LOG_I("enter uninstall all app certificate");

    int32_t ret = CmClientUninstallAllAppCert(CM_MSG_UNINSTALL_ALL_APP_CERTIFICATE);

    CM_LOG_I("leave uninstall all app certificate, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetAppCertList(const uint32_t store, struct CredentialList *certificateList)
{
    CM_LOG_I("enter get app certificatelist");
    if (certificateList == NULL || CM_STORE_CHECK(store)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGetAppCertList(store, certificateList);
    CM_LOG_I("leave get app certificatelist, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetAppCertListByUid(const uint32_t store, uint32_t appUid,
    struct CredentialList *certificateList)
{
    CM_LOG_D("enter get app certificatelist by uid");
    if (certificateList == NULL || CM_STORE_CHECK(store)) {
        CM_LOG_E("CmGetAppCertListByUid params is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGetAppCertListByUid(store, appUid, certificateList);
    CM_LOG_I("leave get app certificatelist by uid, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmCallingGetAppCertList(const uint32_t store, struct CredentialList *certificateList)
{
    CM_LOG_I("enter get calling app certificate");
    if (certificateList == NULL || CM_STORE_CHECK(store)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGetCallingAppCertList(store, certificateList);
    CM_LOG_I("leave get calling app certificate, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetAppCert(const struct CmBlob *keyUri, const uint32_t store,
    struct Credential *certificate)
{
    CM_LOG_I("enter get app certificate");
    if (keyUri == NULL || certificate == NULL || CM_STORE_CHECK(store)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGetAppCert(keyUri, store, certificate);
    CM_LOG_I("leave get app certificate, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGrantAppCertificate(const struct CmBlob *keyUri, uint32_t appUid, struct CmBlob *authUri)
{
    CM_LOG_I("enter grant app certificate");
    if ((keyUri == NULL) || (authUri == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGrantAppCertificate(keyUri, appUid, authUri);
    CM_LOG_I("leave grant app certificate, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetAuthorizedAppList(const struct CmBlob *keyUri, struct CmAppUidList *appUidList)
{
    CM_LOG_I("enter get authorized app list");
    if ((keyUri == NULL) || (appUidList == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGetAuthorizedAppList(keyUri, appUidList);
    CM_LOG_I("leave get authorized app list, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmIsAuthorizedApp(const struct CmBlob *authUri)
{
    CM_LOG_I("enter check is app authed");
    if (authUri == NULL) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientIsAuthorizedApp(authUri);
    CM_LOG_I("leave check is app authed, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmRemoveGrantedApp(const struct CmBlob *keyUri, uint32_t appUid)
{
    CM_LOG_I("enter remove granted app");
    if (keyUri == NULL) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientRemoveGrantedApp(keyUri, appUid);
    CM_LOG_I("leave remove granted app, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmInit(const struct CmBlob *authUri, const struct CmSignatureSpec *spec, struct CmBlob *handle)
{
    CM_LOG_I("enter cert manager init");
    if ((authUri == NULL) || (spec == NULL) || (handle == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientInit(authUri, spec, handle);
    CM_LOG_I("leave cert manager init, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmUpdate(const struct CmBlob *handle, const struct CmBlob *inData)
{
    CM_LOG_I("enter cert manager update");
    if ((handle == NULL) || (inData == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientUpdate(handle, inData);
    CM_LOG_I("leave cert manager update, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmFinish(const struct CmBlob *handle, const struct CmBlob *inData, struct CmBlob *outData)
{
    CM_LOG_I("enter cert manager finish");
    if ((handle == NULL) || (inData == NULL) || (outData == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientFinish(handle, inData, outData);
    CM_LOG_I("leave cert manager finish, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmAbort(const struct CmBlob *handle)
{
    CM_LOG_I("enter cert manager abort");
    if (handle == NULL) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientAbort(handle);
    CM_LOG_I("leave cert manager abort, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetUserCertList(uint32_t store, struct CertList *certificateList)
{
    CM_LOG_I("enter get cert list");
    if (certificateList == NULL) {
        return CMR_ERROR_NULL_POINTER;
    }

    const struct UserCAProperty property = { INIT_INVALID_VALUE, CM_ALL_USER };
    int32_t ret = CmClientGetUserCertList(&property, store, certificateList);
    CM_LOG_I("leave get cert list, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetUserCertInfo(const struct CmBlob *certUri, uint32_t store, struct CertInfo *certificateInfo)
{
    CM_LOG_I("enter get cert info");
    if ((certUri == NULL) || (certificateInfo == NULL)) {
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = CmClientGetUserCertInfo(certUri, store, certificateInfo);
    CM_LOG_I("leave get cert info, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmSetUserCertStatus(const struct CmBlob *certUri, uint32_t store, const bool status)
{
    CM_LOG_I("enter set cert status");
    if (certUri == NULL) {
        return CMR_ERROR_NULL_POINTER;
    }

    uint32_t uStatus = status ? 0 : 1; // 0 indicates the certificate enabled status

    int32_t ret = CmClientSetUserCertStatus(certUri, store, uStatus);
    CM_LOG_I("leave set cert status, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmInstallUserTrustedCert(const struct CmBlob *userCert, const struct CmBlob *certAlias,
    struct CmBlob *certUri)
{
    CM_LOG_I("enter install user trusted cert");
    if ((userCert == NULL) || (certAlias == NULL) || (certUri == NULL)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t userId = INIT_INVALID_VALUE;
    bool status = true;
    int32_t ret = CmInstallUserCACert(userCert, certAlias, userId, status, certUri);
    CM_LOG_I("leave install user trusted cert, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmUninstallUserTrustedCert(const struct CmBlob *certUri)
{
    CM_LOG_I("enter uninstall user trusted cert");
    if (certUri == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientUninstallUserTrustedCert(certUri);
    CM_LOG_I("leave uninstall user trusted cert, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmUninstallAllUserTrustedCert(void)
{
    CM_LOG_I("enter uninstall all user trusted cert");

    int32_t ret = CmClientUninstallAllUserTrustedCert();
    CM_LOG_I("leave uninstall all user trusted cert, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmInstallSystemAppCert(const struct CmAppCertParam *certParam, struct CmBlob *keyUri)
{
    CM_LOG_I("enter install system app certificate");
    if ((certParam == NULL) || (certParam->appCert == NULL) || (certParam->appCertPwd == NULL) ||
        (certParam->certAlias == NULL) || (keyUri == NULL) || (keyUri->data == NULL) ||
        (certParam->store != CM_SYS_CREDENTIAL_STORE) || (certParam->userId == 0) ||
        (certParam->userId == INIT_INVALID_VALUE)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientInstallSystemAppCert(certParam, keyUri);
    CM_LOG_I("leave install system app certificate, result = %d", ret);
    return ret;
}


static int32_t CmInstallUserTrustedCertByFormat(const struct CmInstallCertInfo *installCertInfo, bool status,
    struct CmBlob *certUri, const enum CmCertFileFormat certFormat)
{
    CM_LOG_I("enter install user ca cert by format");
    if (CmCheckInstallCertInfo(installCertInfo) != CM_SUCCESS || CmCheckBlob(certUri) != CM_SUCCESS) {
        CM_LOG_E("check installCertInfo failed");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    bool isAdvSecMode = false;
    int32_t ret = CheckAdvSecMode(&isAdvSecMode);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("check advSecMode failed, ret = %d", ret);
        return ret;
    }
    if (isAdvSecMode) {
        CM_LOG_E("the device enters advanced security mode");
        return CMR_ERROR_DEVICE_ENTER_ADVSECMODE;
    }

    uint32_t uStatus = status ? 0 : 1; // 0 indicates the certificate enabled status
    ret = CmClientInstallUserTrustedCert(installCertInfo, certFormat, uStatus, certUri);
    CM_LOG_I("leave install user ca cert, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmInstallUserCACert(const struct CmBlob *userCert,
    const struct CmBlob *certAlias, const uint32_t userId, const bool status, struct CmBlob *certUri)
{
    struct CmInstallCertInfo installInfo = {
        .userCert = userCert,
        .certAlias = certAlias,
        .userId = userId
    };
    int32_t ret = CmInstallUserTrustedCertByFormat(&installInfo, status, certUri, PEM_DER);
    CM_LOG_I("leave install user ca cert, result = %d", ret);
    return ret;
}

static int32_t UnpackCertUriList(struct CertUriList *certUriList, uint8_t *inData, uint32_t dataSize)
{
    if (certUriList == NULL || inData == NULL || dataSize < sizeof(uint32_t)) {
        CM_LOG_E("invalid argument");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    uint8_t *data = inData;
    uint32_t certCount = (uint32_t)*data;
    if (dataSize < (sizeof(uint32_t) + (certCount * MAX_LEN_URI))) {
        CM_LOG_E("buffer size too small");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    data += sizeof(uint32_t);
    certUriList->certCount = certCount;

    uint32_t uriListSize = (sizeof(struct CmBlob) + MAX_LEN_URI) * certCount;
    struct CmBlob *uriList = (struct CmBlob *)CmMalloc(uriListSize);
    if (uriList == NULL) {
        CM_LOG_E("memory operation failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(uriList, uriListSize, 0, uriListSize);
    certUriList->uriList = uriList;

    uint8_t *uriData = (uint8_t *)uriList + (sizeof(struct CmBlob) * certCount);

    if (memcpy_s(uriData, MAX_LEN_URI * certCount, data, MAX_LEN_URI * certCount) != EOK) {
        CM_LOG_E("memory copy failed");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    for (uint32_t i = 0; i < certCount; ++i) {
        uriList[i].data = uriData;
        uriList[i].size = MAX_LEN_URI;
        uriData += MAX_LEN_URI;
    }
    return CM_SUCCESS;
}

CM_API_EXPORT int32_t CmInstallUserTrustedP7BCert(const struct CmInstallCertInfo *installCertInfo, const bool status,
    struct CertUriList *certUriList)
{
    if (CmCheckInstallCertInfo(installCertInfo) != CM_SUCCESS || certUriList == NULL) {
        CM_LOG_E("invalid params");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t outDataSize = sizeof(uint32_t) + (MAX_LEN_URI * MAX_P7B_INSTALL_COUNT);
    uint8_t *outData = (uint8_t *)CmMalloc(outDataSize);
    if (outData == NULL) {
        CM_LOG_E("malloc failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    struct CmBlob certUriListBlob = { outDataSize, outData };
    int32_t ret = CmInstallUserTrustedCertByFormat(installCertInfo, status, &certUriListBlob, P7B);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("install certs failed, ret = %d", ret);
        CM_FREE_PTR(outData);
        return ret;
    }
    ret = UnpackCertUriList(certUriList, outData, outDataSize);
    CM_FREE_PTR(outData);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("unpack certUriList failed, ret = %d", ret);
        return ret;
    }
    return CM_SUCCESS;
}

CM_API_EXPORT int32_t CmGetUserCACertList(const struct UserCAProperty *property, struct CertList *certificateList)
{
    CM_LOG_I("enter get user ca cert list");
    if (certificateList == NULL || property == NULL) {
        return CMR_ERROR_NULL_POINTER;
    }

    const uint32_t store = CM_USER_TRUSTED_STORE;
    int32_t ret = CmClientGetUserCertList(property, store, certificateList);
    CM_LOG_I("leave get user ca cert list, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetCertStorePath(const enum CmCertType type, const uint32_t userId,
    char *path, uint32_t pathLen)
{
    if (path == NULL) {
        return CMR_ERROR_NULL_POINTER;
    }

    if (type == CM_CA_CERT_SYSTEM) {
        if (strcpy_s(path, pathLen, CA_STORE_PATH_SYSTEM) != EOK) {
            CM_LOG_E("get system ca path: out path len[%u] too small.", pathLen);
            return CMR_ERROR_BUFFER_TOO_SMALL;
        }
        return CM_SUCCESS;
    }

    if (type == CM_CA_CERT_USER) {
        if (sprintf_s(path, pathLen, "%s%u", CA_STORE_PATH_USER_SERVICE_BASE, userId) < 0) {
            CM_LOG_E("get user ca path: out path len[%u] too small.", pathLen);
            return CMR_ERROR_BUFFER_TOO_SMALL;
        }
        return CM_SUCCESS;
    }

    return CMR_ERROR_INVALID_ARGUMENT;
}

CM_API_EXPORT int32_t CmGetUkeyCertList(const struct CmBlob *ukeyProvider, const struct UkeyInfo *ukeyInfo,
    struct CredentialDetailList *certificateList)
{
    CM_LOG_D("enter get ukey cert list");
    if (ukeyProvider == NULL || ukeyInfo == NULL || certificateList == NULL) {
        CM_LOG_E("CmGetUkeyCertList params is invalid");
        return CMR_ERROR_NULL_POINTER;
    }
    bool isSupport = HasSystemCapability(HUKS_SYSCAP);
    if (isSupport == false) {
        CM_LOG_E("the device is not support");
        return CMR_ERROR_UKEY_DEVICE_SUPPORT;
    }
    int32_t ret = CmClientGetUkeyCertList(ukeyProvider, ukeyInfo, certificateList);
    CM_LOG_I("leave get ukey cert list, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetUkeyCert(const struct CmBlob *keyUri, const struct UkeyInfo *ukeyInfo,
    struct CredentialDetailList *certificateList)
{
    CM_LOG_D("enter get ukey cert");
    if (keyUri == NULL || ukeyInfo == NULL || certificateList == NULL) {
        CM_LOG_E("CmGetUkeyCert params is invalid");
        return CMR_ERROR_NULL_POINTER;
    }
    bool isSupport = HasSystemCapability(HUKS_SYSCAP);
    if (isSupport == false) {
        CM_LOG_E("the device is not support");
        return CMR_ERROR_UKEY_DEVICE_SUPPORT;
    }
    int32_t ret = CmClientGetUkeyCert(keyUri, ukeyInfo, certificateList);
    CM_LOG_I("leave get ukey cert, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmCheckAppPermission(const struct CmBlob *keyUri, uint32_t appUid,
    enum CmPermissionState *hasPermission, struct CmBlob *huksAlias)
{
    CM_LOG_D("enter check app permission");
    if (keyUri == NULL) {
        CM_LOG_E("CmCheckAppPermission params is invalid");
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = CmClientCheckAppPermission(keyUri, appUid, hasPermission, huksAlias);
    CM_LOG_I("leave check app permission, result = %d", ret);
    return ret;
}

CM_API_EXPORT void CmFreeUkeyCertificate(struct CredentialDetailList *certificateList)
{
    if (certificateList == NULL || certificateList->credential == NULL) {
        return;
    }
    for (uint32_t i = 0; i < MAX_COUNT_UKEY_CERTIFICATE; ++i) {
        CM_FREE_BLOB(certificateList->credential[i].credData);
    }
    certificateList->credentialCount = 0;
    CM_FREE_PTR(certificateList->credential);
}

CM_API_EXPORT void CmFreeCredential(struct Credential *certificate)
{
    if (certificate == NULL) {
        return;
    }

    if (certificate->credData.data != NULL) {
        CmFree(certificate->credData.data);
    }
}