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

#include "cm_advsecmode_check.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_ipc_client.h"
#include "cm_type.h"

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

CM_API_EXPORT int32_t CmInstallAppCertEx(const struct CmAppCertParam *certParam, struct CmBlob *keyUri)
{
    CM_LOG_I("enter install app certificate extension");
    /* The store must be private, and the userid must be invalid */
    if (certParam == NULL || certParam->appCert == NULL || certParam->appCertPwd == NULL||
        certParam->certAlias == NULL || keyUri == NULL || certParam->userId != INIT_INVALID_VALUE ||
        keyUri->data == NULL || certParam->store != CM_PRI_CREDENTIAL_STORE || CM_LEVEL_CHECK(certParam->level)) {
        CM_LOG_E("an error in the parameters of installing the application certificate ex.");
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

    struct CmAppCertParam certParam = { (struct CmBlob *)appCert, (struct CmBlob *)appCertPwd,
        (struct CmBlob *)certAlias, store, INIT_INVALID_VALUE, level };

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

CM_API_EXPORT int32_t CmInstallUserCACert(const struct CmBlob *userCert,
    const struct CmBlob *certAlias, const uint32_t userId, const bool status, struct CmBlob *certUri)
{
    CM_LOG_I("enter install user ca cert");
    if ((userCert == NULL) || (certAlias == NULL) || (certUri == NULL)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    bool isAdvSecMode = false;
    int32_t ret = CheckAdvSecMode(&isAdvSecMode);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    if (isAdvSecMode) {
        CM_LOG_E("InstallUserTrustedCert: the device enters advanced security mode");
        return CMR_ERROR_DEVICE_ENTER_ADVSECMODE;
    }

    uint32_t uStatus = status ? 0 : 1; // 0 indicates the certificate enabled status
    ret = CmClientInstallUserTrustedCert(userCert, certAlias, userId, uStatus, certUri);
    CM_LOG_I("leave install user ca cert, result = %d", ret);
    return ret;
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

