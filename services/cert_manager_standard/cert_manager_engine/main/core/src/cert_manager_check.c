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

#include "cert_manager_check.h"

#include <ctype.h>

#include "cert_manager.h"
#include "cert_manager_permission_check.h"
#include "cert_manager_uri.h"
#include "cm_log.h"

int32_t CheckUri(const struct CmBlob *keyUri)
{
    if (CmCheckBlob(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid uri");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (keyUri->size > MAX_AUTH_LEN_URI) {
        CM_LOG_E("invalid uri len:%u", keyUri->size);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    for (uint32_t i = 1; i < keyUri->size; ++i) { /* from index 1 has '\0' */
        if (keyUri->data[i] == 0) {
            return CM_SUCCESS;
        }
    }
    return CMR_ERROR_INVALID_ARGUMENT;
}

int32_t CmServiceGetSystemCertListCheck(const uint32_t store)
{
    if (store != CM_SYSTEM_TRUSTED_STORE) {
        CM_LOG_E("invalid input arguments store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    return CM_SUCCESS;
}

int32_t CmServiceGetSystemCertCheck(const uint32_t store, const struct CmBlob *certUri)
{
    if (store != CM_SYSTEM_TRUSTED_STORE) {
        CM_LOG_E("invalid input arguments store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (CheckUri(certUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    return CM_SUCCESS;
}

int32_t CmServiceSetCertStatusCheck(const uint32_t store, const struct CmBlob *certUri, const uint32_t status)
{
    if (store != CM_SYSTEM_TRUSTED_STORE) {
        CM_LOG_E("invalid input arguments store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (CheckUri(certUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if ((status != 0) && (status != 1)) {
        CM_LOG_E("invalid input status:%u", status);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasPrivilegedPermission() || !CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    if (!CmIsSystemApp()) {
        CM_LOG_E("set cert status: caller is not system app");
        return CMR_ERROR_NOT_SYSTEMP_APP;
    }

    return CM_SUCCESS;
}

static int32_t CmCheckAppCert(const struct CmBlob *appCert)
{
    if (CmCheckBlob(appCert) != CM_SUCCESS) {
        CM_LOG_E("appCert blob is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (appCert->size > MAX_LEN_APP_CERT) {
        CM_LOG_E("appCert size max check fail, appCert size:%u", appCert->size);
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

static int32_t CmCheckAppCertPwd(const struct CmBlob *appCertPwd)
{
    if (CmCheckBlob(appCertPwd) != CM_SUCCESS) {
        CM_LOG_E("appCertPwd blob is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (appCertPwd->size > MAX_LEN_APP_CERT_PASSWD) {
        CM_LOG_E("appCertPwd size max check fail, appCertPwd size:%u", appCertPwd->size);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (CheckUri(appCertPwd) != CM_SUCCESS) {
        CM_LOG_E("appCertPwd data check fail");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

static int32_t CmCheckCertAlias(const struct CmBlob *certAlias)
{
    if (CmCheckBlob(certAlias) != CM_SUCCESS) {
        CM_LOG_E("certAlias blob is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (certAlias->size > MAX_LEN_CERT_ALIAS) {
        CM_LOG_E("alias size is too large");
        return CMR_ERROR_ALIAS_LENGTH_REACHED_LIMIT;
    }

    if (CheckUri(certAlias) != CM_SUCCESS) {
        CM_LOG_E("appCertPwd data check fail");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

static bool CmCheckUserIdAndUpdateContext(const uint32_t inputUserId, uint32_t *callerUserId)
{
    if (*callerUserId == 0) { /* caller is sa */
        if (inputUserId == 0 || inputUserId == INIT_INVALID_VALUE) {
            CM_LOG_E("caller is sa, input userId %u is invalid", inputUserId);
            return false;
        }
        CM_LOG_D("update caller userId from %u to %u", *callerUserId, inputUserId);
        *callerUserId = inputUserId;
        return true;
    }

    /* caller is hap */
    if (inputUserId != INIT_INVALID_VALUE) {
        CM_LOG_E("caller is hap, input userId %u is not supported", inputUserId);
        return false;
    }
    return true;
}

static bool CmCheckMaxInstalledCertCount(const uint32_t store, const struct CmContext *cmContext)
{
    bool isValid = true;
    uint32_t fileCount = 0;
    struct CmBlob fileNames[MAX_COUNT_CERTIFICATE];
    uint32_t len = MAX_COUNT_CERTIFICATE * sizeof(struct CmBlob);
    (void)memset_s(fileNames, len, 0, len);

    if (CmServiceGetAppCertList(cmContext, store, fileNames,
        MAX_COUNT_CERTIFICATE, &fileCount) != CM_SUCCESS) {
        isValid = false;
        CM_LOG_E("Get App cert list fail");
    }

    if (fileCount >= MAX_COUNT_CERTIFICATE) {
        isValid = false;
        CM_LOG_E("The app cert installed has reached max count:%u", fileCount);
    }

    CM_LOG_D("app cert installed count:%u", fileCount);

    CmFreeFileNames(fileNames, fileCount);
    return isValid;
}

int32_t CmServiceInstallAppCertCheck(const struct CmAppCertParam *certParam, struct CmContext *cmContext)
{
    if ((certParam == NULL) || (cmContext == NULL)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (CM_STORE_CHECK(certParam->store)) {
        CM_LOG_E("CmInstallAppCertCheck store check fail, store:%u", certParam->store);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmCheckAppCert(certParam->appCert);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ret = CmCheckAppCertPwd(certParam->appCertPwd);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ret = CmCheckCertAlias(certParam->certAlias);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (certParam->store == CM_SYS_CREDENTIAL_STORE &&
        !CmCheckUserIdAndUpdateContext(certParam->userId, &(cmContext->userId))) {
        CM_LOG_E("input userId is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (CmCheckMaxInstalledCertCount(certParam->store, cmContext) == false) {
        CM_LOG_E("CmCheckMaxInstalledCertCount check fail");
        return CMR_ERROR_MAX_CERT_COUNT_REACHED;
    }

    if (!CmPermissionCheck(certParam->store)) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    if (!CmIsSystemAppByStoreType(certParam->store)) {
        CM_LOG_E("install app cert: caller is not system app");
        return CMR_ERROR_NOT_SYSTEMP_APP;
    }

    return CM_SUCCESS;
}

static int32_t checkCallerAndUri(struct CmContext *cmContext, const struct CmBlob *uri,
    const uint32_t type, bool isCheckUid)
{
    struct CMUri uriObj;
    int32_t ret = CertManagerUriDecode(&uriObj, (char *)uri->data);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to decode uri, ret = %d", ret);
        return ret;
    }

    if ((uriObj.object == NULL) || (uriObj.user == NULL) || (uriObj.app == NULL) || (uriObj.type != type)) {
        CM_LOG_E("uri format is invalid");
        (void)CertManagerFreeUri(&uriObj);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t userId = (uint32_t)atoi(uriObj.user);
    uint32_t uid = (uint32_t)atoi(uriObj.app);
    (void)CertManagerFreeUri(&uriObj);
    if ((cmContext->userId != 0) && (cmContext->userId != userId)) {
        CM_LOG_E("caller userid is not producer");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if ((isCheckUid) && (cmContext->userId == 0) && (cmContext->uid != uid)) {
        CM_LOG_E("caller uid is not producer");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    cmContext->userId = userId;
    cmContext->uid = uid;
    return CM_SUCCESS;
}

int32_t CmServiceUninstallAppCertCheck(struct CmContext *cmContext,
    const uint32_t store, const struct CmBlob *keyUri)
{
    if (CM_STORE_CHECK(store)) {
        CM_LOG_E("invalid input arguments store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (CheckUri(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmPermissionCheck(store)) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    if (!CmIsSystemAppByStoreType(store)) {
        CM_LOG_E("uninstall app cert: caller is not system app");
        return CMR_ERROR_NOT_SYSTEMP_APP;
    }

    if (store == CM_SYS_CREDENTIAL_STORE) {
        return checkCallerAndUri(cmContext, keyUri, CM_URI_TYPE_SYS_KEY, true);
    }

    return CM_SUCCESS;
}

static int32_t CmGetSysAppCertListCheck(const struct CmContext *cmContext, const uint32_t store)
{
    if (cmContext->userId == 0) {
        CM_LOG_E("get sys app cert list: caller is not hap");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    if (!CmIsSystemApp()) {
        CM_LOG_E("get sys app cert list: caller is not system app");
        return CMR_ERROR_NOT_SYSTEMP_APP;
    }
    return CM_SUCCESS;
}

int32_t CmServiceGetAppCertListCheck(const struct CmContext *cmContext, const uint32_t store)
{
    if (CM_STORE_CHECK(store)) {
        CM_LOG_E("invalid input arguments store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (store == CM_SYS_CREDENTIAL_STORE) {
        return CmGetSysAppCertListCheck(cmContext, store);
    }

    if (!CmHasPrivilegedPermission() || !CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    if (!CmIsSystemApp()) {
        CM_LOG_E("get app cert list: caller is not system app");
        return CMR_ERROR_NOT_SYSTEMP_APP;
    }

    return CM_SUCCESS;
}

int32_t CmServiceGetAppCertCheck(struct CmContext *cmContext, const uint32_t store, const struct CmBlob *keyUri)
{
    if (CM_STORE_CHECK(store)) {
        CM_LOG_E("invalid input arguments store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (CheckUri(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    if (store == CM_SYS_CREDENTIAL_STORE) {
        int32_t ret = checkCallerAndUri(cmContext, keyUri, CM_URI_TYPE_SYS_KEY, false);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get type and userid from uri error");
            return ret;
        }

        if (!CmHasSystemAppPermission()) {
            CM_LOG_E("sys ca store check failed");
            return CMR_ERROR_PERMISSION_DENIED;
        }
        if (!CmIsSystemApp()) {
            CM_LOG_E("GetAppCertCheck: caller is not system app");
            return CMR_ERROR_NOT_SYSTEMP_APP;
        }
    }

    return CM_SUCCESS;
}

static bool CmCheckAndUpdateCallerUserId(const uint32_t inputUserId, uint32_t *callerUserId)
{
    if (*callerUserId == 0) { /* caller is sa */
        if (inputUserId == INIT_INVALID_VALUE) {
            CM_LOG_D("caller is sa");
            return true;
        }
        CM_LOG_D("sa designates the userid: update caller userId from %u to %u", *callerUserId, inputUserId);
        *callerUserId = inputUserId;
        return true;
    }

    /* caller is hap, callerUserId is not 0 */
    if (inputUserId != INIT_INVALID_VALUE) {
        CM_LOG_E("caller is hap, input userId %u is not supported", inputUserId);
        return false;
    }
    return true;
}

int32_t CmServiceInstallUserCertCheck(struct CmContext *cmContext, const struct CmBlob *userCert,
    const struct CmBlob *certAlias, const uint32_t userId)
{
    if (cmContext == NULL) {
        CM_LOG_E("CmServiceInstallUserCertCheck: context is null");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if ((CmCheckBlob(userCert) != CM_SUCCESS) || userCert->size > MAX_LEN_CERTIFICATE) {
        CM_LOG_E("input params userCert is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmCheckCertAlias(certAlias);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (!CmHasCommonPermission() || !CmHasUserTrustedPermission()) {
        CM_LOG_E("install user cert: caller no permission");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    if (!CmIsSystemApp()) {
        CM_LOG_E("install user cert: caller is not system app");
        return CMR_ERROR_NOT_SYSTEMP_APP;
    }

    if (!CmCheckAndUpdateCallerUserId(userId, &(cmContext->userId))) {
        CM_LOG_E("input userId is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t CmServiceUninstallUserCertCheck(struct CmContext *cmContext, const struct CmBlob *certUri)
{
    if (cmContext == NULL) {
        CM_LOG_E("CmServiceUninstallUserCertCheck: context is null");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (CmCheckBlob(certUri) != CM_SUCCESS || CheckUri(certUri) != CM_SUCCESS) {
        CM_LOG_E("certUri is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission() || !CmHasUserTrustedPermission()) {
        CM_LOG_E("uninstall user cert: caller no permission");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    if (!CmIsSystemApp()) {
        CM_LOG_E("uninstall user cert: caller is not system app");
        return CMR_ERROR_NOT_SYSTEMP_APP;
    }

    int32_t ret = checkCallerAndUri(cmContext, certUri, CM_URI_TYPE_CERTIFICATE, true);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uninstall user cert: caller and uri check fail");
        return ret;
    }
    return CM_SUCCESS;
}
