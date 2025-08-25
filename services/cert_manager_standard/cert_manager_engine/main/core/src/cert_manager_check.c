/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "cm_util.h"

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
        return CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE;
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
        return CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE;
    }

    if (CheckUri(certUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT_URI;
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
        return CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE;
    }

    if (CheckUri(certUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    if ((status != 0) && (status != 1)) {
        CM_LOG_E("invalid input status:%u", status);
        return CMR_ERROR_INVALID_ARGUMENT_STATUS;
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
        return CMR_ERROR_INVALID_ARGUMENT_APP_CERT;
    }

    if (appCert->size > MAX_LEN_APP_CERT) {
        CM_LOG_E("appCert size max check fail, appCert size:%u", appCert->size);
        return CMR_ERROR_INVALID_ARGUMENT_APP_CERT;
    }
    return CM_SUCCESS;
}

static int32_t CmCheckAppCertPwd(const struct CmBlob *appCertPwd)
{
    if (CmCheckBlob(appCertPwd) != CM_SUCCESS) {
        CM_LOG_E("appCertPwd blob is invalid");
        return CMR_ERROR_INVALID_ARGUMENT_APP_PWD;
    }

    if (appCertPwd->size > MAX_LEN_APP_CERT_PASSWD) {
        CM_LOG_E("appCertPwd size max check fail, appCertPwd size:%u", appCertPwd->size);
        return CMR_ERROR_INVALID_ARGUMENT_APP_PWD;
    }

    for (uint32_t i = 0; i < appCertPwd->size; i++) { /* from index 0 has '\0' */
        if (appCertPwd->data[i] == 0) {
            return CM_SUCCESS;
        }
    }
    return CMR_ERROR_INVALID_ARGUMENT;
}

static int32_t CmCheckCredPrivKey(const struct CmBlob * appCredPrivKey)
{
    if (CmCheckBlob(appCredPrivKey) != CM_SUCCESS) {
        CM_LOG_E("appCredPrivKey blob is invalid");
        return CMR_ERROR_INVALID_ARGUMENT_CRED_PREVKEY;
    }
    if (appCredPrivKey->size > MAX_LEN_CRED_PRI_KEY) {
        CM_LOG_E("appCredPrivKey size max check fail, appCredPrivKey size:%u", appCredPrivKey->size);
        return CMR_ERROR_INVALID_ARGUMENT_CRED_PREVKEY;
    }
    return CM_SUCCESS;
}

// If called in lake, the laias input may be in chinese, so it will not be checked
static bool AppCertCheckBlobValid(const struct CmBlob *data, const enum AliasTransFormat aliasFormat)
{
    for (uint32_t i = 0; i < data->size; i++) {
        if ((i > 0) && (data->data[i] == '\0')) { /* from index 1 has '\0' */
            CM_LOG_D("data has string end character");
            return true;
        }

        // chinese is not permitted ,has invalid character
        if (aliasFormat == DEFAULT_FORMAT && (!isalnum(data->data[i])) && (data->data[i] != '_')) {
            CM_LOG_E("data include invalid character");
            return false;
        }
    }

    CM_LOG_E("data has no string end character");
    return false;
}

static int32_t CmCheckCertAlias(const struct CmBlob *certAlias, uint32_t store, const enum AliasTransFormat aliasFormat)
{
    if (CmCheckBlob(certAlias) != CM_SUCCESS) {
        CM_LOG_E("certAlias blob is invalid");
        return CMR_ERROR_INVALID_ARGUMENT_ALIAS;
    }

    if (certAlias->size > MAX_LEN_CERT_ALIAS) {
        CM_LOG_E("alias size is too large");
        return CMR_ERROR_INVALID_ARGUMENT_ALIAS;
    }

    if ((store == CM_PRI_CREDENTIAL_STORE) && (certAlias->size > MAX_LEN_PRI_CRED_ALIAS)) {
        CM_LOG_E("pri_cred: alias size is too large");
        return CMR_ERROR_INVALID_ARGUMENT_ALIAS;
    }

    if ((store != CM_PRI_CREDENTIAL_STORE) && (strcmp("", (char *)certAlias->data) == 0)) {
        CM_LOG_D("cert alias is empty string");
        return CM_SUCCESS;
    }

    if (!AppCertCheckBlobValid(certAlias, aliasFormat)) {
        CM_LOG_E("certAlias data check fail");
        return CMR_ERROR_INVALID_ARGUMENT_ALIAS;
    }
    return CM_SUCCESS;
}

static bool CmCheckUserIdAndUpdateContext(const uint32_t inputUserId, uint32_t *callerUserId, uint32_t store)
{
    if (*callerUserId == 0) { /* caller is sa */
        if (inputUserId == 0 || inputUserId == INIT_INVALID_VALUE) {
            if (store == CM_CREDENTIAL_STORE) {
                return true;
            } else {
                CM_LOG_E("caller is sa, input userId %u is invalid", inputUserId);
                return false;
            }
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

static int32_t CmCheckAppCertParam(const struct CmAppCertParam *certParam)
{
    if (CM_STORE_CHECK(certParam->store)) {
        CM_LOG_E("CmCheckAppCertParam store check fail, store:%u", certParam->store);
        return CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE;
    }

    if (CM_LEVEL_CHECK(certParam->level)) {
        CM_LOG_E("CmCheckAppCertParam level check fail, level:%u", certParam->level);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (CM_CRED_FORMAT_CHECK(certParam->credFormat)) {
        CM_LOG_E("CmCheckAppCertParam credFormat check fail, credFormat:%u", certParam->credFormat);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (CM_DETECT_ALIAS_CHECK(certParam->aliasFormat)) {
        CM_LOG_E("CmCheckAppCertParam credFormat check fail, aliasFormat:%u", certParam->aliasFormat);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmCheckAppCert(certParam->appCert);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ret = CmCheckCertAlias(certParam->certAlias, certParam->store, certParam->aliasFormat);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (certParam->credFormat == FILE_P12) {
        ret = CmCheckAppCertPwd(certParam->appCertPwd);
        if (ret != CM_SUCCESS) {
            return ret;
        }
    } else {
        ret = CmCheckCredPrivKey(certParam->appCertPrivKey);
        if (ret != CM_SUCCESS) {
            return ret;
        }
    }
    return ret;
}

int32_t CmServiceInstallAppCertCheck(const struct CmAppCertParam *certParam, struct CmContext *cmContext)
{
    if ((certParam == NULL) || (cmContext == NULL)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmCheckAppCertParam(certParam);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("app cert param is invalid");
        return ret;
    }

    if ((certParam->store == CM_SYS_CREDENTIAL_STORE || certParam->store == CM_CREDENTIAL_STORE) &&
        !CmCheckUserIdAndUpdateContext(certParam->userId, &(cmContext->userId), certParam->store)) {
        CM_LOG_E("input userId is invalid");
        return CMR_ERROR_INVALID_ARGUMENT_USER_ID;
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

static int32_t CheckAndUpdateCallerAndUri(struct CmContext *cmContext, const struct CmBlob *uri,
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
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    uint32_t userId = 0;
    uint32_t uid = 0;
    if (CmIsNumeric(uriObj.user, strlen(uriObj.user) + 1, &userId) != CM_SUCCESS ||
        CmIsNumeric(uriObj.app, strlen(uriObj.app) + 1, &uid) != CM_SUCCESS) {
        CM_LOG_E("parse string to uint32 failed.");
        (void)CertManagerFreeUri(&uriObj);
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    (void)CertManagerFreeUri(&uriObj);
    if (type == CM_URI_TYPE_SYS_KEY) {
        if ((cmContext->userId != 0) && (cmContext->userId != userId)) {
            CM_LOG_E("caller is hap, current user is %u, userid[%u] is invalid", cmContext->userId, userId);
            return CMR_ERROR_INVALID_ARGUMENT_USER_ID;
        }
    } else if (type == CM_URI_TYPE_CERTIFICATE) {
        if ((cmContext->userId != 0) && (cmContext->userId != userId) && (userId != 0)) {
            CM_LOG_E("caller is hap, current user is %u, userid[%u] is invalid", cmContext->userId, userId);
            return CMR_ERROR_INVALID_ARGUMENT_USER_ID;
        }
    } else {
        return CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE;
    }

    if ((isCheckUid) && (cmContext->userId == 0) && (cmContext->uid != uid)) {
        CM_LOG_E("caller uid is not producer");
        return CMR_ERROR_INVALID_ARGUMENT_UID;
    }

    cmContext->userId = userId;
    cmContext->uid = uid;
    return CM_SUCCESS;
}

/* check context and uri and update it */
int32_t CmServiceGetUserCertInfoCheck(struct CmContext *cmContext, const struct CmBlob *uri,
    const uint32_t type, bool isCheckUid)
{
    if (cmContext == NULL) {
        CM_LOG_E("CmServiceGetCertInfoCheck: Context is NULL");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (CheckUri(uri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    return CheckAndUpdateCallerAndUri(cmContext, uri, type, isCheckUid);
}

int32_t CmServiceUninstallAppCertCheck(struct CmContext *cmContext,
    const uint32_t store, const struct CmBlob *keyUri)
{
    if (CM_STORE_CHECK(store)) {
        CM_LOG_E("invalid input arguments store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE;
    }

    if (CheckUri(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT_URI;
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
        return CheckAndUpdateCallerAndUri(cmContext, keyUri, CM_URI_TYPE_SYS_KEY, true);
    }

    return CM_SUCCESS;
}

static int32_t CmGetSysAppCertListCheck(const struct CmContext *cmContext, const uint32_t store)
{
    if (cmContext->userId == 0) {
        CM_LOG_E("get sys app cert list: caller is not hap");
        return CMR_ERROR_INVALID_ARGUMENT_USER_ID;
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
        return CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE;
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

int32_t CmServiceGetCallingAppCertListCheck(const struct CmContext *cmContext, const uint32_t store)
{
    if (CM_STORE_CHECK(store)) {
        CM_LOG_E("invalid input arguments store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE;
    }

    if (store == CM_SYS_CREDENTIAL_STORE) {
        return CmGetSysAppCertListCheck(cmContext, store);
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    if (store == CM_PRI_CREDENTIAL_STORE) {
        return CM_SUCCESS;
    }

    if (!CmHasPrivilegedPermission()) {
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
        return CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE;
    }

    if (CheckUri(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    if (store == CM_SYS_CREDENTIAL_STORE) {
        int32_t ret = CheckAndUpdateCallerAndUri(cmContext, keyUri, CM_URI_TYPE_SYS_KEY, false);
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

    /* caller is hap, callerUserId can be 0 or 0xFFFFFFFF */
    if (inputUserId != 0 && inputUserId != INIT_INVALID_VALUE) {
        CM_LOG_E("caller is hap, input userId %u is not supported", inputUserId);
        return false;
    }
    if (inputUserId == 0) {
        CM_LOG_D("hap install in public location: update caller userId from %u to 0", *callerUserId);
        *callerUserId = 0;
    }
    return true;
}

int32_t CmServiceInstallUserCertCheck(struct CmContext *cmContext, const struct CmBlob *userCert,
    const struct CmBlob *certAlias, const uint32_t userId, const uint32_t certFormat)
{
    if (cmContext == NULL) {
        CM_LOG_E("CmServiceInstallUserCertCheck: context is null");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t userCertMaxLen = (certFormat == P7B) ? MAX_LEN_CERTIFICATE_P7B : MAX_LEN_CERTIFICATE;
    if ((CmCheckBlob(userCert) != CM_SUCCESS) || userCert->size > userCertMaxLen) {
        CM_LOG_E("input params userCert is invalid");
        return CMR_ERROR_INVALID_ARGUMENT_APP_CERT;
    }

    int32_t ret = CmCheckCertAlias(certAlias, CM_USER_TRUSTED_STORE, DEFAULT_FORMAT);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (!CmHasEnterpriseUserTrustedPermission() && !CmHasUserTrustedPermission()) {
        CM_LOG_E("install user cert: caller no permission");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    if (!CmCheckAndUpdateCallerUserId(userId, &(cmContext->userId))) {
        CM_LOG_E("input userId is invalid");
        return CMR_ERROR_INVALID_ARGUMENT_USER_ID;
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
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    if (!CmHasEnterpriseUserTrustedPermission() && !CmHasUserTrustedPermission()) {
        CM_LOG_E("uninstall user cert: caller no permission");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    int32_t ret = CheckAndUpdateCallerAndUri(cmContext, certUri, CM_URI_TYPE_CERTIFICATE, true);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uninstall user cert: caller and uri check fail");
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CmServiceSetUserCertStatusCheck(struct CmContext *cmContext, const struct CmBlob *certUri)
{
    if (cmContext == NULL) {
        CM_LOG_E("CmServiceUninstallUserCertCheck: context is null");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission() || !CmHasUserTrustedPermission()) {
        CM_LOG_E("caller no permission");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    if (!CmIsSystemApp()) {
        CM_LOG_E("set user status: caller is not system app");
        return CMR_ERROR_NOT_SYSTEMP_APP;
    }

    if (CmCheckBlob(certUri) != CM_SUCCESS || CheckUri(certUri) != CM_SUCCESS) {
        CM_LOG_E("certUri is invalid");
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    int32_t ret = CheckAndUpdateCallerAndUri(cmContext, certUri, CM_URI_TYPE_CERTIFICATE, true);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uninstall user cert: caller and uri check fail");
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CheckInstallMultiCertCount(const struct CmContext *context, const uint32_t certNum)
{
    uint32_t certCount = 0;
    int32_t ret = GetCertOrCredCount(context, CM_USER_TRUSTED_STORE, &certCount);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed obtain cert count for store muti user cert.");
        return ret;
    }
    if (certCount + certNum > MAX_COUNT_CERTIFICATE) {
        CM_LOG_E("cert count beyond maxcount, can't install user certs");
        return CMR_ERROR_MAX_CERT_COUNT_REACHED;
    }
    return CM_SUCCESS;
}
