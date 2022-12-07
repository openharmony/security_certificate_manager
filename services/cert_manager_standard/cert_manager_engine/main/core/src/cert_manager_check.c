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

static bool AppCertCheckBlobValid(const struct CmBlob *data)
{
    for (uint32_t i = 0; i < data->size; i++) {
        if ((i > 0) && (data->data[i] == '\0')) { /* from index 1 has '\0' */
            CM_LOG_E("data has string end character");
            return true;
        }

        if ((!isalnum(data->data[i])) && (data->data[i] != '_')) { /* has invalid character */
            CM_LOG_E("data include invalid character");
            return false;
        }
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

    CM_LOG_I("app cert installed count:%u", fileCount);

    CmFreeFileNames(fileNames, fileCount);
    return isValid;
}

int32_t CmServiceInstallAppCertCheck(const struct CmBlob *appCert, const struct CmBlob *appCertPwd,
    const struct CmBlob *certAlias, const uint32_t store, const struct CmContext *cmContext)
{
    if (store != CM_CREDENTIAL_STORE && store != CM_PRI_CREDENTIAL_STORE) {
        CM_LOG_E("CmInstallAppCertCheck store check fail, store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if ((CmCheckBlob(appCert) != CM_SUCCESS) || (CmCheckBlob(appCertPwd) != CM_SUCCESS) ||
        (CmCheckBlob(certAlias) != CM_SUCCESS)) {
        CM_LOG_E("CmInstallAppCertCheck blob check fail");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (appCert->size > MAX_LEN_APP_CERT || appCertPwd->size > MAX_LEN_APP_CERT_PASSWD ||
        certAlias->size > MAX_LEN_CERT_ALIAS) {
        CM_LOG_E("CmInstallAppCertCheck max check fail, appCert:%u, appCertPwd:%u, certAlias:%u",
            appCert->size, appCertPwd->size, certAlias->size);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!AppCertCheckBlobValid(appCertPwd) || !AppCertCheckBlobValid(certAlias)) {
        CM_LOG_E("CmInstallAppCertCheck blob data check fail");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (CmCheckMaxInstalledCertCount(store, cmContext) == false) {
        CM_LOG_E("CmCheckMaxInstalledCertCount check fail");
        return CM_FAILURE;
    }

    if (!CmPermissionCheck(store)) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    if (!CmIsSystemAppByStoreType(store)) {
        CM_LOG_E("install app cert: caller is not system app");
        return CMR_ERROR_NOT_SYSTEMP_APP;
    }

    return CM_SUCCESS;
}

int32_t CmServiceUninstallAppCertCheck(const uint32_t store, const struct CmBlob *keyUri)
{
    if ((store != CM_CREDENTIAL_STORE) && (store != CM_PRI_CREDENTIAL_STORE)) {
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

    return CM_SUCCESS;
}

int32_t CmServiceGetAppCertListCheck(const uint32_t store)
{
    if ((store != CM_CREDENTIAL_STORE) && (store != CM_PRI_CREDENTIAL_STORE)) {
        CM_LOG_E("invalid input arguments store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT;
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

int32_t CmServiceGetAppCertCheck(const uint32_t store, const struct CmBlob *keyUri)
{
    if ((store != CM_CREDENTIAL_STORE) && (store != CM_PRI_CREDENTIAL_STORE)) {
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

    return CM_SUCCESS;
}

