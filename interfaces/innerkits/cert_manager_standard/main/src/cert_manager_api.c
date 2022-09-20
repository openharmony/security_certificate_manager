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

#ifdef CM_CONFIG_FILE
#include CM_CONFIG_FILE
#else
#include "cm_config.h"
#endif

#include "cert_manager_api.h"
#include "cm_client_ipc.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"

#include "cm_request.h"

CM_API_EXPORT int32_t CmGetCertList(const struct CmContext *cmContext, const uint32_t store,
    struct CertList *certificateList)
{
    CM_LOG_I("enter get certificate list");
    if ((cmContext == NULL) || (certificateList == NULL)) {
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = CmClientGetCertList(cmContext, store, certificateList);
    CM_LOG_I("leave get certificate list, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetCertInfo(const struct CmContext *cmContext, const struct CmBlob *certUri,
    const uint32_t store, struct CertInfo *certificateInfo)
{
    CM_LOG_I("enter get certificate info");
    if ((cmContext == NULL) || (certUri == NULL) || (certificateInfo == NULL)) {
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = CmClientGetCertInfo(cmContext, certUri, store, certificateInfo);
    CM_LOG_I("leave get certificate info, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmSetCertStatus(const struct CmContext *cmContext, const struct CmBlob *certUri,
    const uint32_t store, const bool status)
{
    CM_LOG_I("enter set certificate status");
    if ((cmContext == NULL) || (certUri == NULL)) {
        return CMR_ERROR_NULL_POINTER;
    }

    uint32_t uStatus = status ? 0: 1; // 0 indicates the certificate enabled status

    int32_t ret = CmClientSetCertStatus(cmContext, certUri, store, uStatus);
    CM_LOG_I("leave set certificate status, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmInstallAppCert(const struct CmBlob *appCert, const struct CmBlob *appCertPwd,
    const struct CmBlob *certAlias, const uint32_t store, struct CmBlob *keyUri)
{
    CM_LOG_I("enter install app certificate");
    if (appCert == NULL || appCertPwd == NULL || certAlias == NULL ||
        keyUri == NULL || keyUri->data == NULL || (store != CM_CREDENTIAL_STORE &&
        store != CM_PRI_CREDENTIAL_STORE)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientInstallAppCert(appCert, appCertPwd, certAlias, store, keyUri);
    CM_LOG_I("leave install app certificate, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmUninstallAppCert(const struct CmBlob *keyUri, const uint32_t store)
{
    CM_LOG_I("enter uninstall app certificate");
    if (keyUri == NULL || (store != CM_CREDENTIAL_STORE &&
        store != CM_PRI_CREDENTIAL_STORE)) {
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
    if (certificateList == NULL || (store != CM_CREDENTIAL_STORE &&
        store != CM_PRI_CREDENTIAL_STORE)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGetAppCertList(store, certificateList);
    CM_LOG_I("leave get app certificatelist, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetAppCert(const struct CmBlob *keyUri, const uint32_t store,
    struct Credential *certificate)
{
    CM_LOG_I("enter get app certificate");
    if (keyUri == NULL || certificate == NULL || (store != CM_CREDENTIAL_STORE &&
        store != CM_PRI_CREDENTIAL_STORE)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGetAppCert(keyUri, store, certificate);
    CM_LOG_I("leave get app certificate, result = %d", ret);
    return ret;
}