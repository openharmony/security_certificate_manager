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

#include "cert_manager_api_user_trusted_cert.h"

#include "cm_ipc_client_user_trusted_cert.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"

#include "cm_request.h"

CM_API_EXPORT int32_t CmGetCertList01(uint32_t store, struct CertList *certificateList)
{
    CM_LOG_I("enter get certificate list");
    if (certificateList == NULL) {
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = CmClientGetCertList01(store, certificateList);
    CM_LOG_I("leave get certificate list, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetCertInfo01(const struct CmBlob *certUri, uint32_t store, struct CertInfo *certificateInfo)
{
    CM_LOG_I("enter get certificate info");
    if ((certUri == NULL) || (certificateInfo == NULL)) {
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = CmClientGetCertInfo01(certUri, store, certificateInfo);
    CM_LOG_I("leave get certificate info, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmSetCertStatus01(const struct CmBlob *certUri, uint32_t store, const bool status)
{
    CM_LOG_I("enter set certificate status");
    if (certUri == NULL) {
        return CMR_ERROR_NULL_POINTER;
    }

    uint32_t uStatus = status? 0: 1; // 0 indicates the certificate enabled status

    int32_t ret = CmClientSetCertStatus01(certUri, store, uStatus);
    CM_LOG_I("leave set certificate status, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmInstallUserTrustedCert(const struct CmBlob *userCert, const struct CmBlob *certAlias,
    struct CmBlob *certUri)
{
    CM_LOG_I("enter install user certificate");
    if ((userCert == NULL) || (certAlias == NULL) || (certUri == NULL)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientInstallUserTrustedCert(userCert, certAlias, certUri);
    CM_LOG_I("leave install user certificate, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmUninstallUserTrustedCert(const struct CmBlob *certUri)
{
    CM_LOG_I("enter uninstall user certificate");
    if (certUri == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientUninstallUserTrustedCert(certUri);
    CM_LOG_I("leave uninstall user certificate, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmUninstallAllUserTrustedCert(void)
{
    CM_LOG_I("enter uninstall user all certificate");

    int32_t ret = CmClientUninstallAllUserTrustedCert(void);
    CM_LOG_I("leave uninstall all user certificate, result = %d", ret);
    return ret;
}
