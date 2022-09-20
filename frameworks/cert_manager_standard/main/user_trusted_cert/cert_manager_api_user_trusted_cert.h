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

#ifndef CERT_MANGAGER_API_H
#define CERT_MANGAGER_API_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

CM_API_EXPORT int32_t CmGetCertList01(uint32_t store, struct CertList *certificateList);

CM_API_EXPORT int32_t CmGetCertInfo01(const struct CmBlob *certUri, uint32_t store,
    struct CertInfo *certificateInfo);

CM_API_EXPORT int32_t CmSetCertStatus01(const struct CmBlob *certUri, uint32_t store,
    const bool status);

CM_API_EXPORT int32_t CmInstallUserTrustedCert(const struct CmBlob *userCert,
    const struct CmBlob *certAlias, struct CmBlob *certUri);

CM_API_EXPORT int32_t CmUninstallUserTrustedCert(const struct CmBlob *certUri);

CM_API_EXPORT int32_t CmUninstallAllUserTrustedCert(void);

#ifdef __cplusplus
}
#endif

#endif /* CERT_MANGAGER_API_H */