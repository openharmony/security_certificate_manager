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

#ifndef CM_CLIENT_IPC_H
#define CM_CLIENT_IPC_H

#include "cm_type_inner.h"

#ifdef __cplusplus
extern "C"
{
#endif

int32_t CmClientGetCertList01(const uint32_t store, struct CertList *certificateList);

int32_t CmClientGetCertInfo01(const struct CmBlob *certUri, const uint32_t store,
    struct CertInfo *certificateInfo);

int32_t CmClientSetCertStatus01(const struct CmBlob *certUri, const uint32_t store,
    const uint32_t status);

int32_t CmClientInstallUserTrustedCert(const struct CmBlob *userCert, const struct CmBlob *certAlias,
    struct CmBlob *certUri);

int32_t CmClientUninstallUserTrustedCert(const struct CmBlob *certUri);

int32_t CmClientUninstallAllUserTrustedCert(void);

#ifdef __cplusplus
}
#endif

#endif /* CM_CLIENT_IPC_H */
