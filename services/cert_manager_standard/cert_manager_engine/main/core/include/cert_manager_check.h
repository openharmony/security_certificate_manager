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

#ifndef CM_CRYPTO_CHECK_H
#define CM_CRYPTO_CHECK_H

#include "cm_type_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CheckUri(const struct CmBlob *keyUri);

int32_t CmServiceGetSystemCertListCheck(const uint32_t store);

int32_t CmServiceGetSystemCertCheck(const uint32_t store, const struct CmBlob *certUri);

int32_t CmServiceSetCertStatusCheck(const uint32_t store, const struct CmBlob *certUri, const uint32_t status);

int32_t CmServiceInstallAppCertCheck(const struct CmAppCertParam *certParam, struct CmContext *cmContext);

int32_t CmServiceUninstallAppCertCheck(struct CmContext *cmContext, const uint32_t store,
    const struct CmBlob *keyUri);

int32_t CmServiceGetAppCertListCheck(const struct CmContext *cmContext, const uint32_t store);

int32_t CmServiceGetCallingAppCertListCheck(const struct CmContext *cmContext, const uint32_t store);

int32_t CmServiceGetAppCertCheck(struct CmContext *cmContext, const uint32_t store, const struct CmBlob *keyUri);

int32_t CmServiceInstallUserCertCheck(struct CmContext *cmContext, const struct CmBlob *userCert,
    const struct CmBlob *certAlias, const uint32_t userId, const uint32_t certFormat);

int32_t CmServiceUninstallUserCertCheck(struct CmContext *cmContext, const struct CmBlob *certUri);

int32_t CmServiceGetUserCertInfoCheck(struct CmContext *cmContext, const struct CmBlob *uri,
    const uint32_t type, bool isCheckUid);

int32_t CmServiceSetUserCertStatusCheck(struct CmContext *cmContext, const struct CmBlob *certUri);

int32_t CheckInstallMultiCertCount(const struct CmContext *context, const uint32_t certNum);
#ifdef __cplusplus
}
#endif

#endif