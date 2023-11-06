/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CM_SECURITY_GUARD_INFO_H
#define CM_SECURITY_GUARD_INFO_H

#include "cm_type_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

void CmReportSGSetCertStatus(const struct CmBlob *certUri, uint32_t store, uint32_t status, int32_t result);

void CmReportSGInstallUserCert(const struct CmBlob *certAlias, int32_t result);

void CmReportSGUninstallUserCert(const struct CmBlob *certUri, bool isUninstallAll, int32_t result);

void CmReportSGInstallAppCert(const struct CmBlob *certAlias, uint32_t store, int32_t result);

void CmReportSGUninstallAppCert(const struct CmBlob *keyUri, uint32_t store, bool isUninstallAll, int32_t result);

void CmReportSGGrantAppCert(const struct CmBlob *keyUri, uint32_t appUid, bool isRemove, int32_t result);

#ifdef __cplusplus
}
#endif

#endif