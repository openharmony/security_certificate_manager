/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CERT_MANAGER_PERMISSION_CHECK_H
#define CERT_MANAGER_PERMISSION_CHECK_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

bool CmHasPrivilegedPermission(void);

bool CmHasCommonPermission(void);

bool CmHasEnterpriseUserTrustedPermission(void);

bool CmHasUserTrustedPermission(void);

bool CmHasSystemAppPermission(void);

bool CmIsSystemApp(void);

bool CmIsSystemAppByStoreType(const uint32_t store);

bool CmPermissionCheck(const uint32_t store);

#ifdef __cplusplus
}
#endif

#endif /* CERT_MANAGER_PERMISSION_CHECK_H */
