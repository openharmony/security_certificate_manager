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

#ifndef CERT_MANAGER_UTIL_H
#define CERT_MANAGER_UTIL_H

#include "cert_manager_type.h"
#include "cert_manager_mem.h"
#include "cm_type.h"
#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ASSERT_HKS_CALL(f) do {int32_t _rc = (f); if ((_rc) != HKS_SUCCESS) { return (int32_t) (rc); }} while (0)
#define TRY_CM_CALL(f, rc) do {int32_t _rc = (f); if ((_rc) != HKS_SUCCESS) { \
    CM_LOG_W("Failed: %s, %d\n", #f, (_rc)); (rc) = (int32_t)(_rc); goto finally; }} while (0)

int32_t CertManagerHmac(const char *uri, const struct CmBlob *data, struct CmMutableBlob *mac);

int32_t CertManagerGenerateHmacKey(const char *uri);

int32_t CertManagerBuildKeySpec(struct HksParamSet **params, const struct CMKeyProperties *properties);

#ifdef __cplusplus
}
#endif

#endif // CERT_MANAGER_UTIL_H