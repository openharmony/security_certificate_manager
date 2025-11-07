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

#ifndef CERT_MANAGER_STATUS_H
#define CERT_MANAGER_STATUS_H

#include "cert_manager_mem.h"
#include "cm_type.h"

#define  CERT_STATUS_ENANLED           ((uint32_t) 0)
#define  CERT_STATUS_DISABLED          ((uint32_t) 1)

#define ASSERT_ARGS(c) if (!(c)) { CM_LOG_W("Invalid args: %s\n", #c); return CMR_ERROR_INVALID_ARGUMENT; }

#ifdef __cplusplus
extern "C" {
#endif

int32_t CmGetCertConfigStatus(const char *fileName, uint32_t *status);
#ifdef __cplusplus
}
#endif

#endif // CERT_MANAGER_STATUS_H