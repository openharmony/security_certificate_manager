/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CM_IPC_SERVICE_CERT_PACK_H
#define CM_IPC_SERVICE_CERT_PACK_H

#include "cm_type_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CmServiceGetCertListPack(const struct CmContext *context, uint32_t store,
    const struct CmMutableBlob *certFileList, struct CmBlob *certificateList);

int32_t CmServiceGetCertInfoPack(const uint32_t store, const struct CmBlob *certificateData,
    uint32_t status, const struct CmBlob *certUri, struct CmBlob *certificateInfo);

#ifdef __cplusplus
}
#endif

#endif /* CM_IPC_SERVICE_CERT_PACK_H */

