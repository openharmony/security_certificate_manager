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

#ifndef CM_IPC_SERIALIZATION_H
#define CM_IPC_SERIALIZATION_H

#include "cm_type_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CmTrustCertificateListUnpack(const struct CmBlob *srcData, struct CmContext *cmContext, uint32_t *store);

int32_t CmTrustCertificateInfoUnpack(const struct CmBlob *srcData, struct CmContext *cmContext,
    struct CmBlob *uriBlob, uint32_t *store);

int32_t CmCertificateStatusUnpack(const struct CmBlob *srcData, struct CmContext *cmContext,
    struct CmBlob *uriBlob, uint32_t *store, uint32_t* status);

int32_t CmParamSetToParams(const struct CmParamSet *paramSet, struct CmParamOut *outParams, uint32_t cnt);

#ifdef __cplusplus
}
#endif

#endif
