/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef CM_FUZZ_TEST_COMMON_H
#define CM_FUZZ_TEST_COMMON_H

#include "cert_manager_service_ipc_interface_code.h"
#include "cm_mem.h"
#include "cm_param.h"
#include "cm_type.h"
#include "securec.h"

namespace CmFuzzTest {
bool GetUintFromBuffer(uint8_t *srcData, uint32_t *remSize, uint32_t *offset, uint32_t *outVal);

bool GetCmBlobFromBuffer(uint8_t *srcData, uint32_t *remSize, uint32_t *offset, struct CmBlob *outBlob);

bool GetCertListFromBuffer(uint8_t *srcData, uint32_t *remSize, uint32_t *offset, struct CertList *outList);

bool GetCertInfoFromBuffer(uint8_t *srcData, uint32_t *remSize, uint32_t *offset, struct CertInfo *outInfo);

bool CopyMyData(const uint8_t *data, const size_t size, const uint32_t minSize, uint8_t **myData);

bool ConstructParamSet(uint8_t *srcData, uint32_t *remainSize, uint32_t *offset,
    CertManagerInterfaceCode code, struct CmParamSet **paramSetOut);

bool IpcServiceApiFuzzerTest(const uint8_t *data, const size_t size, CertManagerInterfaceCode code,
    bool isParamsetToBlob, void (*ipcServiceApi)(const struct CmBlob *, struct CmBlob *, const struct CmContext *));
} // namespace CmFuzzTest
#endif /* CM_FUZZ_TEST_COMMON_H */
