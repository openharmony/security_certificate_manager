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

#include "cm_fuzz_test_common.h"

namespace CmFuzzTest {
bool GetUintFromBuffer(uint8_t *srcData, uint32_t *remSize, uint32_t *offset, uint32_t *outVal)
{
    if (*remSize < sizeof(uint32_t)) {
        return false;
    }

    *outVal = *(reinterpret_cast<uint32_t *>(srcData + *offset));
    *remSize -= sizeof(uint32_t);
    *offset += sizeof(uint32_t);

    return true;
}

bool GetCmBlobFromBuffer(uint8_t *srcData, uint32_t *remSize, uint32_t *offset, struct CmBlob *outBlob)
{
    if (GetUintFromBuffer(srcData, remSize, offset, &(outBlob->size)) != true) {
        return false;
    }

    if (*remSize < outBlob->size) {
        return false;
    }
    outBlob->data = srcData + *offset;
    *remSize -= outBlob->size;
    *offset += outBlob->size;

    return true;
}

bool GetCertListFromBuffer(uint8_t *srcData, uint32_t *remSize, uint32_t *offset, struct CertList *outList)
{
    if (GetUintFromBuffer(srcData, remSize, offset, &(outList->certsCount)) != true) {
        return false;
    }

    if (outList->certsCount > (*remSize / sizeof(struct CertAbstract))) {
        return false;
    }
    outList->certAbstract = reinterpret_cast<struct CertAbstract *>(srcData + *offset);

    return true;
}

bool GetCertInfoFromBuffer(uint8_t *srcData, uint32_t *remSize, uint32_t *offset, struct CertInfo *outInfo)
{
    if (*remSize < sizeof(struct CertInfo)) {
        return false;
    }

    outInfo = reinterpret_cast<struct CertInfo *>(srcData + *offset);
    *remSize -= sizeof(struct CertInfo);
    *offset += sizeof(struct CertInfo);

    if (*remSize < outInfo->certInfo.size) {
        return false;
    }

    outInfo->certInfo.data = const_cast<uint8_t *>(srcData + *offset);
    return true;
}

bool CopyMyData(const uint8_t *data, const size_t size, const uint32_t minSize, uint8_t **myData)
{
    if (data == nullptr|| static_cast<uint32_t>(size) < minSize) {
        return false;
    }

    uint8_t *tempData = static_cast<uint8_t *>(CmMalloc(sizeof(uint8_t) * size));
    if (tempData == nullptr) {
        return false;
    }
    (void)memcpy_s(tempData, size, data, size);

    *myData = tempData;
    return true;
}
}