/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "cm_openssl_rsa.h"
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_openssl_engine.h"
#include "cm_openssl_rsa.h"
#include "securec.h"

int32_t RsaSaveKeyMaterial(const RSA *rsa, const uint32_t keySize, struct CmBlob *key)
{
    const uint32_t keyByteLen = keySize / CM_BITS_PER_BYTE;
    const uint32_t rawMaterialLen = sizeof(struct KeyMaterialRsa) + keyByteLen * CM_RSA_KEYPAIR_CNT;
    uint8_t *rawMaterial = (uint8_t *)CmMalloc(rawMaterialLen);
    if (rawMaterial == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }

    (void)memset_s(rawMaterial, rawMaterialLen, 0, rawMaterialLen);

    struct KeyMaterialRsa *keyMaterial = (struct KeyMaterialRsa *)rawMaterial;
    keyMaterial->keyAlg = CM_ALG_RSA;
    keyMaterial->keySize = keySize;

    uint8_t tmpBuff[keyByteLen];
    if (memset_s(tmpBuff, keyByteLen, 0, keyByteLen) != EOK) {
        CmFree(rawMaterial);
        return CMR_ERROR_INVALID_OPERATION;
    }

    uint32_t offset = sizeof(*keyMaterial);
    keyMaterial->nSize = (uint32_t)BN_bn2bin(RSA_get0_n(rsa), tmpBuff);
    if (memcpy_s(rawMaterial + offset, keyByteLen, tmpBuff, keyMaterial->nSize) != EOK) {
        CmFree(rawMaterial);
        return CMR_ERROR_INVALID_OPERATION;
    }

    offset += keyMaterial->nSize;
    keyMaterial->eSize = (uint32_t)BN_bn2bin(RSA_get0_e(rsa), tmpBuff);
    if (memcpy_s(rawMaterial + offset, keyByteLen, tmpBuff, keyMaterial->eSize) != EOK) {
        CmFree(rawMaterial);
        return CMR_ERROR_INVALID_OPERATION;
    }

    offset += keyMaterial->eSize;
    keyMaterial->dSize = (uint32_t)BN_bn2bin(RSA_get0_d(rsa), tmpBuff);
    if (memcpy_s(rawMaterial + offset, keyByteLen, tmpBuff, keyMaterial->dSize) != EOK) {
        CmFree(rawMaterial);
        return CMR_ERROR_INVALID_OPERATION;
    }

    key->data = rawMaterial;
    key->size = sizeof(struct KeyMaterialRsa) + keyMaterial->nSize + keyMaterial->eSize + keyMaterial->dSize;

    return CM_SUCCESS;
}
