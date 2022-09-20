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

#include <openssl/evp.h>
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_openssl_engine.h"
#include "cm_openssl_curve25519.h"

#define CM_OPENSSL_SUCCESS    1     /* openssl return 1: success */

int32_t SaveCurve25519KeyMaterial(uint32_t algType, const EVP_PKEY *pKey, struct CmBlob *keyOut)
{
    uint32_t totalSize = sizeof(struct KeyMaterial25519) + (CURVE25519_KEY_LEN << 1);
    uint8_t *buffer = (uint8_t *)CmMalloc(totalSize);
    if (buffer == NULL) {
        CM_LOG_E("malloc size %u failed", totalSize);
        return CMR_ERROR_MALLOC_FAIL;
    }

    size_t tmpPubKeyLen = CURVE25519_KEY_LEN;
    size_t tmpPriKeyLen = CURVE25519_KEY_LEN;
    uint32_t offset = sizeof(struct KeyMaterial25519);

    if (EVP_PKEY_get_raw_public_key(pKey, buffer + offset, &tmpPubKeyLen) != CM_OPENSSL_SUCCESS) {
        CM_LOG_E("EVP_PKEY_get_raw_public_key failed");
        CmFree(buffer);
        return CMR_ERROR_INVALID_OPERATION;
    }
    uint32_t pubKeyLen = (uint32_t)tmpPubKeyLen;

    offset += pubKeyLen;
    if (EVP_PKEY_get_raw_private_key(pKey, buffer + offset, &tmpPriKeyLen) != CM_OPENSSL_SUCCESS) {
        CM_LOG_E("EVP_PKEY_get_raw_private_key");
        CmFree(buffer);
        return CMR_ERROR_INVALID_OPERATION;
    }
    uint32_t priKeyLen = (uint32_t)tmpPriKeyLen;

    struct KeyMaterial25519 *keyMaterial = (struct KeyMaterial25519 *)buffer;
    keyMaterial->keyAlg = algType;
    keyMaterial->keySize = CURVE25519_KEY_BITS;
    keyMaterial->pubKeySize = pubKeyLen;
    keyMaterial->priKeySize = priKeyLen;

    keyOut->data = buffer;
    keyOut->size = totalSize;
    return CM_SUCCESS;
}