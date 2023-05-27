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

#include "cert_manager_crypto_operation.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "securec.h"

#include "cm_log.h"
#include "cm_type.h"

#define DIGEST_SHA256_LEN 32

int32_t CmGetRandom(struct CmBlob *random)
{
    if (CmCheckBlob(random) != CM_SUCCESS) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int ret = RAND_bytes(random->data, random->size);
    if (ret <= 0) {
        CM_LOG_E("Get random failed");
        return CMR_ERROR_KEY_OPERATION_FAILED;
    }

    return CM_SUCCESS;
}

int32_t CmGetHash(const struct CmBlob *inData, struct CmBlob *hash)
{
    if ((CmCheckBlob(inData) != CM_SUCCESS) || (CmCheckBlob(hash) != CM_SUCCESS) ||
        (hash->size < DIGEST_SHA256_LEN)) {
        CM_LOG_E("invalid input args");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    const EVP_MD *opensslAlg = EVP_sha256();
    if (opensslAlg == NULL) {
        CM_LOG_E("get openssl alg failed");
        return CMR_ERROR_KEY_OPERATION_FAILED;
    }

    int32_t ret = EVP_Digest(inData->data, inData->size, hash->data, &hash->size, opensslAlg, NULL);
    if (ret <= 0) {
        CM_LOG_E("digest failed");
        return CMR_ERROR_KEY_OPERATION_FAILED;
    }
    return CM_SUCCESS;
}

