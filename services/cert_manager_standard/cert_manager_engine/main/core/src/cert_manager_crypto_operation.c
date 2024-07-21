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

#define BYTE_SHIFT_10           0x10
#define BYTE_SHIFT_8            0x08
#define BYTE_SHIFT_6            6
#define BASE64_URL_TABLE_SIZE   0x3F
#define BASE64_BITS_PER_OCTET   6
#define BYTE_LEN                8
#define BASE64_CARRY_SIZE       5
#define BYTE_INDEX_ZONE         0
#define BYTE_INDEX_ONE          1
#define BYTE_INDEX_TWO          2
#define BYTE_INDEX_THREE        3

static int32_t Base64UrlEncode(const struct CmBlob *indata, struct CmBlob *uriHash)
{
    if ((indata == NULL) || (uriHash == NULL)) {
        CM_LOG_E("input param is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    char base64UrlTable[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    int outputLen = (indata->size * BYTE_LEN + BASE64_CARRY_SIZE) / BASE64_BITS_PER_OCTET;
    uriHash->size = outputLen + 1;
    uriHash->data[outputLen] = '\0';
    int i;
    int j;
    for (i = 0, j = 0; i < indata->size;) {
        unsigned int octeta = i < indata->size ? *(indata->data + (i++)) : 0;
        unsigned int octetb = i < indata->size ? *(indata->data + (i++)) : 0;
        unsigned int octetc = i < indata->size ? *(indata->data + (i++)) : 0;

        unsigned int triple = (octeta << BYTE_SHIFT_10) + (octetb << BYTE_SHIFT_8) + octetc;

        uriHash->data[j++] = base64UrlTable[(triple >> BYTE_INDEX_THREE * BYTE_SHIFT_6) & BASE64_URL_TABLE_SIZE];
        uriHash->data[j++] = base64UrlTable[(triple >> BYTE_INDEX_TWO   * BYTE_SHIFT_6) & BASE64_URL_TABLE_SIZE];
        uriHash->data[j++] = base64UrlTable[(triple >> BYTE_INDEX_ONE   * BYTE_SHIFT_6) & BASE64_URL_TABLE_SIZE];
        uriHash->data[j++] = base64UrlTable[(triple >> BYTE_INDEX_ZONE  * BYTE_SHIFT_6) & BASE64_URL_TABLE_SIZE];
    }
    return CM_SUCCESS;
}

int32_t GetNameEncode(const struct CmBlob *inBlob, struct CmBlob *outBlob)
{
    if ((inBlob == NULL) || (outBlob == NULL)) {
        CM_LOG_E("input param is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    uint8_t tempBuf[DIGEST_SHA256_LEN] = {0};
    struct CmBlob inDigest = { DIGEST_SHA256_LEN, tempBuf };
    int32_t ret = CM_SUCCESS;
    do {
        ret = CmGetHash(inBlob, &inDigest);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmGetHash fail, ret = %d", ret);
            break;
        }
        ret = Base64UrlEncode(&inDigest, outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Base64UrlEncode fail, ret = %d", ret);
            break;
        }
    } while (0);
    return ret;
}

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

