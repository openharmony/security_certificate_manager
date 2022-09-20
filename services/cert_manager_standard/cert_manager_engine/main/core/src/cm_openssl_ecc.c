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

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "cm_type.h"
#include "cm_config.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_openssl_engine.h"
#include "cm_openssl_ecc.h"
#include "securec.h"

static int32_t TransEccKeyToKeyBlob(
    const EC_KEY *eccKey, const struct KeyMaterialEcc *keyMaterial, BIGNUM *pubX, BIGNUM *pubY, uint8_t *rawMaterial)
{
    const EC_GROUP *ecGroup = EC_KEY_get0_group(eccKey);
    int retCode = EC_POINT_get_affine_coordinates_GFp(ecGroup, EC_KEY_get0_public_key(eccKey), pubX, pubY, NULL);
    if (retCode <= 0) {
        CM_LOG_E("EC_POINT_get_affine_coordinates_GFp failed");
        return CM_FAILURE;
    }

    const BIGNUM *priv = EC_KEY_get0_private_key(eccKey);
    uint32_t offset = sizeof(struct KeyMaterialEcc);

    retCode = BN_bn2binpad(pubX, rawMaterial + offset, keyMaterial->xSize);
    if (retCode <= 0) {
        CM_LOG_E("BN_bn2binpad pubX failed");
        return CM_FAILURE;
    }
    offset += keyMaterial->xSize;

    retCode = BN_bn2binpad(pubY, rawMaterial + offset, keyMaterial->ySize);
    if (retCode <= 0) {
        CM_LOG_E("BN_bn2binpad pubY failed");
        return CM_FAILURE;
    }
    offset += keyMaterial->ySize;

    retCode = BN_bn2binpad(priv, rawMaterial + offset, keyMaterial->zSize);
    if (retCode <= 0) {
        CM_LOG_E("BN_bn2binpad priv failed");
        return CM_FAILURE;
    }

    return CM_SUCCESS;
}

int32_t EccSaveKeyMaterial(const EC_KEY *eccKey, const struct CmKeySpec *spec,
    uint8_t **output, uint32_t *outputSize)
{
    uint32_t keySize = spec->keyLen;
    /* public exponent x and y, and private exponent, so need size is: keySize / 8 * 3 */
    uint32_t rawMaterialLen = sizeof(struct KeyMaterialEcc) + CM_KEY_BYTES(keySize) * ECC_KEYPAIR_CNT;
    uint8_t *rawMaterial = (uint8_t *)CmMalloc(rawMaterialLen);
    if (rawMaterial == NULL) {
        CM_LOG_E("malloc buffer failed!");
        return CMR_ERROR_MALLOC_FAIL;
    }

    (void)memset_s(rawMaterial, rawMaterialLen, 0, rawMaterialLen);

    /*
     * ECC key data internal struct:
     * struct KeyMaterialEcc + pubX_data + pubY_data + pri_data
     */
    struct KeyMaterialEcc *keyMaterial = (struct KeyMaterialEcc *)rawMaterial;
    keyMaterial->keyAlg = (enum CmKeyAlg)spec->algType;
    keyMaterial->keySize = keySize;
    keyMaterial->xSize = CM_KEY_BYTES(keySize);
    keyMaterial->ySize = CM_KEY_BYTES(keySize);
    keyMaterial->zSize = CM_KEY_BYTES(keySize);

    BIGNUM *pubX = BN_new();
    BIGNUM *pubY = BN_new();

    int32_t ret;
    do {
        if ((pubX == NULL) || (pubY == NULL)) {
            CM_LOG_E("BN_new x or y failed");
            ret = CMR_ERROR_NULL_POINTER;
            CmFree(rawMaterial);
            break;
        }
        ret = TransEccKeyToKeyBlob(eccKey, keyMaterial, pubX, pubY, rawMaterial);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("transfer ecc key to key blob failed");
            CmFree(rawMaterial);
            break;
        }
        *output = rawMaterial;
        *outputSize = rawMaterialLen;
    } while (0);

    if (pubX != NULL) {
        BN_free(pubX);
        pubX = NULL;
    }
    if (pubY != NULL) {
        BN_free(pubY);
        pubY = NULL;
    }
    return ret;
}
