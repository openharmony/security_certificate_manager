/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef CM_OPENSSL_ECC_H
#define CM_OPENSSL_ECC_H

#include <openssl/evp.h>
#include <openssl/ec.h>
#include "cm_type.h"
#include "cm_openssl_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ECC_KEYPAIR_CNT 3

struct KeyMaterialEcc {
    enum CmKeyAlg keyAlg;
    uint32_t keySize;
    uint32_t xSize;
    uint32_t ySize;
    uint32_t zSize;
};

int32_t EccSaveKeyMaterial(const EC_KEY *eccKey, const struct CmKeySpec *spec,
    uint8_t **output, uint32_t *outputSize);

#ifdef __cplusplus
}
#endif

#endif
