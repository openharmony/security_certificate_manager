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

#ifndef CM_OPENSSL_CURVE25519_H
#define CM_OPENSSL_CURVE25519_H

#include <openssl/evp.h>
#include "cm_type.h"
#include "cm_openssl_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CURVE25519_KEY_LEN 32
#define CURVE25519_KEY_BITS 256

struct KeyMaterial25519 {
    enum CmKeyAlg keyAlg;
    uint32_t keySize;
    uint32_t pubKeySize;
    uint32_t priKeySize;
    uint32_t reserved;
};


int32_t SaveCurve25519KeyMaterial(uint32_t algType, const EVP_PKEY *pKey, struct CmBlob *keyOut);

#ifdef __cplusplus
}
#endif

#endif /* HKS_OPENSSL_CURVE25519_H */
