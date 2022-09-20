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

#ifndef CM_OPENSSL_RSA_H
#define CM_OPENSSL_RSA_H

#include <openssl/rsa.h>
#include "cm_type.h"
#include "cm_openssl_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CM_RSA_KEYPAIR_CNT 3

struct KeyMaterialRsa {
    enum CmKeyAlg keyAlg;
    uint32_t keySize;
    uint32_t nSize;
    uint32_t eSize;
    uint32_t dSize;
};

int32_t RsaSaveKeyMaterial(const RSA *rsa, const uint32_t keySize, struct CmBlob *key);

#ifdef __cplusplus
}
#endif

#endif
