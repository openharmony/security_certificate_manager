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

#ifndef CM_OPENSSL_ENGINE_H
#define CM_OPENSSL_ENGINE_H

#include <openssl/rsa.h>
#include "cm_type.h"
#include "cm_openssl_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

enum CmKeyAlg {
    CM_ALG_RSA = 1,
    CM_ALG_ECC = 2,

    CM_ALG_AES = 20,
    CM_ALG_HMAC = 50,
    CM_ALG_HKDF = 51,
    CM_ALG_PBKDF2 = 52,

    CM_ALG_ECDH = 100,
    CM_ALG_X25519 = 101,
    CM_ALG_ED25519 = 102,

    CM_ALG_SM2 = 150,
    CM_ALG_SM3 = 151,
    CM_ALG_SM4 = 152,
};

#ifdef __cplusplus
}
#endif

#endif
