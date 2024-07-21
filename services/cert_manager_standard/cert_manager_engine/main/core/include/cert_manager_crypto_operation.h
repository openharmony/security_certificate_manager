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

#ifndef CERT_MANAGER_CRYPTO_OPERATION_H
#define CERT_MANAGER_CRYPTO_OPERATION_H

#include "cm_type.h"

#define DIGEST_SHA256_LEN           32
#define MAX_LEN_BASE64URL_SHA256    64

#ifdef __cplusplus
extern "C" {
#endif

int32_t GetNameEncode(const struct CmBlob *inBlob, struct CmBlob *outBlob);

int32_t GetEncodeIfLenUp64(const struct CmBlob *inData, struct CmBlob *outData);

int32_t CmGetRandom(struct CmBlob *random);

int32_t CmGetHash(const struct CmBlob *inData, struct CmBlob *hash);

#ifdef __cplusplus
}
#endif

#endif /* CERT_MANAGER_CRYPTO_OPERATION_H */

