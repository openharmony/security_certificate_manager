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

#ifndef CERT_MANAGER_KEY_OPERATION_H
#define CERT_MANAGER_KEY_OPERATION_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

enum CmSignVerifyCmd {
    SIGN_VERIFY_CMD_UPDATE,
    SIGN_VERIFY_CMD_FINISH,
    SIGN_VERIFY_CMD_ABORT,
};

struct CmKeyProperties {
    uint32_t algType;
    uint32_t keySize;
    uint32_t padding;
    uint32_t digest;
    uint32_t purpose;
};

int32_t CmKeyOpGenMacKey(const struct CmBlob *alias);

int32_t CmKeyOpGenMacKeyIfNotExist(const struct CmBlob *alias);

int32_t CmKeyOpDeleteKey(const struct CmBlob *alias);

int32_t CmKeyOpCalcMac(const struct CmBlob *alias, const struct CmBlob *srcData, struct CmBlob *mac);

int32_t CmKeyOpImportKey(const struct CmBlob *alias, const struct CmKeyProperties *properties,
    const struct CmBlob *keyPair);

int32_t CmKeyOpInit(const struct CmContext *context, const struct CmBlob *alias, const struct CmSignatureSpec *spec,
    struct CmBlob *handle);

int32_t CmKeyOpProcess(enum CmSignVerifyCmd cmdId, const struct CmContext *context, const struct CmBlob *handle,
    const struct CmBlob *inData, struct CmBlob *outData);

#ifdef __cplusplus
}
#endif

#endif /* CERT_MANAGER_KEY_OPERATION_H */

