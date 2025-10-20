/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef CM_ANI_UTILS_H
#define CM_ANI_UTILS_H

#include <string>
#include <map>
#include "cm_type.h"
#include "ani.h"

namespace OHOS::Security::CertManager::Ani {
namespace AniUtils {
bool IsUndefined(ani_env *env, ani_object object);

int32_t ParseUint8Array(ani_env *env, ani_arraybuffer uint8Array, CmBlob &outBlob);

int32_t ParseString(ani_env *env, ani_string ani_str, CmBlob &strBlob);

ani_string GenerateCharStr(ani_env *env, const char *strData, uint32_t length);

ani_string GenerateString(ani_env *env, CmBlob &outBlob);

int32_t GenerateNativeResult(ani_env *env, const int32_t code, const char *message,
    ani_object result, ani_object &resultObjOut);

int32_t CreateBooleanObject(ani_env *env, bool value, ani_object &resultObjOut);

int32_t GenerateCmResult(ani_env *env, ani_object &resultObjOut);

int32_t GenerateCredObj(ani_env *env, ani_string type, ani_string alias, ani_string keyUri, ani_object &resultObjOut);

int32_t GenerateCredArray(ani_env *env, CredentialAbstract *credentialAbstract, uint32_t credCount,
    ani_array &outArrayRef);

int32_t GenerateCredentialObj(ani_env *env, ani_object &resultObjOut);

int32_t GenerateUint8Array(ani_env *env, const CmBlob *data, ani_object &resultObjOut);

int32_t ParseSignatureSpec(ani_env *env, ani_object aniSpec, CmSignatureSpec *signatureSpec);

int32_t GenerateCMHandle(ani_env *env, const CmBlob *handleData, ani_object &resultObjOut);

int32_t GenerateCertObj(ani_env *env, CertAbstract *certAbstract, ani_object &resultObjOut);

int32_t GenerateCertArray(ani_env *env, CertAbstract *certAbstract, uint32_t certCount, ani_array &outArrayRef);

int32_t GenerateCertInfo(ani_env *env, ani_object &resultObjectOut);

int32_t SetObjStringProperty(ani_env *env, ani_object obj, const std::map<std::string, std::string> &valueMap);

int32_t GenerateBusinessError(ani_env *env, const int32_t errorCode, const char *message, ani_object &objectOut);
} // namespace AniUtils
} // namespace OHOS::Security::CertManager::Ani
#endif // CM_ANI_UTILS_H