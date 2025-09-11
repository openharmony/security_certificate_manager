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

#include "cm_ani_utils.h"

#include "cm_log.h"
#include "cm_mem.h"
#include "securec.h"
#include "cm_api_common.h"
#include "cm_ani_common.h"

namespace OHOS::Security::CertManager::Ani {
namespace AniUtils {
const char *ETS_CTOR = "<ctor>";
const char *NATIVE_RESULT_CLASS = "@ohos.security.certManager.NativeResult";
const char *CALLBACK_WRAPPER_CLASS = "@ohos.security.certManagerDialog.AsyncCallbackWrapper";
const char *BUSINESS_ERROR_CLASS = "@ohos.base.BusinessError";
const char *CM_RESULT_CLASS = "@ohos.security.certManager.CMResultClass";
const char *CRED_ABSTRACT_CLASS = "@ohos.security.certManager.CredentialAbstractClass";
const char *CREDENTIAL_CLASS = "@ohos.security.certManager.CredentialClass";
const char *CERT_ABSTRACT_CLASS = "@ohos.security.certManager.CertAbstractClass";
const char *CERT_INFO_CLASS = "@ohos.security.certManager.CertInfoClass";
const char *UINT8_ARRAY_CLASS = "escompat.Uint8Array";
const char *KEY_PURPOSE_ENUM = "@ohos.security.certManager.certificateManager.CmKeyPurpose";
const char *KEY_PADDING_ENUM = "@ohos.security.certManager.certificateManager.CmKeyPadding";
const char *KEY_DIGEST_ENUM = "@ohos.security.certManager.certificateManager.CmKeyDigest";
const char *CM_HANDLE_CLASS = "@ohos.security.certManager.CMHandleClass";
const char *BOOLEAN_CLASS = "std.core.Boolean";

bool IsUndefined(ani_env *env, ani_object object)
{
    ani_boolean isUndefined;
    ani_status status = env->Reference_IsUndefined(object, &isUndefined);
    if (status != ANI_OK) {
        CM_LOG_E("check ref is undefined failed.");
        return true;
    }
    return (bool)isUndefined;
}

int32_t ParseUint8Array(ani_env *env, ani_arraybuffer uint8Array, CmBlob &outBlob)
{
    if (env == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }
    bool isUndefined = IsUndefined(env, uint8Array);
    if (isUndefined) {
        CM_LOG_E("check uint8Array is undefined");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    
    void* resultData;
    ani_size resultSize;
    ani_status ret = env->ArrayBuffer_GetInfo(uint8Array, &resultData, &resultSize);
    if (ret != ANI_OK) {
        CM_LOG_E("get ani uint8Array buffer failed, ret = %d", static_cast<int32_t>(ret));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    outBlob.data = static_cast<uint8_t *>(resultData);
    outBlob.size = resultSize;
    return CM_SUCCESS;
}

int32_t ParseString(ani_env *env, ani_string ani_str, CmBlob &outBlob)
{
    if (env == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }
    ani_size strSize;
    ani_status ret = env->String_GetUTF8Size(ani_str, &strSize);
    if (ret != ANI_OK) {
        CM_LOG_E("get ani string size failed, ret = %d", static_cast<int32_t>(ret));
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    char *strData = static_cast<char *>(CmMalloc(strSize + 1));
    if (strData == nullptr) {
        CM_LOG_E("memory operation failed.");
        return CMR_ERROR_MALLOC_FAIL;
    }

    ani_size bytes_written = 0;
    ret = env->String_GetUTF8(ani_str, strData, strSize + 1, &bytes_written);
    if (ret != ANI_OK) {
        CM_LOG_E("get ani string, ret = %d", static_cast<int32_t>(ret));
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    strData[bytes_written] = '\0';
    outBlob.data = (uint8_t *)strData;
    outBlob.size = strSize + 1;
    return CM_SUCCESS;
}

ani_string GenerateCharStr(ani_env *env, const char *strData, uint32_t length)
{
    if (env == nullptr) {
        CM_LOG_E("env is nullptr.");
        return nullptr;
    }
    ani_string aniString{};
    ani_status ret = env->String_NewUTF8(strData, length, &aniString);
    if (ret != ANI_OK) {
        CM_LOG_E("generate ani string failed, ret = %d", static_cast<int32_t>(ret));
        return nullptr;
    }
    return aniString;
}

ani_string GenerateString(ani_env *env, CmBlob &outBlob)
{
    return GenerateCharStr(env, (char *)outBlob.data, outBlob.size - 1);
}

int32_t CreateBooleanObject(ani_env *env, bool value, ani_object &resultObjOut)
{
    if (env == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }
    ani_class cls;
    if (env->FindClass(BOOLEAN_CLASS, &cls) != ANI_OK) {
        CM_LOG_E("find class failed, class %s not found.", BOOLEAN_CLASS);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    ani_method ctor;
    if (env->Class_FindMethod(cls, ETS_CTOR, "z:", &ctor) != ANI_OK) {
        CM_LOG_E("find class method failed, method %s not found.", ETS_CTOR);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (env->Object_New(cls, ctor, &resultObjOut) != ANI_OK) {
        CM_LOG_E("create %s object failed.", BOOLEAN_CLASS);
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

static int32_t CreateResultObject(ani_env *env, ani_object &resultObjOut, const char *mangling)
{
    if (env == nullptr || mangling == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }
    ani_class cls;
    if (env->FindClass(mangling, &cls) != ANI_OK) {
        CM_LOG_E("find class failed, class %s not found.", mangling);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    ani_method ctor;
    if (env->Class_FindMethod(cls, ETS_CTOR, ":V", &ctor) != ANI_OK) {
        CM_LOG_E("find class method failed, method %s not found.", ETS_CTOR);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (env->Object_New(cls, ctor, &resultObjOut) != ANI_OK) {
        CM_LOG_E("create %s object failed.", mangling);
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t GenerateNativeResult(ani_env *env, const int32_t code, const char *message,
    ani_object result, ani_object &resultObjOut)
{
    if (env == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }
    if (CreateResultObject(env, resultObjOut, NATIVE_RESULT_CLASS) != CM_SUCCESS) {
        CM_LOG_E("create native result object failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (env->Object_SetFieldByName_Int(resultObjOut, "code", (ani_int)code) != ANI_OK) {
        CM_LOG_E("Object_SetFieldByName_Int Failed result");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (message != nullptr) {
        ani_string resultMessage;
        env->String_NewUTF8(message, strlen(message), &resultMessage);
        ani_status status = env->Object_SetFieldByName_Ref(resultObjOut, "message", resultMessage);
        if (status != ANI_OK) {
            CM_LOG_E("Object_SetFieldByName_Ref Failed message");
            return CMR_ERROR_INVALID_ARGUMENT;
        }
    }

    if (result != nullptr) {
        ani_status status = env->Object_SetFieldByName_Ref(resultObjOut, "result", result);
        if (status != ANI_OK) {
            CM_LOG_E("Object_SetFieldByName_Ref Failed result");
            return CMR_ERROR_INVALID_ARGUMENT;
        }
    }
    return CM_SUCCESS;
}

int32_t GenerateCmResult(ani_env *env, ani_object &resultObjOut)
{
    if (env == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }
    if (CreateResultObject(env, resultObjOut, CM_RESULT_CLASS) != CM_SUCCESS) {
        CM_LOG_E("create cmResult object failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t GenerateCredObj(ani_env *env, ani_string type, ani_string alias, ani_string keyUri, ani_object &resultObjOut)
{
    if (env == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }
    if (CreateResultObject(env, resultObjOut, CRED_ABSTRACT_CLASS) != CM_SUCCESS) {
        CM_LOG_E("create credAbstract object object failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    ani_status status = env->Object_SetPropertyByName_Ref(resultObjOut, "type", type);
    if (status != ANI_OK) {
        CM_LOG_E("cmRcredAbstractesult set field type failed. ret = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    status = env->Object_SetPropertyByName_Ref(resultObjOut, "alias", alias);
    if (status != ANI_OK) {
        CM_LOG_E("cmRcredAbstractesult set field alias failed. ret = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    status = env->Object_SetPropertyByName_Ref(resultObjOut, "keyUri", keyUri);
    if (status != ANI_OK) {
        CM_LOG_E("cmRcredAbstractesult set field keyUri failed. ret = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t GenerateCredArray(ani_env *env, CredentialAbstract *credentialAbstract, uint32_t credCount,
    ani_array &outArrayRef)
{
    if (env == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }

    ani_ref undefinedRef;
    env->GetUndefined(&undefinedRef);
    ani_array resultArray;
    env->Array_New(credCount, undefinedRef, &resultArray);
    for (uint32_t i = 0; i < credCount; i++) {
        ani_string aniCredType{};
        ani_string aniCredAlias{};
        ani_string aniCredKeyUri{};
        env->String_NewUTF8(credentialAbstract[i].type, strlen(credentialAbstract[i].type), &aniCredType);
        env->String_NewUTF8(credentialAbstract[i].alias, strlen(credentialAbstract[i].alias), &aniCredAlias);
        env->String_NewUTF8(credentialAbstract[i].keyUri, strlen(credentialAbstract[i].keyUri), &aniCredKeyUri);

        ani_object credAbstractObj{};
        int32_t ret = GenerateCredObj(env, aniCredType, aniCredAlias, aniCredKeyUri, credAbstractObj);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("generate cred object failed. ret = %d", ret);
            return CMR_ERROR_INVALID_ARGUMENT;
        }
        if (env->Array_Set(resultArray, i, credAbstractObj) != ANI_OK) {
            CM_LOG_E("credArray setRef failed.");
            return CMR_ERROR_INVALID_ARGUMENT;
        }
    }
    outArrayRef = resultArray;
    return CM_SUCCESS;
}

int32_t GenerateCredentialObj(ani_env *env, ani_object &resultObjOut)
{
    if (env == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }
    if (CreateResultObject(env, resultObjOut, CREDENTIAL_CLASS) != CM_SUCCESS) {
        CM_LOG_E("create credential object failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t GenerateUint8Array(ani_env *env, const CmBlob *data, ani_object &resultObjOut)
{
    if (env == nullptr || data == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }
    ani_class uint8ArrayClass;
    if (env->FindClass(UINT8_ARRAY_CLASS, &uint8ArrayClass) != ANI_OK) {
        CM_LOG_E("find class failed, class %s not found.", UINT8_ARRAY_CLASS);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    ani_method ctor;
    if (env->Class_FindMethod(uint8ArrayClass, ETS_CTOR, "i:", &ctor) != ANI_OK) {
        CM_LOG_E("find class method failed, method %s not found.", ETS_CTOR);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (env->Object_New(uint8ArrayClass, ctor, &resultObjOut, data->size) != ANI_OK) {
        CM_LOG_E("create %s object failed.", UINT8_ARRAY_CLASS);
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    ani_ref buffer;
    env->Object_GetFieldByName_Ref(resultObjOut, "buffer", &buffer);
    void *bufferPtr = nullptr;
    size_t bufferLength;
    if (env->ArrayBuffer_GetInfo(static_cast<ani_arraybuffer>(buffer), &bufferPtr, &bufferLength) != ANI_OK) {
        CM_LOG_E("get buffer ref failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (memcpy_s(bufferPtr, bufferLength, data->data, data->size) != EOK) {
        CM_LOG_E("unit8array buffer memcpy failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

static int32_t GetPurposeEnumValue(ani_env *env, ani_object aniSpec, uint32_t *value)
{
    ani_enum purposeEnum;
    env->FindEnum(KEY_PURPOSE_ENUM, &purposeEnum);
    ani_enum_item purpose;
    if (env->Object_GetPropertyByName_Ref(aniSpec, "purpose", (ani_ref *)&purpose) != ANI_OK) {
        CM_LOG_E("get purpose enumItem failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (env->EnumItem_GetValue_Int(purpose, (ani_int *)value) != ANI_OK) {
        CM_LOG_E("get purposeEnum value failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

static int32_t GetPaddingEnumValue(ani_env *env, ani_object aniSpec, uint32_t *value)
{
    ani_enum paddingEnum;
    env->FindEnum(KEY_PADDING_ENUM, &paddingEnum);
    ani_enum_item padding;
    if (env->Object_GetPropertyByName_Ref(aniSpec, "padding", (ani_ref *)&padding) != ANI_OK) {
        CM_LOG_E("get padding prop failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (IsUndefined(env, padding)) {
        CM_LOG_D("padding prop is undefined, set default value.");
        *value = CM_PADDING_PSS;
        return CM_SUCCESS;
    }
    if (env->EnumItem_GetValue_Int(padding, (ani_int *)value) != ANI_OK) {
        CM_LOG_E("get paddingEnum value failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    for (uint32_t i = 0; i < (sizeof(PADDING_MAP) / sizeof(PADDING_MAP[0])); i++) {
        if (*value == PADDING_MAP[i].key) {
            *value = PADDING_MAP[i].retPadding;
            return CM_SUCCESS;
        }
    }
    CM_LOG_E("padding do not exist in PADDING_MAP.");
    return CMR_ERROR_INVALID_ARGUMENT;
}

static int32_t GetDigestEnumValue(ani_env *env, ani_object aniSpec, uint32_t *value)
{
    ani_enum digestEnum;
    env->FindEnum(KEY_DIGEST_ENUM, &digestEnum);
    ani_enum_item digest;
    if (env->Object_GetPropertyByName_Ref(aniSpec, "digest", (ani_ref *)&digest) != ANI_OK) {
        CM_LOG_E("get digest prop failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (IsUndefined(env, digest)) {
        CM_LOG_D("digest prop is undefined, set default value.");
        *value = CM_DIGEST_SHA256;
        return CM_SUCCESS;
    }
    if (env->EnumItem_GetValue_Int(digest, (ani_int *)value) != ANI_OK) {
        CM_LOG_E("get digestEnum value failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    for (uint32_t i = 0; i < (sizeof(DIGEST_MAP) / sizeof(DIGEST_MAP[0])); i++) {
        if (*value == DIGEST_MAP[i].key) {
            *value = DIGEST_MAP[i].retDigest;
            return CM_SUCCESS;
        }
    }
    CM_LOG_E("digest do not exist in DIGEST_MAP.");
    return CMR_ERROR_INVALID_ARGUMENT;
}

int32_t ParseSignatureSpec(ani_env *env, ani_object aniSpec, CmSignatureSpec *signatureSpec)
{
    if (env == nullptr || signatureSpec == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }
    int32_t ret = GetPurposeEnumValue(env, aniSpec, &signatureSpec->purpose);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get signatureSpec purpose failed.");
        return ret;
    }
    ret = GetPaddingEnumValue(env, aniSpec, &signatureSpec->padding);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get signatureSpec padding failed.");
        return ret;
    }
    ret = GetDigestEnumValue(env, aniSpec, &signatureSpec->digest);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get signatureSpec digest failed.");
        return ret;
    }
    return CM_SUCCESS;
}

int32_t GenerateCMHandle(ani_env *env, const CmBlob *handleData, ani_object &resultObjOut)
{
    if (env == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }
    if (CreateResultObject(env, resultObjOut, CM_HANDLE_CLASS) != CM_SUCCESS) {
        CM_LOG_E("create cmHandle object failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    ani_object handleUint8Array;
    int32_t ret = GenerateUint8Array(env, handleData, handleUint8Array);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("create cmHandle uint8Array failed.");
        return ret;
    }
    if (env->Object_SetPropertyByName_Ref(resultObjOut, "handle", handleUint8Array) != ANI_OK) {
        CM_LOG_E("cmHandle set property handle failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t GenerateCertObj(ani_env *env, CertAbstract *certAbstract, ani_object &resultObjOut)
{
    if (env == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }
    if (CreateResultObject(env, resultObjOut, CERT_ABSTRACT_CLASS) != CM_SUCCESS) {
        CM_LOG_E("create certAbstract object object failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    ani_string uri{};
    ani_string certAlias{};
    ani_string subjectName{};
    env->String_NewUTF8(certAbstract->uri, strlen(certAbstract->uri), &uri);
    env->String_NewUTF8(certAbstract->certAlias, strlen(certAbstract->certAlias), &certAlias);
    env->String_NewUTF8(certAbstract->subjectName, strlen(certAbstract->subjectName), &subjectName);

    ani_status status = env->Object_SetPropertyByName_Ref(resultObjOut, "uri", uri);
    if (status != ANI_OK) {
        CM_LOG_E("cmCertAbstractesult set field uri failed. ret = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    status = env->Object_SetPropertyByName_Ref(resultObjOut, "certAlias", certAlias);
    if (status != ANI_OK) {
        CM_LOG_E("cmCertAbstractesult set field certAlias failed. ret = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    status = env->Object_SetPropertyByName_Ref(resultObjOut, "subjectName", subjectName);
    if (status != ANI_OK) {
        CM_LOG_E("cmCertAbstractesult set field subjectName failed. ret = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    status = env->Object_SetPropertyByName_Boolean(resultObjOut, "state",
        static_cast<ani_boolean>(certAbstract->status));
    if (status != ANI_OK) {
        CM_LOG_E("cmCertAbstractesult set field state failed. ret = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t GenerateCertArray(ani_env *env, CertAbstract *certAbstract, uint32_t certCount, ani_array &outArrayRef)
{
    if (env == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }

    ani_ref undefinedRef;
    env->GetUndefined(&undefinedRef);
    ani_array resultArray;
    env->Array_New(certCount, undefinedRef, &resultArray);
    for (uint32_t i = 0; i < certCount; i++) {
        ani_object certAbstractObj{};
        int32_t ret = GenerateCertObj(env, &certAbstract[i], certAbstractObj);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("generate cert object failed. ret = %d", ret);
            return CMR_ERROR_INVALID_ARGUMENT;
        }
        if (env->Array_Set(resultArray, i, certAbstractObj) != ANI_OK) {
            CM_LOG_E("certArray setRef failed.");
            return CMR_ERROR_INVALID_ARGUMENT;
        }
    }
    outArrayRef = resultArray;
    return CM_SUCCESS;
}

int32_t GenerateCertInfo(ani_env *env, ani_object &resultObjOut)
{
    if (env == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }
    if (CreateResultObject(env, resultObjOut, CERT_INFO_CLASS) != CM_SUCCESS) {
        CM_LOG_E("create certInfo object failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t SetObjStringProperty(ani_env *env, ani_object obj, std::map<std::string, std::string> valueMap)
{
    if (env == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }
    ani_status status;
    for (auto it = valueMap.begin(); it != valueMap.end(); ++it) {
        ani_string strObj = GenerateCharStr(env, it->second.c_str(), it->second.size());
        if (strObj == nullptr) {
            CM_LOG_E("generate string property %s obj failed", it->first.c_str());
            return CMR_ERROR_INVALID_ARGUMENT;
        }
        status = env->Object_SetPropertyByName_Ref(obj, it->first.c_str(), strObj);
        if (status != ANI_OK) {
            CM_LOG_E("set propterty %s failed。", it->first.c_str());
            return CMR_ERROR_INVALID_ARGUMENT;
        }
    }
    return CM_SUCCESS;
}

int32_t GenerateBusinessError(ani_env *env, const int32_t errorCode, const char *message, ani_object &objectOut)
{
    if (env == nullptr) {
        CM_LOG_E("env is nullptr.");
        return CMR_ERROR_NULL_POINTER;
    }

    if (CreateResultObject(env, objectOut, BUSINESS_ERROR_CLASS) != CM_SUCCESS) {
        CM_LOG_E("create businessError object failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (env->Object_SetFieldByName_Double(objectOut, "code", static_cast<ani_double>(errorCode)) != ANI_OK) {
        CM_LOG_E("set businessError field code error");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    ani_string errMsg = GenerateCharStr(env, message, strlen(message));
    if (errMsg == nullptr) {
        CM_LOG_D("errMsg is nullptr");
        return CM_SUCCESS;
    }

    if (env->Object_SetPropertyByName_Ref(objectOut, "message", static_cast<ani_ref>(errMsg)) != ANI_OK) {
        CM_LOG_E("set businessError field message error");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}
} // namespace AniUtils
} // namespace OHOS::Security::CertManager::Ani