/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "cm_napi_dialog_common.h"

#include <unordered_map>
#include "securec.h"

#include "cm_log.h"
#include "cm_type.h"

namespace CMNapi {
namespace {
constexpr int CM_MAX_DATA_LEN = 0x6400000; // The maximum length is 100M

static const std::string DIALOG_NO_PERMISSION_MSG = "the caller has no permission";
static const std::string DIALOG_INVALID_PARAMS_MSG = "the input parameters is invalid";
static const std::string DIALOG_GENERIC_MSG = "there is an internal error";

static const std::unordered_map<int32_t, int32_t> DIALOG_CODE_TO_JS_CODE_MAP = {
    // invalid params
    { CMR_DIALOG_ERROR_INVALID_ARGUMENT, PARAM_ERROR },
    // no permission
    { CMR_DIALOG_ERROR_PERMISSION_DENIED, HAS_NO_PERMISSION },
    // internal error
    { CMR_DIALOG_ERROR_INTERNAL, DIALOG_ERROR_GENERIC },
};

static const std::unordered_map<int32_t, std::string> DIALOG_CODE_TO_MSG_MAP = {
    { CMR_DIALOG_ERROR_INVALID_ARGUMENT, DIALOG_INVALID_PARAMS_MSG },
    { CMR_DIALOG_ERROR_PERMISSION_DENIED, DIALOG_NO_PERMISSION_MSG },
    { CMR_DIALOG_ERROR_INTERNAL, DIALOG_GENERIC_MSG },
};
}  // namespace

napi_value ParseUint32(napi_env env, napi_value object, uint32_t &store)
{
    napi_valuetype type;
    napi_typeof(env, object, &type);
    if (type != napi_number) {
        CM_LOG_E("param type is not number");
        return nullptr;
    }
    uint32_t temp = 0;
    napi_get_value_uint32(env, object, &temp);
    store = temp;
    return GetInt32(env, 0);
}

napi_value ParseBoolean(napi_env env, napi_value object, bool &status)
{
    napi_valuetype type;
    napi_typeof(env, object, &type);
    if (type != napi_boolean) {
        CM_LOG_E("param type is not bool");
        return nullptr;
    }
    bool temp = false;
    napi_get_value_bool(env, object, &temp);
    status = temp;
    return GetInt32(env, 0);
}

napi_value ParseString(napi_env env, napi_value obj, CmBlob *&blob)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, obj, &type));
    if (type != napi_string) {
        CM_LOG_E("the type of param is not string");
        return nullptr;
    }
    size_t length = 0;
    napi_status status = napi_get_value_string_utf8(env, obj, nullptr, 0, &length);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        CM_LOG_E("could not get string length");
        return nullptr;
    }

    // add 0 length check
    if ((length == 0) || (length > CM_MAX_DATA_LEN)) {
        CM_LOG_E("input string length is 0 or too large, length: %d", length);
        return nullptr;
    }

    char *data = static_cast<char *>(CmMalloc(length + 1));
    if (data == nullptr) {
        napi_throw_error(env, nullptr, "could not alloc memory");
        CM_LOG_E("could not alloc memory");
        return nullptr;
    }
    (void)memset_s(data, length + 1, 0, length + 1);

    size_t res = 0;
    status = napi_get_value_string_utf8(env, obj, data, length + 1, &res);
    if (status != napi_ok) {
        CmFree(data);
        GET_AND_THROW_LAST_ERROR((env));
        CM_LOG_E("could not get string");
        return nullptr;
    }

    blob = static_cast<CmBlob *>(CmMalloc(sizeof(CmBlob)));
    if (blob == nullptr) {
        CmFree(data);
        napi_throw_error(env, nullptr, "could not alloc memory");
        CM_LOG_E("could not alloc memory");
        return nullptr;
    }
    blob->data = reinterpret_cast<uint8_t *>(data);
    blob->size = static_cast<uint32_t>((length + 1) & UINT32_MAX);

    return GetInt32(env, 0);
}

static const char *GetJsErrorMsg(int32_t errCode)
{
    auto iter = DIALOG_CODE_TO_MSG_MAP.find(errCode);
    if (iter != DIALOG_CODE_TO_MSG_MAP.end()) {
        return (iter->second).c_str();
    }
    return DIALOG_GENERIC_MSG.c_str();
}

int32_t TranformErrorCode(int32_t errorCode)
{
    auto iter = DIALOG_CODE_TO_JS_CODE_MAP.find(errorCode);
    if (iter != DIALOG_CODE_TO_JS_CODE_MAP.end()) {
        return iter->second;
    }
    return DIALOG_ERROR_GENERIC;
}

napi_value GenerateBusinessError(napi_env env, int32_t errorCode)
{
    const char *errorMessage = GetJsErrorMsg(errorCode);
    if (errorMessage == nullptr) {
        return nullptr;
    }

    napi_value businessErrorMsg = nullptr;
    NAPI_CALL(env, napi_create_object(env, &businessErrorMsg));

    napi_value code = nullptr;
    int32_t outputCode = TranformErrorCode(errorCode);
    NAPI_CALL(env, napi_create_int32(env, outputCode, &code));
    NAPI_CALL(env, napi_set_named_property(env, businessErrorMsg, BUSINESS_ERROR_PROPERTY_CODE.c_str(), code));
    napi_value message = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, errorMessage, NAPI_AUTO_LENGTH, &message));
    NAPI_CALL(env, napi_set_named_property(env, businessErrorMsg, BUSINESS_ERROR_PROPERTY_MESSAGE.c_str(), message));
    return businessErrorMsg;
}

void ThrowError(napi_env env, int32_t errorCode, std::string errMsg)
{
    napi_value paramsError = nullptr;
    napi_value outCode = nullptr;
    napi_value message = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, errorCode, &outCode));
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &message));
    NAPI_CALL_RETURN_VOID(env, napi_create_error(env, nullptr, message, &paramsError));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, paramsError,
        BUSINESS_ERROR_PROPERTY_CODE.c_str(), outCode));
    NAPI_CALL_RETURN_VOID(env, napi_throw(env, paramsError));
}

void GeneratePromise(napi_env env, napi_deferred deferred, int32_t resultCode,
    napi_value *result, int32_t length)
{
    if (length < RESULT_NUMBER) {
        return;
    }
    if (resultCode == CM_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, deferred, result[1]));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, deferred, result[0]));
    }
}


}  // namespace CertManagerNapi
