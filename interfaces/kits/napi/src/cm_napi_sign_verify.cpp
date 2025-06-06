/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "cm_napi_sign_verify.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_napi_common.h"

namespace CMNapi {
namespace {
constexpr int CM_NAPI_INIT_ARGS_CNT = 3;
constexpr int CM_NAPI_UPDATE_ARGS_CNT = 3;
constexpr int CM_NAPI_FINISH_ARGS_CNT = 3;
constexpr int CM_NAPI_ABORT_ARGS_CNT = 2;

constexpr int CM_NAPI_CALLBACK_ARG_CNT = 1;
constexpr int CM_NAPI_SIGNATURE_ARG_CNT = 1;

constexpr uint32_t OUT_SIGNATURE_SIZE = 1000;
constexpr uint32_t OUT_HANLDE_SIZE = 8;
} // namespace

struct SignVerifyAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t errCode = 0;
    bool isSign = false;
    struct CmBlob *authUri = nullptr;
    struct CmBlob *handle = nullptr;
    struct CmBlob *inData = nullptr;
    struct CmBlob *signature = nullptr;
    struct CmSignatureSpec *spec = nullptr;
};
using SignVerifyAsyncContext = SignVerifyAsyncContextT *;

static SignVerifyAsyncContext InitSignVerifyAsyncContext(void)
{
    SignVerifyAsyncContext context = static_cast<SignVerifyAsyncContext>(CmMalloc(sizeof(SignVerifyAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(SignVerifyAsyncContextT), 0, sizeof(SignVerifyAsyncContextT));
    }
    return context;
}

static void FreeSignVerifyAsyncContext(napi_env env, SignVerifyAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    DeleteNapiContext(env, context->asyncWork, context->callback);
    FreeCmBlob(context->authUri);
    FreeCmBlob(context->handle);
    FreeCmBlob(context->inData);
    FreeCmBlob(context->signature);
    CM_FREE_PTR(context->spec);
    CM_FREE_PTR(context);
}

struct CmJSKeyPaddingCmKeyPaddingMap {
    CmJSKeyPadding key;
    CmKeyPadding retPadding;
};

const struct CmJSKeyPaddingCmKeyPaddingMap PADDING_MAP[] = {
    { CM_JS_PADDING_NONE, CM_PADDING_NONE },
    { CM_JS_PADDING_PSS, CM_PADDING_PSS },
    { CM_JS_PADDING_PKCS1_V1_5, CM_PADDING_PKCS1_V1_5 },
};

struct CmJSKeyDigestCmKeyDigestMap {
    CmJSKeyDigest key;
    CmKeyDigest retDigest;
};

const struct CmJSKeyDigestCmKeyDigestMap DIGEST_MAP[] = {
    { CM_JS_DIGEST_NONE, CM_DIGEST_NONE },
    { CM_JS_DIGEST_MD5, CM_DIGEST_MD5 },
    { CM_JS_DIGEST_SHA1, CM_DIGEST_SHA1 },
    { CM_JS_DIGEST_SHA224, CM_DIGEST_SHA224 },
    { CM_JS_DIGEST_SHA256, CM_DIGEST_SHA256 },
    { CM_JS_DIGEST_SHA384, CM_DIGEST_SHA384 },
    { CM_JS_DIGEST_SHA512, CM_DIGEST_SHA512 },
    { CM_JS_DIGEST_SM3, CM_DIGEST_SM3 },
};

static napi_value GetPadding(napi_env env, napi_value object, uint32_t *paddingRet)
{
    napi_value padding = nullptr;
    napi_status status = napi_get_named_property(env, object, "padding", &padding);
    if (status != napi_ok || padding == nullptr) {
        CM_LOG_E("get padding failed");
        return nullptr;
    }

    napi_valuetype type = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, padding, &type));
    if (type == napi_undefined) {
        CM_LOG_D("padding is undefined, set padding value is default");
        *paddingRet = CM_PADDING_PSS;
        return GetInt32(env, 0);
    }

    if (type != napi_number) {
        ThrowError(env, PARAM_ERROR, "arguments invalid, type of param padding is not number");
        CM_LOG_E("arguments invalid, type of param padding is not number");
        return nullptr;
    }

    uint32_t paddingValue = 0;
    status = napi_get_value_uint32(env, padding, &paddingValue);
    if (status != napi_ok) {
        CM_LOG_E("get padding value failed");
        ThrowError(env, PARAM_ERROR, "arguments invalid, get padding value failed");
        return nullptr;
    }

    bool findFlag = false;
    for (uint32_t i = 0; i < (sizeof(PADDING_MAP) / sizeof(PADDING_MAP[0])); i++) {
        if (paddingValue == PADDING_MAP[i].key) {
            *paddingRet = PADDING_MAP[i].retPadding;
            findFlag = true;
            break;
        }
    }
    if (!findFlag) {
        ThrowError(env, PARAM_ERROR, "padding do not exist in PADDING_MAP");
        CM_LOG_E("padding do not exist in PADDING_MAP.");
        return nullptr;
    }

    return GetInt32(env, 0);
}

static napi_value GetDigest(napi_env env, napi_value object, uint32_t *digestRet)
{
    napi_value digest = nullptr;
    napi_status status = napi_get_named_property(env, object, "digest", &digest);
    if (status != napi_ok || digest == nullptr) {
        CM_LOG_E("get digest failed");
        return nullptr;
    }
    napi_valuetype type = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, digest, &type));
    if (type == napi_undefined) {
        CM_LOG_D("digest is undefined, set digest value is default");
        *digestRet = CM_DIGEST_SHA256;
        return GetInt32(env, 0);
    }

    if (type != napi_number) {
        ThrowError(env, PARAM_ERROR, "arguments invalid, type of param digest is not number");
        CM_LOG_E("arguments invalid, type of param digest is not number.");
        return nullptr;
    }

    uint32_t digestValue = 0;
    status = napi_get_value_uint32(env, digest, &digestValue);
    if (status != napi_ok) {
        ThrowError(env, PARAM_ERROR, "arguments invalid, get digest value failed");
        CM_LOG_E("arguments invalid,get digest value failed.");
        return nullptr;
    }
    bool findFlag = false;
    for (uint32_t i = 0; i < (sizeof(DIGEST_MAP) / sizeof(DIGEST_MAP[0])); i++) {
        if (digestValue == DIGEST_MAP[i].key) {
            *digestRet = DIGEST_MAP[i].retDigest;
            findFlag = true;
            break;
        }
    }
    if (!findFlag) {
        ThrowError(env, PARAM_ERROR, "digest do not exist in DIGEST_MAP");
        CM_LOG_E("digest do not exist in DIGEST_MAP.");
        return nullptr;
    }

    return GetInt32(env, 0);
}

static napi_value ParseSpec(napi_env env, napi_value object, CmSignatureSpec *&spec)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, object, &type));
    if (type != napi_object) {
        CM_LOG_E("type of param spec is not object");
        return nullptr;
    }

    napi_value purpose = nullptr;
    napi_status status = napi_get_named_property(env, object, "purpose", &purpose);
    if (status != napi_ok || purpose == nullptr) {
        CM_LOG_E("get purpose failed");
        return nullptr;
    }

    NAPI_CALL(env, napi_typeof(env, purpose, &type));
    if (type != napi_number) {
        CM_LOG_E("type of param purpose is not number");
        return nullptr;
    }

    uint32_t purposeValue = 0;
    status = napi_get_value_uint32(env, purpose, &purposeValue);
    if (status != napi_ok) {
        CM_LOG_E("get purpose value failed");
        return nullptr;
    }

    spec = static_cast<CmSignatureSpec *>(CmMalloc(sizeof(CmSignatureSpec)));
    if (spec == nullptr) {
        CM_LOG_E("malloc spec struct failed");
        return nullptr;
    }
    spec->purpose = purposeValue;

    /* padding */
    napi_value result = GetPadding(env, object, &spec->padding);
    if (result == nullptr) {
        CM_LOG_E("get padding failed when using GetPadding function");
        CM_FREE_PTR(spec);
        return nullptr;
    }

    /* digest */
    result = GetDigest(env, object, &spec->digest);
    if (result == nullptr) {
        CM_LOG_E("get digest failed when using GetDigest function");
        CM_FREE_PTR(spec);
        return nullptr;
    }

    return GetInt32(env, 0);
}

static napi_value GetBlob(napi_env env, napi_value object, CmBlob *&blob)
{
    blob = static_cast<CmBlob *>(CmMalloc(sizeof(CmBlob)));
    if (blob == nullptr) {
        CM_LOG_E("malloc blob failed");
        return nullptr;
    }
    (void)memset_s(blob, sizeof(CmBlob), 0, sizeof(CmBlob));

    napi_value result = GetUint8Array(env, object, *blob);
    if (result == nullptr) {
        CM_LOG_E("parse blob data failed");
        return nullptr;
    }

    return GetInt32(env, 0);
}

static napi_value ParseCMInitParams(napi_env env, napi_callback_info info, SignVerifyAsyncContext context)
{
    size_t argc = CM_NAPI_INIT_ARGS_CNT;
    napi_value argv[CM_NAPI_INIT_ARGS_CNT] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if ((argc != CM_NAPI_INIT_ARGS_CNT) && (argc != (CM_NAPI_INIT_ARGS_CNT - CM_NAPI_CALLBACK_ARG_CNT))) {
        ThrowError(env, PARAM_ERROR, "init arguments count invalid, arguments count need between 2 and 3.");
        CM_LOG_E("init arguments count is not expected");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseString(env, argv[index], context->authUri);
    if (result == nullptr) {
        ThrowError(env, PARAM_ERROR, "authUri is not a string or the length is 0 or too long.");
        CM_LOG_E("get uri failed when using init function");
        return nullptr;
    }

    index++;
    result = ParseSpec(env, argv[index], context->spec);
    if (result == nullptr) {
        ThrowError(env, PARAM_ERROR, "get spec type error");
        CM_LOG_E("get sepc failed when using init function");
        return nullptr;
    }

    index++;
    if (index < argc) {
        int32_t ret = GetCallback(env, argv[index], context->callback);
        if (ret != CM_SUCCESS) {
            ThrowError(env, PARAM_ERROR, "Get callback failed, callback must be a function.");
            CM_LOG_E("get callback function failed when using init function");
            return nullptr;
        }
    }

    return GetInt32(env, 0);
}

static napi_value ParseCMUpdateParams(napi_env env, napi_callback_info info, SignVerifyAsyncContext context)
{
    size_t argc = CM_NAPI_UPDATE_ARGS_CNT;
    napi_value argv[CM_NAPI_UPDATE_ARGS_CNT] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if ((argc != CM_NAPI_UPDATE_ARGS_CNT) && (argc != (CM_NAPI_UPDATE_ARGS_CNT - CM_NAPI_CALLBACK_ARG_CNT))) {
        ThrowError(env, PARAM_ERROR, "update arguments count invalid, arguments count need between 2 and 3.");
        CM_LOG_E("update arguments count is not expected");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = GetBlob(env, argv[index], context->handle);
    if (result == nullptr) {
        ThrowError(env, PARAM_ERROR, "handle is not a uint8Array or the length is 0 or too long.");
        CM_LOG_E("get handle failed when using update function");
        return nullptr;
    }

    index++;
    result = GetBlob(env, argv[index], context->inData);
    if (result == nullptr) {
        ThrowError(env, PARAM_ERROR, "inData is not a uint8Array or the length is 0 or too long.");
        CM_LOG_E("get inData failed when using update function");
        return nullptr;
    }

    index++;
    if (index < argc) {
        int32_t ret = GetCallback(env, argv[index], context->callback);
        if (ret != CM_SUCCESS) {
            ThrowError(env, PARAM_ERROR, "Get callback failed, callback must be a function.");
            CM_LOG_E("get callback function failed when using update function");
            return nullptr;
        }
    }

    return GetInt32(env, 0);
}

static napi_value MallocFinishOutData(napi_env env, SignVerifyAsyncContext context)
{
    context->signature = static_cast<CmBlob *>(CmMalloc(sizeof(CmBlob)));
    if (context->signature == nullptr) { /* signature will free after all process */
        CM_LOG_E("malloc outData failed when process sign finish");
        ThrowError(env, INNER_FAILURE, GENERIC_MSG);
        return nullptr;
    }
    (void)memset_s(context->signature, sizeof(CmBlob), 0, sizeof(CmBlob));

    uint8_t *data = static_cast<uint8_t *>(CmMalloc(OUT_SIGNATURE_SIZE));
    if (data == nullptr) {
        CM_LOG_E("malloc outData.data failed when process sign finish");
        ThrowError(env, INNER_FAILURE, GENERIC_MSG);
        return nullptr;
    }
    (void)memset_s(data, OUT_SIGNATURE_SIZE, 0, OUT_SIGNATURE_SIZE);

    context->signature->data = data;
    context->signature->size = OUT_SIGNATURE_SIZE;
    return GetInt32(env, 0);
}

static napi_value ProcessFinishOneParam(napi_env env, SignVerifyAsyncContext context)
{
    /* promise: sign */
    context->isSign = true;
    return MallocFinishOutData(env, context);
}

static int32_t CheckIsCallback(napi_env env, napi_value object, bool &isFunc)
{
    isFunc = false;
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, object, &valueType);
    if (status != napi_ok) {
        CM_LOG_E("could not get object type");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (valueType == napi_function) {
        isFunc = true;
    }
    return CM_SUCCESS;
}

static napi_value ProcessFinishTwoParam(napi_env env, napi_value *argv, SignVerifyAsyncContext context,
    size_t curIndex, size_t maxIndex)
{
    curIndex++;
    if (curIndex >= maxIndex) {
        return nullptr; /* not possible */
    }

    /*
     * check wether arg 2 is callback: if true, get callback function and return: callback sign.
     * else is promise verify, then get arg 2 as signature
     */
    bool isFunc = false;
    int32_t ret = CheckIsCallback(env, argv[curIndex], isFunc);
    if (ret != CM_SUCCESS) {
        return nullptr;
    }

    napi_value result = nullptr;
    if (isFunc) {
        /* callback: sign */
        context->isSign = true;
        result = MallocFinishOutData(env, context);
        if (result == nullptr) {
            return nullptr;
        }

        ret = GetCallback(env, argv[curIndex], context->callback);
        if (ret != CM_SUCCESS) {
            ThrowError(env, PARAM_ERROR, "Get callback failed, callback must be a function.");
            CM_LOG_E("arg2 is callback: get sign callback function failed when using finish function");
            return nullptr;
        }

        return GetInt32(env, 0);
    }

    /* promise verify */
    context->isSign = false;
    result = GetBlob(env, argv[curIndex], context->signature);
    if (result == nullptr) {
        ThrowError(env, PARAM_ERROR, "signature is not a uint8Array or the length is 0 or too long.");
        CM_LOG_E("get signature failed when process promise verify");
        return nullptr;
    }

    return GetInt32(env, 0);
}

static napi_value ProcessFinishThreeParam(napi_env env, napi_value *argv, SignVerifyAsyncContext context,
    size_t curIndex, size_t maxIndex)
{
    /* callback: verify */
    context->isSign = false;

    curIndex++;
    if (curIndex >= maxIndex) {
        return nullptr; /* not possible */
    }

    napi_value result = GetBlob(env, argv[curIndex], context->signature);
    if (result == nullptr) {
        ThrowError(env, PARAM_ERROR, "signature is not a uint8Array or the length is 0 or too long.");
        CM_LOG_E("get signature failed when process callback verify");
        return nullptr;
    }

    curIndex++;
    if (curIndex >= maxIndex) {
        return nullptr; /* not possible */
    }

    int32_t ret = GetCallback(env, argv[curIndex], context->callback);
    if (ret != CM_SUCCESS) {
        ThrowError(env, PARAM_ERROR, "Get callback failed, callback must be a function.");
        CM_LOG_E("get verify callback function failed when using finish function");
        return nullptr;
    }

    return GetInt32(env, 0);
}

static napi_value ParseCMFinishParams(napi_env env, napi_callback_info info, SignVerifyAsyncContext context)
{
    size_t argc = CM_NAPI_FINISH_ARGS_CNT;
    napi_value argv[CM_NAPI_FINISH_ARGS_CNT] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if ((argc != CM_NAPI_FINISH_ARGS_CNT) && (argc != (CM_NAPI_FINISH_ARGS_CNT - CM_NAPI_CALLBACK_ARG_CNT)) &&
        (argc != (CM_NAPI_FINISH_ARGS_CNT - CM_NAPI_CALLBACK_ARG_CNT - CM_NAPI_SIGNATURE_ARG_CNT))) {
        ThrowError(env, PARAM_ERROR, "finish arguments count invalid, arguments count need between 1 and 3.");
        CM_LOG_E("finish arguments count is not expected");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = GetBlob(env, argv[index], context->handle);
    if (result == nullptr) {
        ThrowError(env, PARAM_ERROR, "handle is not a uint8Array or the length is 0 or too long.");
        CM_LOG_E("get handle failed when using finish function");
        return nullptr;
    }

    if (argc == CM_NAPI_FINISH_ARGS_CNT) {
        return ProcessFinishThreeParam(env, argv, context, index, argc);
    } else if (argc == (CM_NAPI_FINISH_ARGS_CNT - CM_NAPI_CALLBACK_ARG_CNT)) {
        return ProcessFinishTwoParam(env, argv, context, index, argc);
    } else { /* only three types */
        return ProcessFinishOneParam(env, context);
    }
}

static napi_value ParseCMAbortParams(napi_env env, napi_callback_info info, SignVerifyAsyncContext context)
{
    size_t argc = CM_NAPI_ABORT_ARGS_CNT;
    napi_value argv[CM_NAPI_ABORT_ARGS_CNT] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if ((argc != CM_NAPI_ABORT_ARGS_CNT) && (argc != (CM_NAPI_ABORT_ARGS_CNT - CM_NAPI_CALLBACK_ARG_CNT))) {
        ThrowError(env, PARAM_ERROR, "abort arguments count invalid, arguments count need between 1 and 2.");
        CM_LOG_E("abort arguments count is not expected");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = GetBlob(env, argv[index], context->handle);
    if (result == nullptr) {
        ThrowError(env, PARAM_ERROR, "handle is not a uint8Array or the length is 0 or too long.");
        CM_LOG_E("get handle failed when using abort function");
        return nullptr;
    }

    index++;
    if (index < argc) {
        int32_t ret = GetCallback(env, argv[index], context->callback);
        if (ret != CM_SUCCESS) {
            ThrowError(env, PARAM_ERROR, "Get callback failed, callback must be a function.");
            CM_LOG_E("get callback function failed when using abort function");
            return nullptr;
        }
    }

    return GetInt32(env, 0);
}

static void InitExecute(napi_env env, void *data)
{
    SignVerifyAsyncContext context = static_cast<SignVerifyAsyncContext>(data);
    context->handle = static_cast<CmBlob *>(CmMalloc(sizeof(CmBlob)));
    if (context->handle == nullptr) {
        CM_LOG_E("malloc handle out failed");
        context->errCode = CMR_ERROR_MALLOC_FAIL;
        return;
    }
    (void)memset_s(context->handle, sizeof(CmBlob), 0, sizeof(CmBlob));

    context->handle->data = static_cast<uint8_t *>(CmMalloc(OUT_HANLDE_SIZE));
    if (context->handle->data == nullptr) {
        CM_LOG_E("malloc handle.data failed");
        context->errCode = CMR_ERROR_MALLOC_FAIL;
        return;
    }
    (void)memset_s(context->handle->data, OUT_HANLDE_SIZE, 0, OUT_HANLDE_SIZE);
    context->handle->size = OUT_HANLDE_SIZE;

    context->errCode = CmInit(context->authUri, context->spec, context->handle);
}

static napi_value GenerateArrayBuffer(napi_env env, uint8_t *data, uint32_t size)
{
    uint8_t *tempBuf = static_cast<uint8_t *>(CmMalloc(size));
    if (tempBuf == nullptr) {
        CM_LOG_E("malloc outbuf failed");
        return nullptr;
    }
    (void)memcpy_s(tempBuf, size, data, size);

    napi_value outBuffer = nullptr;
    napi_status status = napi_create_external_arraybuffer(
        env, tempBuf, size, [](napi_env env, void *data, void *hint) { CmFree(data); }, nullptr, &outBuffer);
    if (status == napi_ok) {
        tempBuf = nullptr; /* free by finalize callback */
    } else {
        CM_LOG_E("create external array buffer failed");
        CM_FREE_PTR(tempBuf);
        GET_AND_THROW_LAST_ERROR((env));
    }

    return outBuffer;
}

static napi_value ConvertResultHandle(napi_env env, const CmBlob *handle)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));

    napi_value handleNapi = nullptr;
    napi_value handleBuf = GenerateArrayBuffer(env, handle->data, handle->size);
    if (handleBuf != nullptr) {
        NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, handle->size, handleBuf, 0, &handleNapi));
    } else {
        handleNapi = GetNull(env);
    }
    NAPI_CALL(env, napi_set_named_property(env, result, "handle", handleNapi));

    return result;
}

static void InitComplete(napi_env env, napi_status status, void *data)
{
    SignVerifyAsyncContext context = static_cast<SignVerifyAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->errCode == CM_SUCCESS) {
        napi_create_uint32(env, 0, &result[0]);
        result[1] = ConvertResultHandle(env, context->handle);
    } else {
        result[0] = GenerateBusinessError(env, context->errCode);
        napi_get_undefined(env, &result[1]);
    }

    if (context->deferred != nullptr) {
        GeneratePromise(env, context->deferred, context->errCode, result, CM_ARRAY_SIZE(result));
    } else {
        GenerateCallback(env, context->callback, result, CM_ARRAY_SIZE(result), context->errCode);
    }
    FreeSignVerifyAsyncContext(env, context);
}

static void UpdateExecute(napi_env env, void *data)
{
    SignVerifyAsyncContext context = static_cast<SignVerifyAsyncContext>(data);
    context->errCode = CmUpdate(context->handle, context->inData);
}

static void UpdateOrAbortComplete(napi_env env, napi_status status, void *data)
{
    SignVerifyAsyncContext context = static_cast<SignVerifyAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->errCode == CM_SUCCESS) {
        napi_create_uint32(env, 0, &result[0]);
        napi_get_undefined(env, &result[1]);
    } else {
        result[0] = GenerateBusinessError(env, context->errCode);
        napi_get_undefined(env, &result[1]);
    }

    if (context->deferred != nullptr) {
        GeneratePromise(env, context->deferred, context->errCode, result, CM_ARRAY_SIZE(result));
    } else {
        GenerateCallback(env, context->callback, result, CM_ARRAY_SIZE(result), context->errCode);
    }
    FreeSignVerifyAsyncContext(env, context);
}

static void FinishExecute(napi_env env, void *data)
{
    SignVerifyAsyncContext context = static_cast<SignVerifyAsyncContext>(data);
    if (context->isSign) {
        CmBlob inData = { 0, nullptr };
        context->errCode = CmFinish(context->handle, &inData, context->signature);
        return;
    }

    CmBlob outData = { 0, nullptr };
    context->errCode = CmFinish(context->handle, context->signature, &outData);
}

static napi_value ConvertResultSignature(napi_env env, bool isSign, const CmBlob *sign)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));

    napi_value signResultNapi = nullptr;
    if (isSign) {
        napi_value signBuf = GenerateArrayBuffer(env, sign->data, sign->size);
        if (signBuf != nullptr) {
            NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, sign->size, signBuf, 0, &signResultNapi));
        } else {
            signResultNapi = GetNull(env);
        }
    } else {
        signResultNapi = GetNull(env);
    }
    NAPI_CALL(env, napi_set_named_property(env, result, "outData", signResultNapi));

    return result;
}

static void FinishComplete(napi_env env, napi_status status, void *data)
{
    SignVerifyAsyncContext context = static_cast<SignVerifyAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->errCode == CM_SUCCESS) {
        napi_create_uint32(env, 0, &result[0]);
        result[1] = ConvertResultSignature(env, context->isSign, context->signature);
    } else {
        result[0] = GenerateBusinessError(env, context->errCode);
        napi_get_undefined(env, &result[1]);
    }

    if (context->deferred != nullptr) {
        GeneratePromise(env, context->deferred, context->errCode, result, CM_ARRAY_SIZE(result));
    } else {
        GenerateCallback(env, context->callback, result, CM_ARRAY_SIZE(result), context->errCode);
    }
    FreeSignVerifyAsyncContext(env, context);
}

static void AbortExecute(napi_env env, void *data)
{
    SignVerifyAsyncContext context = static_cast<SignVerifyAsyncContext>(data);
    context->errCode = CmAbort(context->handle);
}

static napi_value CMInitAsyncWork(napi_env env, SignVerifyAsyncContext context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "cminit", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName,
        InitExecute,
        InitComplete,
        static_cast<void *>(context),
        &context->asyncWork));

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        ThrowError(env, PARAM_ERROR, "queue async work error");
        CM_LOG_E("queue async work failed when using init function");
        return nullptr;
    }
    return promise;
}

static napi_value CMUpdateAsyncWork(napi_env env, SignVerifyAsyncContext context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "cmupdate", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName,
        UpdateExecute,
        UpdateOrAbortComplete,
        static_cast<void *>(context),
        &context->asyncWork));

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        ThrowError(env, PARAM_ERROR, "queue async work error");
        CM_LOG_E("queue async work failed when using update function");
        return nullptr;
    }
    return promise;
}

static napi_value CMFinishAsyncWork(napi_env env, SignVerifyAsyncContext context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "cmfinish", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName,
        FinishExecute,
        FinishComplete,
        static_cast<void *>(context),
        &context->asyncWork));

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        ThrowError(env, PARAM_ERROR, "queue async work error");
        CM_LOG_E("queue async work failed when using finish function");
        return nullptr;
    }
    return promise;
}

static napi_value CMAbortAsyncWork(napi_env env, SignVerifyAsyncContext context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "cmabort", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName,
        AbortExecute,
        UpdateOrAbortComplete,
        static_cast<void *>(context),
        &context->asyncWork));

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        ThrowError(env, PARAM_ERROR, "queue async work error");
        CM_LOG_E("queue async work failed when using abort function");
        return nullptr;
    }
    return promise;
}

napi_value CMNapiInit(napi_env env, napi_callback_info info)
{
    CM_LOG_I("cm napi init enter");

    SignVerifyAsyncContext context = InitSignVerifyAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("init cm init context failed");
        return nullptr;
    }

    napi_value result = ParseCMInitParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("parse cm init params failed");
        FreeSignVerifyAsyncContext(env, context);
        return nullptr;
    }

    result = CMInitAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("start cm init async work failed");
        FreeSignVerifyAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("cm napi init end");
    return result;
}

napi_value CMNapiUpdate(napi_env env, napi_callback_info info)
{
    CM_LOG_I("cm napi update enter");
    SignVerifyAsyncContext context = InitSignVerifyAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("init cm update context failed");
        return nullptr;
    }

    napi_value result = ParseCMUpdateParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("parse cm update params failed");
        FreeSignVerifyAsyncContext(env, context);
        return nullptr;
    }

    result = CMUpdateAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("start cm update async work failed");
        FreeSignVerifyAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("cm napi update end");
    return result;
}

napi_value CMNapiFinish(napi_env env, napi_callback_info info)
{
    CM_LOG_I("cm napi finish enter");
    SignVerifyAsyncContext context = InitSignVerifyAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("init cm finish context failed");
        return nullptr;
    }

    napi_value result = ParseCMFinishParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("parse cm finish params failed");
        FreeSignVerifyAsyncContext(env, context);
        return nullptr;
    }

    result = CMFinishAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("start cm finish async work failed");
        FreeSignVerifyAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("cm napi finish end");
    return result;
}

napi_value CMNapiAbort(napi_env env, napi_callback_info info)
{
    CM_LOG_I("cm napi abort enter");
    SignVerifyAsyncContext context = InitSignVerifyAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("init cm abort context failed");
        return nullptr;
    }

    napi_value result = ParseCMAbortParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("parse cm abort params failed");
        FreeSignVerifyAsyncContext(env, context);
        return nullptr;
    }

    result = CMAbortAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("start cm abort async work failed");
        FreeSignVerifyAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("cm napi abort end");
    return result;
}
}  // namespace CMNapi

