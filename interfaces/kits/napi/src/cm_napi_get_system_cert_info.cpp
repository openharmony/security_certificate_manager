/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "cm_napi_get_system_cert_info.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_napi_common.h"

namespace CMNapi {
namespace {
constexpr int CM_NAPI_GET_CERT_INFO_MIN_ARGS = 1;
constexpr int CM_NAPI_GET_CERT_INFO_MAX_ARGS = 2;
}  // namespace

struct GetCertInfoAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct CmBlob *certUri = nullptr;
    uint32_t store = 0;
    struct CertInfo *certificate = nullptr;
};
using GetCertInfoAsyncContext = GetCertInfoAsyncContextT *;

static GetCertInfoAsyncContext CreateGetCertInfoAsyncContext()
{
    GetCertInfoAsyncContext context =
        static_cast<GetCertInfoAsyncContext>(CmMalloc(sizeof(GetCertInfoAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(
            context, sizeof(GetCertInfoAsyncContextT), 0, sizeof(GetCertInfoAsyncContextT));
    }
    return context;
}

static void DeleteGetCertInfoAsyncContext(napi_env env, GetCertInfoAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    DeleteNapiContext(env, context->asyncWork, context->callback);

    if (context->certUri != nullptr) {
        FreeCmBlob(context->certUri);
    }

    if (context->certificate != nullptr) {
        FreeCertInfo(context->certificate);
    }

    CmFree(context);
    context = nullptr;
}

static napi_value GetCertInfoParseParams(napi_env env, napi_callback_info info,
    GetCertInfoAsyncContext context, uint32_t store)
{
    size_t argc = CM_NAPI_GET_CERT_INFO_MAX_ARGS;
    napi_value argv[CM_NAPI_GET_CERT_INFO_MAX_ARGS] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if ((argc != CM_NAPI_GET_CERT_INFO_MAX_ARGS) && (argc != CM_NAPI_GET_CERT_INFO_MIN_ARGS)) {
        ThrowError(env, PARAM_ERROR, "arguments count invalid when getting trusted certificate info");
        CM_LOG_E("arguments count invalid when getting trusted certificate info");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseString(env, argv[index], context->certUri);
    if (result == nullptr) {
        ThrowError(env, PARAM_ERROR, "certUri type error");
        CM_LOG_E("get cert uri failed when getting trusted certificate info");
        return nullptr;
    }

    index++;
    if (index < argc) {
        int32_t ret = GetCallback(env, argv[index], context->callback);
        if (ret != CM_SUCCESS) {
            ThrowError(env, PARAM_ERROR, "Get callback type failed.");
            CM_LOG_E("get callback function failed when get cert info function");
            return nullptr;
        }
    }

    context->store = store;
    return GetInt32(env, 0);
}

static napi_value GetCertInfoWriteResult(napi_env env, GetCertInfoAsyncContext context)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));
    napi_value certInfo = GenerateCertInfo(env, context->certificate);
    if (certInfo != nullptr) {
        napi_set_named_property(env, result, CM_RESULT_PRPPERTY_CERTINFO.c_str(), certInfo);
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    return result;
}

static void GetCertInfoExecute(napi_env env, void *data)
{
    GetCertInfoAsyncContext context = static_cast<GetCertInfoAsyncContext>(data);

    context->certificate = static_cast<struct CertInfo *>(CmMalloc(sizeof(struct CertInfo)));
    if (context->certificate == nullptr) {
        CM_LOG_E("malloc certificate fail");
        context->result = CMR_ERROR_MALLOC_FAIL;
        return;
    }
    (void)memset_s(context->certificate, sizeof(struct CertInfo), 0, sizeof(struct CertInfo));

    context->certificate->certInfo.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE));
    if (context->certificate->certInfo.data == nullptr) {
        CM_LOG_E("malloc certificate certInfo data fail");
        context->result = CMR_ERROR_MALLOC_FAIL;
        return;
    }
    context->certificate->certInfo.size = MAX_LEN_CERTIFICATE;

    if (context->store == CM_SYSTEM_TRUSTED_STORE) {
        context->result = CmGetCertInfo(context->certUri, context->store,
            context->certificate);
    } else {
        context->result = CmGetUserCertInfo(context->certUri, context->store, context->certificate);
    }
}

static void GetCertInfoComplete(napi_env env, napi_status status, void *data)
{
    GetCertInfoAsyncContext context = static_cast<GetCertInfoAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->result == CM_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
        result[1] = GetCertInfoWriteResult(env, context);
    } else {
        result[0] = GenerateBusinessError(env, context->result);
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    }
    if (context->deferred != nullptr) {
        GeneratePromise(env, context->deferred, context->result, result, CM_ARRAY_SIZE(result));
    } else {
        GenerateCallback(env, context->callback, result, CM_ARRAY_SIZE(result), context->result);
    }
    DeleteGetCertInfoAsyncContext(env, context);
    CM_LOG_D("get system cert info end");
}

static napi_value GetCertInfoAsyncWork(napi_env env, GetCertInfoAsyncContext context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "GetCertInfoAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env,
        nullptr,
        resourceName,
        GetCertInfoExecute,
        GetCertInfoComplete,
        static_cast<void *>(context),
        &context->asyncWork));
    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteGetCertInfoAsyncContext(env, context);
        CM_LOG_E("get system cert info could not queue async work");
        return nullptr;
    }
    return promise;
}

napi_value CMNapiGetSystemCertInfo(napi_env env, napi_callback_info info)
{
    CM_LOG_I("get system cert info enter");
    GetCertInfoAsyncContext context = CreateGetCertInfoAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = GetCertInfoParseParams(env, info, context, CM_SYSTEM_TRUSTED_STORE);
    if (result == nullptr) {
        CM_LOG_E("could not parse params");
        DeleteGetCertInfoAsyncContext(env, context);
        return nullptr;
    }
    result = GetCertInfoAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("could not start async work");
        DeleteGetCertInfoAsyncContext(env, context);
        return nullptr;
    }
    CM_LOG_I("get system cert info end");
    return result;
}

napi_value CMNapiGetUserTrustedCertInfo(napi_env env, napi_callback_info info)
{
    CM_LOG_I("get user cert info enter");

    GetCertInfoAsyncContext context = CreateGetCertInfoAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("create cert info context failed");
        return nullptr;
    }

    napi_value result = GetCertInfoParseParams(env, info, context, CM_USER_TRUSTED_STORE);
    if (result == nullptr) {
        CM_LOG_E("parse get cert info params failed");
        DeleteGetCertInfoAsyncContext(env, context);
        return nullptr;
    }
    result = GetCertInfoAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("get cert info params async work failed");
        DeleteGetCertInfoAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("get user cert info end");
    return result;
}
}  // namespace CertManagerNapi
