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

#include "cm_napi_get_system_cert_list.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_napi_common.h"

namespace CMNapi {
namespace {
constexpr int CM_NAPI_GET_SYSTEM_CERT_LIST_MIN_ARGS = 1;
constexpr int CM_NAPI_GET_SYSTEM_CERT_LIST_MAX_ARGS = 2;
constexpr int CM_NAPI_GET_USER_CERT_LIST_MIN_ARGS = 0;
constexpr int CM_NAPI_GET_USER_CERT_LIST_MAX_ARGS = 1;
}  // namespace

struct GetCertListAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct CmContext *cmContext = nullptr;
    uint32_t store = 0;
    struct CertList *certificateList = nullptr;
};
using GetCertListAsyncContext = GetCertListAsyncContextT *;

static GetCertListAsyncContext CreateGetCertListAsyncContext()
{
    GetCertListAsyncContext context =
        static_cast<GetCertListAsyncContext>(CmMalloc(sizeof(GetCertListAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(
            context, sizeof(GetCertListAsyncContextT), 0, sizeof(GetCertListAsyncContextT));
    }
    return context;
}

static void DeleteGetCertListAsyncContext(napi_env env, GetCertListAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    DeleteNapiContext(env, context->asyncWork, context->callback);

    if (context->cmContext != nullptr) {
        FreeCmContext(context->cmContext);
    }

    if (context->certificateList != nullptr) {
        FreeCertList(context->certificateList);
    }

    CmFree(context);
    context = nullptr;
}

static napi_value GetCertListParseParams(
    napi_env env, napi_callback_info info, GetCertListAsyncContext context)
{
    size_t argc = CM_NAPI_GET_SYSTEM_CERT_LIST_MAX_ARGS;
    napi_value argv[CM_NAPI_GET_SYSTEM_CERT_LIST_MAX_ARGS] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < CM_NAPI_GET_SYSTEM_CERT_LIST_MIN_ARGS) {
        ThrowParamsError(env, PARAM_ERROR, "Missing parameter");
        CM_LOG_E("Missing parameter");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseCmContext(env, argv[index], context->cmContext);
    if (result == nullptr) {
        ThrowParamsError(env, PARAM_ERROR, "get context type error");
        CM_LOG_E("could not get cert manager context");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
    }

    context->store = CM_SYSTEM_TRUSTED_STORE;
    return GetInt32(env, 0);
}

static napi_value GetUserTrustedCertListParseParams(
    napi_env env, napi_callback_info info, GetCertListAsyncContext context)
{
    size_t argc = CM_NAPI_GET_USER_CERT_LIST_MAX_ARGS;
    napi_value argv[CM_NAPI_GET_USER_CERT_LIST_MAX_ARGS] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if ((argc != CM_NAPI_GET_USER_CERT_LIST_MIN_ARGS) &&
        (argc != CM_NAPI_GET_USER_CERT_LIST_MAX_ARGS)) {
        ThrowParamsError(env, PARAM_ERROR, "arguments count invalid when getting user trusted certificate list");
        CM_LOG_E("arguments count is not expected when getting user trusted certificate list");
        return nullptr;
    }

    size_t index = 0;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
        if (context->callback == nullptr) {
            ThrowParamsError(env, PARAM_ERROR, "Get callback type error");
            CM_LOG_E("get callback function failed when getting user trusted certificate list");
            return nullptr;
        }
    }

    context->store = CM_USER_TRUSTED_STORE;
    return GetInt32(env, 0);
}

static napi_value GetCertListWriteResult(napi_env env, GetCertListAsyncContext context)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));
    napi_value certChains = GenerateCertAbstractArray(env,
        context->certificateList->certAbstract, context->certificateList->certsCount);
    if (certChains != nullptr) {
        napi_set_named_property(env, result, CM_RESULT_PRPPERTY_CERTLIST.c_str(), certChains);
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    return result;
}

static void GetCertListExecute(napi_env env, void *data)
{
    GetCertListAsyncContext context = static_cast<GetCertListAsyncContext>(data);

    context->certificateList = static_cast<struct CertList *>(CmMalloc(sizeof(struct CertList)));
    if (context->certificateList == nullptr) {
        CM_LOG_E("malloc certificateList fail");
        context->result = CMR_ERROR_MALLOC_FAIL;
        return;
    }
    context->certificateList->certAbstract = nullptr;
    context->certificateList->certsCount = 0;

    uint32_t buffSize = MAX_COUNT_CERTIFICATE * sizeof(struct CertAbstract);
    context->certificateList->certAbstract = static_cast<struct CertAbstract *>(CmMalloc(buffSize));
    if (context->certificateList->certAbstract == nullptr) {
        CM_LOG_E("malloc certificateList certAbstract fail");
        context->result = CMR_ERROR_MALLOC_FAIL;
        return;
    }
    (void)memset_s(context->certificateList->certAbstract, buffSize, 0, buffSize);
    context->certificateList->certsCount = MAX_COUNT_CERTIFICATE;

    if (context->store == CM_SYSTEM_TRUSTED_STORE) {
        context->result = CmGetCertList(context->store, context->certificateList);
    } else {
        context->result = CmGetUserCertList(context->store, context->certificateList);
    }
}

static void GetCertListComplete(napi_env env, napi_status status, void *data)
{
    GetCertListAsyncContext context = static_cast<GetCertListAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->result == CM_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
        result[1] = GetCertListWriteResult(env, context);
    } else {
        const char *errorMsg = "get system cert list error";
        result[0] = GenerateBusinessError(env, context->result, errorMsg);
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    }
    if (context->deferred != nullptr) {
        GeneratePromise(env, context->deferred, context->result, result, sizeof(result));
    } else {
        GenerateCallback(env, context->callback, result, sizeof(result));
    }
    DeleteGetCertListAsyncContext(env, context);
}

static napi_value GetCertListAsyncWork(napi_env env, GetCertListAsyncContext context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "GetCertListAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env,
        nullptr,
        resourceName,
        GetCertListExecute,
        GetCertListComplete,
        static_cast<void *>(context),
        &context->asyncWork));

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteGetCertListAsyncContext(env, context);
        CM_LOG_E("could not queue async work");
        return nullptr;
    }
    return promise;
}

napi_value CMNapiGetSystemCertList(napi_env env, napi_callback_info info)
{
    GetCertListAsyncContext context = CreateGetCertListAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        return nullptr;
    }
    napi_value result = GetCertListParseParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("could not parse params");
        DeleteGetCertListAsyncContext(env, context);
        return nullptr;
    }
    result = GetCertListAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("could not start async work");
        DeleteGetCertListAsyncContext(env, context);
        return nullptr;
    }
    return result;
}

napi_value CMNapiGetUserTrustedCertList(napi_env env, napi_callback_info info)
{
    GetCertListAsyncContext context = CreateGetCertListAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("create context failed");
        return nullptr;
    }

    napi_value result = GetUserTrustedCertListParseParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("could not parse user trusted cert list params");
        DeleteGetCertListAsyncContext(env, context);
        return nullptr;
    }

    result = GetCertListAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("get user trusted cert list async work failed");
        DeleteGetCertListAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}  // namespace CertManagerNapi
