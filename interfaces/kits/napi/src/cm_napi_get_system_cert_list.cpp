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

#include "cm_napi_get_system_cert_list.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_napi_common.h"

namespace CMNapi {
namespace {
constexpr int CM_NAPI_GET_CERT_LIST_MIN_ARGS = 0;
constexpr int CM_NAPI_GET_CERT_LIST_MAX_ARGS = 1;
}  // namespace

struct GetCertListAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    uint32_t store = 0;
    enum CmCertScope scope = CM_ALL_USER;
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

    if (context->certificateList != nullptr) {
        FreeCertList(context->certificateList);
    }

    CmFree(context);
    context = nullptr;
}

static int32_t GetAndCheckScope(napi_env env, napi_value arg, enum CmCertScope &certScope)
{
    uint32_t scope = 0;
    napi_value result = ParseUint32(env, arg, scope);
    if (result == nullptr) {
        CM_LOG_E("Failed to get scope value");
        return CM_FAILURE;
    }

    if (!IsValidCertScope(scope)) {
        CM_LOG_E("scope[%u] is invalid", scope);
        return CM_FAILURE;
    }

    certScope = static_cast<enum CmCertScope>(scope);
    return CM_SUCCESS;
}

static napi_value GetCertListParseParams(    napi_env env, napi_callback_info info,
    GetCertListAsyncContext context, uint32_t store)
{
    size_t argc = CM_NAPI_GET_CERT_LIST_MAX_ARGS;
    napi_value argv[CM_NAPI_GET_CERT_LIST_MAX_ARGS] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    /* get system ca list */
    if (store == CM_SYSTEM_TRUSTED_STORE) {
        if (argc != CM_NAPI_GET_CERT_LIST_MIN_ARGS) { /* no args when get system ca list */
            ThrowError(env, PARAM_ERROR, "arguments count invalid when getting system trusted certificate list");
            CM_LOG_E("arguments count is not expected when getting system trusted certificate list");
            return nullptr;
        }
        context->store = store;
        return GetInt32(env, 0);
    }

    /* get user ca list */
    if ((argc != CM_NAPI_GET_CERT_LIST_MIN_ARGS) &&
        (argc != CM_NAPI_GET_CERT_LIST_MAX_ARGS)) {
        ThrowError(env, PARAM_ERROR, "arguments count invalid when getting user trusted certificate list");
        CM_LOG_E("arguments count is not expected when getting trusted certificate list");
        return nullptr;
    }

    if (argc == CM_NAPI_GET_CERT_LIST_MAX_ARGS) {
        int32_t ret = GetAndCheckScope(env, argv[0], context->scope);
        if (ret != CM_SUCCESS) {
            ThrowError(env, PARAM_ERROR, "Failed to get scope");
            CM_LOG_E("Failed to get scope when get certlist function");
            return nullptr;
        }
    }

    context->store = store;
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

    uint32_t buffSize = MAX_COUNT_CERTIFICATE_ALL * sizeof(struct CertAbstract);
    context->certificateList->certAbstract = static_cast<struct CertAbstract *>(CmMalloc(buffSize));
    if (context->certificateList->certAbstract == nullptr) {
        CM_LOG_E("malloc certificateList certAbstract fail");
        context->result = CMR_ERROR_MALLOC_FAIL;
        return;
    }
    (void)memset_s(context->certificateList->certAbstract, buffSize, 0, buffSize);
    context->certificateList->certsCount = MAX_COUNT_CERTIFICATE_ALL;

    if (context->store == CM_SYSTEM_TRUSTED_STORE) {
        context->result = CmGetCertList(context->store, context->certificateList);
        return;
    }

    if (context->scope == CM_CURRENT_USER || context->scope == CM_GLOBAL_USER) {
        struct UserCAProperty prop = { INIT_INVALID_VALUE, context->scope };
        context->result = CmGetUserCACertList(&prop, context->certificateList);
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
        result[0] = GenerateBusinessError(env, context->result);
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    }
    if (context->deferred != nullptr) {
        GeneratePromise(env, context->deferred, context->result, result, CM_ARRAY_SIZE(result));
    } else {
        GenerateCallback(env, context->callback, result, CM_ARRAY_SIZE(result), context->result);
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
    CM_LOG_I("get system cert list enter");
    GetCertListAsyncContext context = CreateGetCertListAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        return nullptr;
    }
    napi_value result = GetCertListParseParams(env, info, context, CM_SYSTEM_TRUSTED_STORE);
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
    CM_LOG_I("get system cert list end");
    return result;
}

napi_value CMNapiGetAllUserTrustedCertList(napi_env env, napi_callback_info info)
{
    CM_LOG_I("get all user cert list enter");

    GetCertListAsyncContext context = CreateGetCertListAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("create context failed");
        return nullptr;
    }

    napi_value result = GetCertListParseParams(env, info, context, CM_USER_TRUSTED_STORE);
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

    CM_LOG_I("get all user cert list end");
    return result;
}
}  // namespace CertManagerNapi
