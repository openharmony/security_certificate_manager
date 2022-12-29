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

#include "cm_napi_set_cert_status.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_napi_common.h"

namespace CMNapi {
namespace {
constexpr int CM_NAPI_SET_CERT_STATUS_MIN_ARGS = 4;
constexpr int CM_NAPI_SET_CERT_STATUS_MAX_ARGS = 5;
}  // namespace

struct SetCertStatusAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct CmContext *cmContext = nullptr;
    struct CmBlob *certUri = nullptr;
    uint32_t store = 0;
    bool status = false;
};
using SetCertStatusAsyncContext = SetCertStatusAsyncContextT *;

static SetCertStatusAsyncContext CreateSetCertStatusAsyncContext()
{
    SetCertStatusAsyncContext context =
        static_cast<SetCertStatusAsyncContext>(CmMalloc(sizeof(SetCertStatusAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(
            context, sizeof(SetCertStatusAsyncContextT), 0, sizeof(SetCertStatusAsyncContextT));
    }
    return context;
}

static void DeleteSetCertStatusAsyncContext(napi_env env, SetCertStatusAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    DeleteNapiContext(env, context->asyncWork, context->callback);

    if (context->certUri != nullptr) {
        FreeCmBlob(context->certUri);
    }

    if (context->cmContext != nullptr) {
        FreeCmContext(context->cmContext);
    }

    CmFree(context);
    context = nullptr;
}

static napi_value SetCertStatusParseParams(
    napi_env env, napi_callback_info info, SetCertStatusAsyncContext context)
{
    size_t argc = CM_NAPI_SET_CERT_STATUS_MAX_ARGS;
    napi_value argv[CM_NAPI_SET_CERT_STATUS_MAX_ARGS] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < CM_NAPI_SET_CERT_STATUS_MIN_ARGS) {
        ThrowParamsError(env, PARAM_ERROR, "Missing parameter");
        CM_LOG_E("CertStatus Missing parameter");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseCmContext(env, argv[index], context->cmContext);
    if (result == nullptr) {
        ThrowParamsError(env, PARAM_ERROR, "get context type error");
        CM_LOG_E("get context failed");
        return nullptr;
    }

    index++;
    result = ParseString(env, argv[index], context->certUri);
    if (result == nullptr) {
        ThrowParamsError(env, PARAM_ERROR, "get certUri type error");
        CM_LOG_E("could not get cert uri when set cert status");
        return nullptr;
    }

    index++;
    result = ParseUint32(env, argv[index], context->store);
    if (result == nullptr) {
        ThrowParamsError(env, PARAM_ERROR, "get store type error");
        CM_LOG_E("could not get store");
        return nullptr;
    }

    index++;
    result = ParseBoolean(env, argv[index], context->status);
    if (result == nullptr) {
        ThrowParamsError(env, PARAM_ERROR, "get status type error");
        CM_LOG_E("could not get status");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
    }
    return GetInt32(env, 0);
}

static void SetCertStatusExecute(napi_env env, void *data)
{
    SetCertStatusAsyncContext context = static_cast<SetCertStatusAsyncContext>(data);
    if (context->store == CM_SYSTEM_TRUSTED_STORE) {
        context->result = CmSetCertStatus(context->certUri, context->store,
            context->status);
    } else if (context->store == CM_USER_TRUSTED_STORE) {
        context->result = CmSetUserCertStatus(context->certUri, context->store, context->status);
    } else {
        context->result = CMR_ERROR_INVALID_ARGUMENT;
    }
}

static void SetCertStatusComplete(napi_env env, napi_status status, void *data)
{
    SetCertStatusAsyncContext context = static_cast<SetCertStatusAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->result == CM_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, true, &result[1]));
    } else {
        const char *errorMsg = "set cert status error";
        result[0] = GenerateBusinessError(env, context->result, errorMsg);
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    }
    if (context->deferred != nullptr) {
        GeneratePromise(env, context->deferred, context->result, result, sizeof(result));
    } else {
        GenerateCallback(env, context->callback, result, sizeof(result));
    }
    DeleteSetCertStatusAsyncContext(env, context);
}

static napi_value SetCertStatusAsyncWork(napi_env env, SetCertStatusAsyncContext context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "SetCertStatusAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env,
        nullptr,
        resourceName,
        SetCertStatusExecute,
        SetCertStatusComplete,
        static_cast<void *>(context),
        &context->asyncWork));

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteSetCertStatusAsyncContext(env, context);
        CM_LOG_E("could not queue async work");
        return nullptr;
    }
    return promise;
}

napi_value CMNapiSetCertStatus(napi_env env, napi_callback_info info)
{
    SetCertStatusAsyncContext context = CreateSetCertStatusAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = SetCertStatusParseParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("could not parse params");
        DeleteSetCertStatusAsyncContext(env, context);
        return nullptr;
    }
    result = SetCertStatusAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("could not start async work");
        DeleteSetCertStatusAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}  // namespace CertManagerNapi
