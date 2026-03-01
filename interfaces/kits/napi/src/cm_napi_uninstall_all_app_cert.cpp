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

#include "cm_napi_uninstall_all_app_cert.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_napi_common.h"

namespace CMNapi {

struct UninstallAllAppCertAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;

    int32_t result = 0;
};
using UninstallAllAppCertAsyncContext = UninstallAllAppCertAsyncContextT *;

static UninstallAllAppCertAsyncContext CreateUninstallAllAppCertAsyncContext()
{
    UninstallAllAppCertAsyncContext context =
        static_cast<UninstallAllAppCertAsyncContext>(CmMalloc(sizeof(UninstallAllAppCertAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(
            context, sizeof(UninstallAllAppCertAsyncContextT), 0, sizeof(UninstallAllAppCertAsyncContextT));
    }
    return context;
}

static void DeleteUninstallAllAppCertAsyncContext(napi_env env, UninstallAllAppCertAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    if (context->asyncWork != nullptr) {
        napi_delete_async_work(env, context->asyncWork);
    }

    CmFree(context);
    context = nullptr;
}

static napi_value UninstallAllAppCertParseParams(
    napi_env env, napi_callback_info info, UninstallAllAppCertAsyncContext context)
{
    size_t argc = 0;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr));

    if (argc != 0) {
        ThrowError(env, PARAM_ERROR, "Missing parameter");
        CM_LOG_E("Missing parameter");
        return nullptr;
    }

    return GetInt32(env, 0);
}

static napi_value UninstallAllAppCertAsyncWork(napi_env env, UninstallAllAppCertAsyncContext asyncContext)
{
    napi_value promise = nullptr;
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "UninstallAllAppCertAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &promise));

    NAPI_CALL(env, napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            UninstallAllAppCertAsyncContext context = static_cast<UninstallAllAppCertAsyncContext>(data);
            context->result = CmUninstallAllAppCert();
        },
        [](napi_env env, napi_status status, void *data) {
            UninstallAllAppCertAsyncContext context = static_cast<UninstallAllAppCertAsyncContext>(data);
            napi_value result[RESULT_NUMBER] = { nullptr };
            if (context->result == CM_SUCCESS) {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
                NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, true, &result[1]));
            } else {
                result[0] = GenerateBusinessError(env, context->result);
                NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
            }
            GeneratePromise(env, context->deferred, context->result, result, CM_ARRAY_SIZE(result));
            DeleteUninstallAllAppCertAsyncContext(env, context);
        },
        static_cast<void *>(asyncContext),
        &asyncContext->asyncWork));

    napi_status status = napi_queue_async_work(env, asyncContext->asyncWork);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteUninstallAllAppCertAsyncContext(env, asyncContext);
        CM_LOG_E("could not queue async work");
        return nullptr;
    }

    return promise;
}

napi_value CMNapiUninstallAllAppCert(napi_env env, napi_callback_info info)
{
    CM_LOG_I("uninstall all app cert enter");

    UninstallAllAppCertAsyncContext context = CreateUninstallAllAppCertAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = UninstallAllAppCertParseParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("could not parse params");
        DeleteUninstallAllAppCertAsyncContext(env, context);
        return nullptr;
    }
    result = UninstallAllAppCertAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("could not start async work");
        DeleteUninstallAllAppCertAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("uninstall all app cert end");
    return result;
}
}  // namespace CertManagerNapi
