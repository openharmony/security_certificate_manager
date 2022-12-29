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

#include "cm_napi_uninstall_all_app_cert.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_napi_common.h"

namespace CMNapi {
namespace {
constexpr int CM_NAPI_UNINSTALL_ALL_APP_CERT_MIN_ARGS = 0;
constexpr int CM_NAPI_UNINSTALL_ALL_APP_CERT_MAX_ARGS = 1;
}  // namespace

struct UninstallAllAppCertAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
};
using UninstallAllAppCertAsyncContext = UninstallAllAppCertAsyncContextT *;

static UninstallAllAppCertAsyncContext CreateUinstallAllAppCertAsyncContext()
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

    DeleteNapiContext(env, context->asyncWork, context->callback);

    CmFree(context);
    context = nullptr;
}

static napi_value UninstallAllAppCertParseParams(
    napi_env env, napi_callback_info info, UninstallAllAppCertAsyncContext context)
{
    size_t argc = CM_NAPI_UNINSTALL_ALL_APP_CERT_MAX_ARGS;
    napi_value argv[CM_NAPI_UNINSTALL_ALL_APP_CERT_MAX_ARGS] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if ((argc != CM_NAPI_UNINSTALL_ALL_APP_CERT_MIN_ARGS) && (argc != CM_NAPI_UNINSTALL_ALL_APP_CERT_MAX_ARGS)) {
        ThrowParamsError(env, PARAM_ERROR, "Missing parameter");
        CM_LOG_E("Missing parameter");
        return nullptr;
    }

    size_t index = 0;

    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
    }

    return GetInt32(env, 0);
}

static napi_value UninstallAllAppCertAsyncWork(napi_env env, UninstallAllAppCertAsyncContext asyncContext)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, asyncContext->callback, &asyncContext->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "UninstallAllAppCertAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

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
                const char *errorMsg = "uninstall all app cert error";
                result[0] = GenerateBusinessError(env, context->result, errorMsg);
                NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
            }
            if (context->deferred != nullptr) {
                GeneratePromise(env, context->deferred, context->result, result, sizeof(result));
            } else {
                GenerateCallback(env, context->callback, result, sizeof(result));
            }
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
    UninstallAllAppCertAsyncContext context = CreateUinstallAllAppCertAsyncContext();
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
    return result;
}
}  // namespace CertManagerNapi
