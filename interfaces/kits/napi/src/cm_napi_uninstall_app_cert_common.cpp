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

#include "cm_napi_uninstall_app_cert.h"
#include "cm_napi_uninstall_app_cert_common.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_napi_common.h"

namespace CMNapi {
namespace {
constexpr int CM_NAPI_UNINSTALL_APP_CERT_MIN_ARGS = 1;
constexpr int CM_NAPI_UNINSTALL_APP_CERT_MAX_ARGS = 2;
}  // namespace

UninstallAppCertAsyncContext CreateUninstallAppCertAsyncContext()
{
    UninstallAppCertAsyncContext context =
        static_cast<UninstallAppCertAsyncContext>(CmMalloc(sizeof(UninstallAppCertAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(
            context, sizeof(UninstallAppCertAsyncContextT), 0, sizeof(UninstallAppCertAsyncContextT));
    }
    return context;
}

void DeleteUninstallAppCertAsyncContext(napi_env env, UninstallAppCertAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    DeleteNapiContext(env, context->asyncWork, context->callback);

    if (context->keyUri != nullptr) {
        FreeCmBlob(context->keyUri);
    }

    CmFree(context);
    context = nullptr;
}

napi_value UninstallAppCertParseParams(
    napi_env env, napi_callback_info info, UninstallAppCertAsyncContext context)
{
    size_t argc = CM_NAPI_UNINSTALL_APP_CERT_MAX_ARGS;
    napi_value argv[CM_NAPI_UNINSTALL_APP_CERT_MAX_ARGS] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if ((argc != CM_NAPI_UNINSTALL_APP_CERT_MIN_ARGS) && (argc != CM_NAPI_UNINSTALL_APP_CERT_MAX_ARGS)) {
        ThrowError(env, PARAM_ERROR, "arguments count invalid, arguments count need between 1 and 2.");
        CM_LOG_E("arguments count invalid. argc = %d", argc);
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseString(env, argv[index], context->keyUri);
    if (result == nullptr) {
        ThrowError(env, PARAM_ERROR, "keyUri is not a string or the length is 0 or too long.");
        CM_LOG_E("could not get cert uri");
        return nullptr;
    }

    index++;
    if (index < argc) {
        int32_t ret = GetCallback(env, argv[index], context->callback);
        if (ret != CM_SUCCESS) {
            ThrowError(env, PARAM_ERROR, "Get callback failed, callback must be a function.");
            CM_LOG_E("get callback function faild when uninstall applicaiton cert");
            return nullptr;
        }
    }

    return GetInt32(env, 0);
}

napi_value UninstallAppCertAsyncWork(napi_env env, UninstallAppCertAsyncContext asyncContext)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, asyncContext->callback, &asyncContext->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "UninstallAppCertAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            UninstallAppCertAsyncContext context = static_cast<UninstallAppCertAsyncContext>(data);
            context->result = CmUninstallAppCert(context->keyUri, context->store);
            if (context->store == APPLICATION_PRIVATE_CERTIFICATE_STORE && context->result == CMR_ERROR_NOT_EXIST) {
                context->result = CM_SUCCESS;
            }
        },
        [](napi_env env, napi_status status, void *data) {
            UninstallAppCertAsyncContext context = static_cast<UninstallAppCertAsyncContext>(data);
            napi_value result[RESULT_NUMBER] = { nullptr };
            if (context->result == CM_SUCCESS) {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
                NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
            } else {
                result[0] = GenerateBusinessError(env, context->result);
                NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
            }
            if (context->deferred != nullptr) {
                GeneratePromise(env, context->deferred, context->result, result, CM_ARRAY_SIZE(result));
            } else {
                GenerateCallback(env, context->callback, result, CM_ARRAY_SIZE(result), context->result);
            }
            DeleteUninstallAppCertAsyncContext(env, context);
        },
        static_cast<void *>(asyncContext),
        &asyncContext->asyncWork));

    napi_status status = napi_queue_async_work(env, asyncContext->asyncWork);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteUninstallAppCertAsyncContext(env, asyncContext);
        CM_LOG_E("could not queue async work");
        return nullptr;
    }

    return promise;
}

napi_value CMNapiUninstallAppCertCommon(napi_env env, napi_callback_info info, uint32_t store)
{
    CM_LOG_I("uninstall app cert enter, store = %u", store);

    UninstallAppCertAsyncContext context = CreateUninstallAppCertAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        return nullptr;
    }

    context->store = store;

    napi_value result = UninstallAppCertParseParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("could not parse params");
        DeleteUninstallAppCertAsyncContext(env, context);
        return nullptr;
    }
    result = UninstallAppCertAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("could not start async work");
        DeleteUninstallAppCertAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("uninstall app cert end");
    return result;
}
}  // namespace CertManagerNapi
