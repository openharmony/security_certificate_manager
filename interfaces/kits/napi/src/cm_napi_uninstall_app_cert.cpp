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

#include "cm_napi_uninstall_app_cert.h"

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

struct UninstallAppCertAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct CmBlob *keyUri = nullptr;
    uint32_t store = 0;
};
using UninstallAppCertAsyncContext = UninstallAppCertAsyncContextT *;

static UninstallAppCertAsyncContext CreateUninstallAppCertAsyncContext()
{
    UninstallAppCertAsyncContext context =
        static_cast<UninstallAppCertAsyncContext>(CmMalloc(sizeof(UninstallAppCertAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(
            context, sizeof(UninstallAppCertAsyncContextT), 0, sizeof(UninstallAppCertAsyncContextT));
    }
    return context;
}

static void DeleteUninstallAppCertAsyncContext(napi_env env, UninstallAppCertAsyncContext &context)
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

static napi_value UninstallAppCertParseParams(
    napi_env env, napi_callback_info info, UninstallAppCertAsyncContext context)
{
    size_t argc = CM_NAPI_UNINSTALL_APP_CERT_MAX_ARGS;
    napi_value argv[CM_NAPI_UNINSTALL_APP_CERT_MAX_ARGS] = {0};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < CM_NAPI_UNINSTALL_APP_CERT_MIN_ARGS) {
        napi_throw_error(env, PARAM_TYPE_ERROR_NUMBER.c_str(), "Missing parameter");
        CM_LOG_E("Missing parameter");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseString(env, argv[index], context->keyUri);
    if (result == nullptr) {
        napi_throw_error(env, PARAM_TYPE_ERROR_NUMBER.c_str(), "Type error");
        CM_LOG_E("could not get cert uri");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
    }

    context->store = APPLICATION_CERTIFICATE_STORE; /* 0 is store type, indicate app certificate */
    return GetInt32(env, 0);
}

static napi_value UninstallAppCertAsyncWork(napi_env env, UninstallAppCertAsyncContext context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "UninstallAppCertAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            UninstallAppCertAsyncContext context = static_cast<UninstallAppCertAsyncContext>(data);
            context->result = CmUninstallAppCert(context->keyUri, context->store);
        },
        [](napi_env env, napi_status status, void *data) {
            UninstallAppCertAsyncContext context = static_cast<UninstallAppCertAsyncContext>(data);
            napi_value result[RESULT_NUMBER] = {0};
            if (context->result == CM_SUCCESS) {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
                NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, true, &result[1]));
            } else {
                const char *errorMessage = "uninstall app cert error";
                result[0] = GenerateBusinessError(env, context->result, errorMessage);
                NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
            }
            if (context->deferred != nullptr) {
                GeneratePromise(env, context->deferred, context->result, result, sizeof(result));
            } else {
                GenerateCallback(env, context->callback, result, sizeof(result));
            }
            DeleteUninstallAppCertAsyncContext(env, context);
        },
        (void *)context,
        &context->asyncWork));

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteUninstallAppCertAsyncContext(env, context);
        CM_LOG_E("could not queue async work");
        return nullptr;
    }

    return promise;
}

napi_value CMNapiUninstallAppCert(napi_env env, napi_callback_info info)
{
    UninstallAppCertAsyncContext context = CreateUninstallAppCertAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        return nullptr;
    }

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
    return result;
}
}  // namespace CertManagerNapi
