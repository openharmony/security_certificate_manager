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

#include "cm_napi_install_app_cert.h"
#include "cm_napi_install_app_cert_common.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_napi_common.h"

namespace CMNapi {
namespace {
constexpr int CM_NAPI_INSTALL_APP_CERT_MIN_ARGS = 3;
constexpr int CM_NAPI_INSTALL_APP_CERT_MAX_ARGS = 4;
}  // namespace

InstallAppCertAsyncContext CreateInstallAppCertAsyncContext()
{
    InstallAppCertAsyncContext context =
        static_cast<InstallAppCertAsyncContext>(CmMalloc(sizeof(InstallAppCertAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(InstallAppCertAsyncContextT), 0, sizeof(InstallAppCertAsyncContextT));
    }
    return context;
}

void DeleteInstallAppCertAsyncContext(napi_env env, InstallAppCertAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    DeleteNapiContext(env, context->asyncWork, context->callback);

    if (context->keystore != nullptr) {
        FreeCmBlob(context->keystore);
    }

    if (context->keystorePwd != nullptr) {
        FreeCmBlob(context->keystorePwd);
    }

    if (context->keyAlias != nullptr) {
        FreeCmBlob(context->keyAlias);
    }

    if (context->keyUri != nullptr) {
        FreeCmBlob(context->keyUri);
    }

    CmFree(context);
    context = nullptr;
}

napi_value InstallAppCertParseParams(
    napi_env env, napi_callback_info info, InstallAppCertAsyncContext context)
{
    size_t argc = CM_NAPI_INSTALL_APP_CERT_MAX_ARGS;
    napi_value argv[CM_NAPI_INSTALL_APP_CERT_MAX_ARGS] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < CM_NAPI_INSTALL_APP_CERT_MIN_ARGS) {
        ThrowParamsError(env, PARAM_ERROR, "Missing parameter");
        CM_LOG_E("Missing parameter");
        return nullptr;
    }

    size_t index = 0;
    context->keystore = static_cast<CmBlob *>(CmMalloc(sizeof(CmBlob)));
    if (context->keystore == nullptr) {
        CM_LOG_E("could not alloc memory");
        return nullptr;
    }
    (void)memset_s(context->keystore, sizeof(CmBlob), 0, sizeof(CmBlob));

    napi_value result = GetUint8Array(env, argv[index], *context->keystore);
    if (result == nullptr) {
        ThrowParamsError(env, PARAM_ERROR, "get keystore type error");
        CM_LOG_E("could not get keystore");
        return nullptr;
    }

    index++;
    result = ParseString(env, argv[index], context->keystorePwd);
    if (result == nullptr) {
        ThrowParamsError(env, PARAM_ERROR, "get keystore Pwd type error");
        CM_LOG_E("could not get keystore Pwd");
        return nullptr;
    }

    index++;
    result = ParseString(env, argv[index], context->keyAlias);
    if (result == nullptr) {
        ThrowParamsError(env, PARAM_ERROR, "get keyAlias type error");
        CM_LOG_E("could not get uri");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
        if (context->callback == nullptr) {
            ThrowParamsError(env, PARAM_ERROR, "Get callback type error");
            CM_LOG_E("get callback function faild when install application cert");
            return nullptr;
        }
    }

    return GetInt32(env, 0);
}

static void InitKeyUri(struct CmBlob *&keyUri)
{
    keyUri = static_cast<struct CmBlob *>(CmMalloc(sizeof(struct CmBlob)));
    if (keyUri == nullptr) {
        CM_LOG_E("malloc keyUri buffer failed");
        return;
    }

    keyUri->data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_URI));
    if (keyUri->data == nullptr) {
        CM_LOG_E("malloc keyUri->data buffer failed");
        return;
    }

    (void)memset_s(keyUri->data, MAX_LEN_URI, 0, MAX_LEN_URI);
    keyUri->size = MAX_LEN_URI;
}

static napi_value InstallAppCertWriteResult(napi_env env, InstallAppCertAsyncContext context)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));

    napi_value keyUri = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, reinterpret_cast<char *>(context->keyUri->data),
        NAPI_AUTO_LENGTH, &keyUri));
    if (keyUri != nullptr) {
        napi_set_named_property(env, result, CM_CERT_PROPERTY_URI.c_str(), keyUri);
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    return result;
}

napi_value InstallAppCertAsyncWork(napi_env env, InstallAppCertAsyncContext asyncContext)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, asyncContext->callback, &asyncContext->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "InstallAppCertAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            InstallAppCertAsyncContext context = static_cast<InstallAppCertAsyncContext>(data);
            InitKeyUri(context->keyUri);
            context->result = CmInstallAppCert(context->keystore,
                context->keystorePwd, context->keyAlias, context->store, context->keyUri);
        },
        [](napi_env env, napi_status status, void *data) {
            InstallAppCertAsyncContext context = static_cast<InstallAppCertAsyncContext>(data);
            napi_value result[RESULT_NUMBER] = { nullptr };
            if (context->result == CM_SUCCESS) {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
                result[1] = InstallAppCertWriteResult(env, context);
            } else {
                const char *errorMsg = "install app cert error";
                result[0] = GenerateBusinessError(env, context->result, errorMsg);
                NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
            }
            if (context->deferred != nullptr) {
                GeneratePromise(env, context->deferred, context->result, result, sizeof(result));
            } else {
                GenerateCallback(env, context->callback, result, sizeof(result));
            }
            DeleteInstallAppCertAsyncContext(env, context);
        },
        static_cast<void *>(asyncContext),
        &asyncContext->asyncWork));

    napi_status status = napi_queue_async_work(env, asyncContext->asyncWork);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteInstallAppCertAsyncContext(env, asyncContext);
        CM_LOG_E("could not queue async work");
        return nullptr;
    }
    return promise;
}

napi_value CMNapiInstallAppCertCommon(napi_env env, napi_callback_info info, uint32_t store)
{
    InstallAppCertAsyncContext context = CreateInstallAppCertAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        return nullptr;
    }

    context->store = store;

    napi_value result = InstallAppCertParseParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("could not parse params");
        DeleteInstallAppCertAsyncContext(env, context);
        return nullptr;
    }
    result = InstallAppCertAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("could not start async work");
        DeleteInstallAppCertAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}  // namespace CertManagerNapi
