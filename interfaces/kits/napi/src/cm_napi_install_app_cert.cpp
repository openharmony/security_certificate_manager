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

struct InstallAppCertAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t result = 0;
    struct CmBlob *keystore = nullptr;
    struct CmBlob *keystorePwd = nullptr;
    struct CmBlob *keyAlias = nullptr;
    struct CmBlob *keyUri = nullptr;
    uint32_t store = 0;
};
using InstallAppCertAsyncContext = InstallAppCertAsyncContextT *;

static InstallAppCertAsyncContext CreateInstallAppCertAsyncContext()
{
    InstallAppCertAsyncContext context =
        static_cast<InstallAppCertAsyncContext>(CmMalloc(sizeof(InstallAppCertAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(InstallAppCertAsyncContextT), 0, sizeof(InstallAppCertAsyncContextT));
    }
    return context;
}

static void DeleteInstallAppCertAsyncContext(napi_env env, InstallAppCertAsyncContext &context)
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

static napi_value InstallAppCertParseParams(
    napi_env env, napi_callback_info info, InstallAppCertAsyncContext context)
{
    size_t argc = CM_NAPI_INSTALL_APP_CERT_MAX_ARGS;
    napi_value argv[CM_NAPI_INSTALL_APP_CERT_MAX_ARGS] = {0};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < CM_NAPI_INSTALL_APP_CERT_MIN_ARGS) {
        napi_throw_error(env, PARAM_TYPE_ERROR_NUMBER.c_str(), "Missing parameter");
        CM_LOG_E("Missing parameter");
        return nullptr;
    }

    size_t index = 0;
    context->keystore = (CmBlob *)CmMalloc(sizeof(CmBlob));
    if (context->keystore == nullptr) {
        CM_LOG_E("could not alloc memory");
        return nullptr;
    }
    (void)memset_s(context->keystore, sizeof(CmBlob), 0, sizeof(CmBlob));

    napi_value result = GetUint8Array(env, argv[index], *context->keystore);
    if (result == nullptr) {
        napi_throw_error(env, PARAM_TYPE_ERROR_NUMBER.c_str(), "Type error");
        CM_LOG_E("could not get keystore");
        return nullptr;
    }

    index++;
    result = ParseString(env, argv[index], context->keystorePwd);
    if (result == nullptr) {
        napi_throw_error(env, PARAM_TYPE_ERROR_NUMBER.c_str(), "Type error");
        CM_LOG_E("could not get keystore Pwd");
        return nullptr;
    }

    index++;
    result = ParseString(env, argv[index], context->keyAlias);
    if (result == nullptr) {
        napi_throw_error(env, PARAM_TYPE_ERROR_NUMBER.c_str(), "Type error");
        CM_LOG_E("could not get uri");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
    }

    context->store = APPLICATION_CERTIFICATE_STORE;
    return GetInt32(env, 0);
}

static void InitKeyUri(struct CmBlob *&keyUri)
{
    keyUri = (struct CmBlob *)CmMalloc(sizeof(struct CmBlob));
    if (keyUri == NULL) {
        CM_LOG_E("malloc keyUri buffer failed");
        return;
    }

    keyUri->data = (uint8_t *)CmMalloc(MAX_LEN_URI);
    if (keyUri->data == NULL) {
        CM_LOG_E("malloc keyUri->data buffer failed");
        return;
    }

    (void)memset_s(keyUri->data, MAX_LEN_URI, 0, MAX_LEN_URI);
    keyUri->size = MAX_LEN_URI;
}

static napi_value InstallAppCertAsyncWork(napi_env env, InstallAppCertAsyncContext context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

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
            napi_value result[RESULT_NUMBER] = {0};
            if (context->result == CM_SUCCESS) {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
                NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, true, &result[1]));
            } else {
                const char *errorMessage = "install app cert error";
                result[0] = GenerateBusinessError(env, context->result, errorMessage);
                NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
            }
            if (context->deferred != nullptr) {
                GeneratePromise(env, context->deferred, context->result, result, sizeof(result));
            } else {
                GenerateCallback(env, context->callback, result, sizeof(result));
            }
            DeleteInstallAppCertAsyncContext(env, context);
        },
        (void *)context,
        &context->asyncWork));

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteInstallAppCertAsyncContext(env, context);
        CM_LOG_E("could not queue async work");
        return nullptr;
    }
    return promise;
}

napi_value CMNapiInstallAppCert(napi_env env, napi_callback_info info)
{
    InstallAppCertAsyncContext context = CreateInstallAppCertAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        return nullptr;
    }

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
