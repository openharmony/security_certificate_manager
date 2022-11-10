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

#include "cm_napi_get_app_cert_info.h"
#include "cm_napi_get_app_cert_info_common.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_napi_common.h"

namespace CMNapi {
namespace {
constexpr int CM_NAPI_GET_APP_CERT_INFO_MIN_ARGS = 1;
constexpr int CM_NAPI_GET_APP_CERT_INFO_MAX_ARGS = 2;
}  // namespace

GetAppCertInfoAsyncContext CreateGetAppCertInfoAsyncContext()
{
    GetAppCertInfoAsyncContext context =
        static_cast<GetAppCertInfoAsyncContext>(CmMalloc(sizeof(GetAppCertInfoAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(GetAppCertInfoAsyncContextT), 0, sizeof(GetAppCertInfoAsyncContextT));
    }
    return context;
}

void DeleteGetAppCertInfoAsyncContext(napi_env env, GetAppCertInfoAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    DeleteNapiContext(env, context->asyncWork, context->callback);

    if (context->keyUri != nullptr) {
        FreeCmBlob(context->keyUri);
    }

    if (context->credential != nullptr) {
        FreeCredential(context->credential);
    }

    CmFree(context);
    context = nullptr;
}

napi_value GetAppCertInfoParseParams(
    napi_env env, napi_callback_info info, GetAppCertInfoAsyncContext context)
{
    size_t argc = CM_NAPI_GET_APP_CERT_INFO_MAX_ARGS;
    napi_value argv[CM_NAPI_GET_APP_CERT_INFO_MAX_ARGS] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc < CM_NAPI_GET_APP_CERT_INFO_MIN_ARGS) {
        ThrowParamsError(env, PARAM_ERROR, "Missing parameter");
        CM_LOG_E("Missing parameter when getting application cert info");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseString(env, argv[index], context->keyUri);
    if (result == nullptr) {
        ThrowParamsError(env, PARAM_ERROR, "get keyUri type error");
        CM_LOG_E("could not get key uri");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
        if (context->callback == nullptr) {
            ThrowParamsError(env, PARAM_ERROR, "Get callback type error");
            CM_LOG_E("get callback function faild when getting application cert info");
            return nullptr;
        }
    }

    return GetInt32(env, 0);
}

napi_value GetAppCertInfoWriteResult(napi_env env, GetAppCertInfoAsyncContext context)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));
    napi_value certInfo = GenerateAppCertInfo(env, context->credential);
    if (certInfo != nullptr) {
        napi_set_named_property(env, result, CM_RESULT_PRPPERTY_CREDENTIAL.c_str(), certInfo);
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    return result;
}

static void InitAppCert(struct Credential *credential)
{
    credential->credData.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE_CHAIN));
    if (credential->credData.data == nullptr) {
        CM_LOG_E("malloc file buffer failed");
        return;
    }
    (void)memset_s(credential->credData.data, MAX_LEN_CERTIFICATE_CHAIN, 0, MAX_LEN_CERTIFICATE_CHAIN);
    credential->credData.size = MAX_LEN_CERTIFICATE_CHAIN;
}

napi_value GetAppCertInfoAsyncWork(napi_env env, GetAppCertInfoAsyncContext asyncContext)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, asyncContext->callback, &asyncContext->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "GetAppCertInfoAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            GetAppCertInfoAsyncContext context = static_cast<GetAppCertInfoAsyncContext>(data);

            context->credential = static_cast<struct Credential *>(CmMalloc(sizeof(struct Credential)));
            if (context->credential != nullptr) {
                (void)memset_s(context->credential, sizeof(struct Credential), 0, sizeof(struct Credential));
                InitAppCert(context->credential);
            }
            context->result = CmGetAppCert(context->keyUri, context->store, context->credential);
        },
        [](napi_env env, napi_status status, void *data) {
            GetAppCertInfoAsyncContext context = static_cast<GetAppCertInfoAsyncContext>(data);
            napi_value result[RESULT_NUMBER] = { nullptr };
            if (context->result == CM_SUCCESS) {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
                result[1] = GetAppCertInfoWriteResult(env, context);
            } else {
                const char *errorMsg = "get app cert info error";
                result[0] = GenerateBusinessError(env, context->result, errorMsg);
                NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
            }
            if (context->deferred != nullptr) {
                GeneratePromise(env, context->deferred, context->result, result, sizeof(result));
            } else {
                GenerateCallback(env, context->callback, result, sizeof(result));
            }
            DeleteGetAppCertInfoAsyncContext(env, context);
        },
        static_cast<void *>(asyncContext),
        &asyncContext->asyncWork));

    napi_status status = napi_queue_async_work(env, asyncContext->asyncWork);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteGetAppCertInfoAsyncContext(env, asyncContext);
        CM_LOG_E("could not queue async work");
        return nullptr;
    }

    return promise;
}

napi_value CMNapiGetAppCertInfoCommon(napi_env env, napi_callback_info info, uint32_t store)
{
    GetAppCertInfoAsyncContext context = CreateGetAppCertInfoAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        return nullptr;
    }

    context->store = store;

    napi_value result = GetAppCertInfoParseParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("could not parse params");
        DeleteGetAppCertInfoAsyncContext(env, context);
        return nullptr;
    }
    result = GetAppCertInfoAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("could not start async work");
        DeleteGetAppCertInfoAsyncContext(env, context);
        return nullptr;
    }
    return result;
}
}  // namespace CertManagerNapi
