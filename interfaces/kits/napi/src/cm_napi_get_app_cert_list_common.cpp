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

#include "cm_napi_get_app_cert_list.h"
#include "cm_napi_get_app_cert_list_common.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_napi_common.h"

namespace CMNapi {
namespace {
constexpr int CM_NAPI_GET_APP_CERT_LIST_MIN_ARGS = 0;
constexpr int CM_NAPI_GET_APP_CERT_LIST_MAX_ARGS = 1;
}  // namespace

GetAppCertListAsyncContext CreateGetAppCertListAsyncContext()
{
    GetAppCertListAsyncContext context =
        static_cast<GetAppCertListAsyncContext>(CmMalloc(sizeof(GetAppCertListAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(GetAppCertListAsyncContextT), 0, sizeof(GetAppCertListAsyncContextT));
    }
    return context;
}

void DeleteGetAppCertListAsyncContext(napi_env env, GetAppCertListAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    DeleteNapiContext(env, context->asyncWork, context->callback);

    if (context->credentialList != nullptr) {
        FreeCredentialList(context->credentialList);
    }

    CmFree(context);
    context = nullptr;
}

napi_value GetAppCertListParseParams(
    napi_env env, napi_callback_info info, GetAppCertListAsyncContext context)
{
    size_t argc = CM_NAPI_GET_APP_CERT_LIST_MAX_ARGS;
    napi_value argv[CM_NAPI_GET_APP_CERT_LIST_MAX_ARGS] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if ((argc != CM_NAPI_GET_APP_CERT_LIST_MIN_ARGS) && (argc != CM_NAPI_GET_APP_CERT_LIST_MAX_ARGS)) {
        ThrowError(env, PARAM_ERROR, "Missing parameter, arguments count need between 0 and 1.");
        CM_LOG_E("Missing parameter");
        return nullptr;
    }

    size_t index = 0;
    if (index < argc) {
        int32_t ret = GetCallback(env, argv[index], context->callback);
        if (ret != CM_SUCCESS) {
            ThrowError(env, PARAM_ERROR, "Get callback failed, callback must be a function.");
            CM_LOG_E("get callback function faild when getting application certificate list");
            return nullptr;
        }
    }

    return GetInt32(env, 0);
}

napi_value GetAppCertListWriteResult(napi_env env, GetAppCertListAsyncContext context)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));
    napi_value credentail = GenerateCredentialAbstractArray(env,
        context->credentialList->credentialAbstract, context->credentialList->credentialCount);
    if (credentail != nullptr) {
        napi_set_named_property(env, result, CM_RESULT_PRPPERTY_CREDENTIAL_LIST.c_str(), credentail);
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    return result;
}

void InitAppCertList(struct CredentialList *credentialList)
{
    uint32_t buffSize = (MAX_COUNT_CERTIFICATE * sizeof(struct CredentialAbstract));
    credentialList->credentialAbstract = static_cast<struct CredentialAbstract *>(CmMalloc(buffSize));
    if (credentialList->credentialAbstract == nullptr) {
        CM_LOG_E("malloc file buffer failed");
        return;
    }
    (void)memset_s(credentialList->credentialAbstract, buffSize, 0, buffSize);
    credentialList->credentialCount = MAX_COUNT_CERTIFICATE;
}

napi_value GetAppCertListAsyncWork(napi_env env, GetAppCertListAsyncContext asyncContext)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, asyncContext->callback, &asyncContext->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "GetAppCertListAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            GetAppCertListAsyncContext context = static_cast<GetAppCertListAsyncContext>(data);

            context->credentialList = static_cast<struct CredentialList *>(CmMalloc(sizeof(struct CredentialList)));
            if (context->credentialList != nullptr) {
                InitAppCertList(context->credentialList);
            }
            context->result = CmGetAppCertList(context->store, context->credentialList);
        },
        [](napi_env env, napi_status status, void *data) {
            GetAppCertListAsyncContext context = static_cast<GetAppCertListAsyncContext>(data);
            napi_value result[RESULT_NUMBER] = { nullptr };
            if (context->result == CM_SUCCESS) {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
                result[1] = GetAppCertListWriteResult(env, context);
            } else {
                result[0] = GenerateBusinessError(env, context->result);
                NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
            }
            if (context->deferred != nullptr) {
                GeneratePromise(env, context->deferred, context->result, result, CM_ARRAY_SIZE(result));
            } else {
                GenerateCallback(env, context->callback, result, CM_ARRAY_SIZE(result), context->result);
            }
            DeleteGetAppCertListAsyncContext(env, context);
            CM_LOG_D("get app cert list end");
        },
        static_cast<void *>(asyncContext),
        &asyncContext->asyncWork));

    napi_status napiStatus = napi_queue_async_work(env, asyncContext->asyncWork);
    if (napiStatus != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteGetAppCertListAsyncContext(env, asyncContext);
        CM_LOG_E("get app cert list could not queue async work");
        return nullptr;
    }
    return promise;
}

napi_value GetCallingAppCertListAsyncWork(napi_env env, GetAppCertListAsyncContext asyncContext)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, asyncContext->callback, &asyncContext->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "GetCallingAppCertListAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *information) {
            GetAppCertListAsyncContext mcontext = static_cast<GetAppCertListAsyncContext>(information);

            mcontext->credentialList = static_cast<struct CredentialList *>(CmMalloc(sizeof(struct CredentialList)));
            if (mcontext->credentialList != nullptr) {
                InitAppCertList(mcontext->credentialList);
            }
            mcontext->result = CmCallingGetAppCertList(mcontext->store, mcontext->credentialList);
        },
        [](napi_env env, napi_status status, void *information) {
            GetAppCertListAsyncContext mcontext = static_cast<GetAppCertListAsyncContext>(information);
            napi_value res[RESULT_NUMBER] = { nullptr };
            if (mcontext->result == CM_SUCCESS) {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &res[0]));
                res[1] = GetAppCertListWriteResult(env, mcontext);
            } else {
                res[0] = GenerateBusinessError(env, mcontext->result);
                NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &res[1]));
            }
            if (mcontext->deferred != nullptr) {
                GeneratePromise(env, mcontext->deferred, mcontext->result, res, CM_ARRAY_SIZE(res));
            } else {
                GenerateCallback(env, mcontext->callback, res, CM_ARRAY_SIZE(res), mcontext->result);
            }
            DeleteGetAppCertListAsyncContext(env, mcontext);
            CM_LOG_D("get calling app cert list end");
        },
        static_cast<void *>(asyncContext),
        &asyncContext->asyncWork));

    napi_status status = napi_queue_async_work(env, asyncContext->asyncWork);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteGetAppCertListAsyncContext(env, asyncContext);
        CM_LOG_E("get calling app cert list could not queue async work");
        return nullptr;
    }
    return promise;
}

napi_value CMNapiGetAppCertListCommon(napi_env env, napi_callback_info info, uint32_t store)
{
    CM_LOG_I("get app cert list enter, store = %u", store);

    GetAppCertListAsyncContext context = CreateGetAppCertListAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        return nullptr;
    }

    context->store = store;

    napi_value result = GetAppCertListParseParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("could not parse params");
        DeleteGetAppCertListAsyncContext(env, context);
        return nullptr;
    }
    result = GetAppCertListAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("could not start async work");
        DeleteGetAppCertListAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("get app cert list end");
    return result;
}

napi_value CMNapiGetCallingAppCertListCommon(napi_env env, napi_callback_info info, uint32_t store)
{
    CM_LOG_I("get calling app cert list enter");

    GetAppCertListAsyncContext context = CreateGetAppCertListAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        return nullptr;
    }

    context->store = store;

    napi_value result = GetAppCertListParseParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("could not parse params");
        DeleteGetAppCertListAsyncContext(env, context);
        return nullptr;
    }
    result = GetCallingAppCertListAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("could not start async work");
        DeleteGetAppCertListAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("get calling app cert list end");
    return result;
}
}  // namespace CertManagerNapi
