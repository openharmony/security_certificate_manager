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
#include "cm_metrics.h"

namespace CMNapi {
namespace {
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
    size_t argc = 1;
    napi_value argv[1] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if ((context->store != APPLICATION_PRIVATE_CERTIFICATE_STORE && argc != 0) ||
        (context->store == APPLICATION_PRIVATE_CERTIFICATE_STORE && argc > 1)) {
        ThrowError(env, PARAM_ERROR, "arguments count invalid, arguments count need 0.", context->metricsReport.get());
        CM_LOG_E("Missing parameter");
        return nullptr;
    }

    size_t index = 0;
    if (index < argc) {
        int32_t ret = GetCallback(env, argv[index], context->callback);
        if (ret != CM_SUCCESS) {
            ThrowError(env, PARAM_ERROR, "Get callback failed, callback must be a function.", context->metricsReport.get());
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

static void GetAppCertListExecute(napi_env env, void *data)
{
    GetAppCertListAsyncContext context = static_cast<GetAppCertListAsyncContext>(data);
    context->credentialList = static_cast<struct CredentialList *>(CmMalloc(sizeof(struct CredentialList)));
    if (context->credentialList == nullptr) {
        CM_LOG_E("malloc credentialList fail");
        context->result = CMR_ERROR_MALLOC_FAIL;
        return;
    }
    context->credentialList->credentialAbstract = nullptr;
    context->credentialList->credentialCount = 0;
    context->result = CmGetAppCertList(context->store, context->credentialList);
}

static void GetAppCertListComplete(napi_env env, napi_status status, void *data)
{
    GetAppCertListAsyncContext context = static_cast<GetAppCertListAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->result == CM_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
        result[1] = GetAppCertListWriteResult(env, context);
        if (context->metricsReport != nullptr) {
            context->metricsReport->Finish(CM_SUCCESS);
        }
    } else {
        result[0] = GenerateBusinessError(env, context->result, context->metricsReport.get());
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    }
    if (context->deferred != nullptr) {
        GeneratePromise(env, context->deferred, context->result, result, CM_ARRAY_SIZE(result));
    } else {
        GenerateCallback(env, context->callback, result, CM_ARRAY_SIZE(result), context->result);
    }
    DeleteGetAppCertListAsyncContext(env, context);
    CM_LOG_D("get app cert list end");
}

napi_value GetAppCertListAsyncWork(napi_env env, GetAppCertListAsyncContext &asyncContext)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, asyncContext->callback, &asyncContext->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "GetAppCertListAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env,
        nullptr,
        resourceName,
        GetAppCertListExecute,
        GetAppCertListComplete,
        static_cast<void *>(asyncContext),
        &asyncContext->asyncWork));

    napi_status napiStatus = napi_queue_async_work(env, asyncContext->asyncWork);
    if (napiStatus != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        CM_LOG_E("get app cert list could not queue async work");
        return nullptr;
    }
    return promise;
}

static void GetCallingAppCertListExecute(napi_env env, void *data)
{
    GetAppCertListAsyncContext mcontext = static_cast<GetAppCertListAsyncContext>(data);

    mcontext->credentialList = static_cast<struct CredentialList *>(CmMalloc(sizeof(struct CredentialList)));
    if (mcontext->credentialList == nullptr) {
        CM_LOG_E("malloc credentialList fail");
        mcontext->result = CMR_ERROR_MALLOC_FAIL;
        return;
    }
    mcontext->credentialList->credentialAbstract = nullptr;
    mcontext->credentialList->credentialCount = 0;
    mcontext->result = CmCallingGetAppCertList(mcontext->store, mcontext->credentialList);
}

static void GetCallingAppCertListComplete(napi_env env, napi_status status, void *data)
{
    GetAppCertListAsyncContext mcontext = static_cast<GetAppCertListAsyncContext>(data);
    napi_value res[RESULT_NUMBER] = { nullptr };
    if (mcontext->result == CM_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &res[0]));
        res[1] = GetAppCertListWriteResult(env, mcontext);
        if (mcontext->metricsReport != nullptr) {
            mcontext->metricsReport->Finish(CM_SUCCESS);
        }
    } else {
        res[0] = GenerateBusinessError(env, mcontext->result, mcontext->metricsReport.get());
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &res[1]));
    }
    GeneratePromise(env, mcontext->deferred, mcontext->result, res, CM_ARRAY_SIZE(res));
    DeleteGetAppCertListAsyncContext(env, mcontext);
    CM_LOG_D("get calling app cert list end");
}

napi_value GetCallingAppCertListAsyncWork(napi_env env, GetAppCertListAsyncContext &asyncContext)
{
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &promise));

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "GetCallingAppCertListAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env,
        nullptr,
        resourceName,
        GetCallingAppCertListExecute,
        GetCallingAppCertListComplete,
        static_cast<void *>(asyncContext),
        &asyncContext->asyncWork));

    napi_status status = napi_queue_async_work(env, asyncContext->asyncWork);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
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

    // 根据 store 选择对应的 JS 接口名,启动打点
    const char *jsName = "getAllAppCertificates";
    if (store == APPLICATION_CERTIFICATE_STORE) {
        jsName = "getAllPublicCertificates";
    } else if (store == APPLICATION_PRIVATE_CERTIFICATE_STORE) {
        jsName = "getAllAppPrivateCertificates";
    } else if (store == APPLICATION_SYSTEM_CERTIFICATE_STORE) {
        jsName = "getAllSystemAppCertificates";
    }
    auto report = std::make_shared<OHOS::Security::CertManager::CmMetricsReport>(
        jsName, OHOS::Security::CertManager::ERROR_CODE_COUNT);
    report->Start();
    context->metricsReport = report;

    result = GetAppCertListAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("could not start async work");
        report->Finish(OHOS::Security::CertManager::INNER_FAILURE);
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

    // getCallingAppCertListCommon 对应的 JS 接口固定为 getPrivateCertificates
    auto report = std::make_shared<OHOS::Security::CertManager::CmMetricsReport>(
        "getPrivateCertificates", OHOS::Security::CertManager::ERROR_CODE_COUNT);
    report->Start();
    context->metricsReport = report;

    result = GetCallingAppCertListAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("could not start async work");
        report->Finish(OHOS::Security::CertManager::INNER_FAILURE);
        DeleteGetAppCertListAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("get calling app cert list end");
    return result;
}
}  // namespace CertManagerNapi
