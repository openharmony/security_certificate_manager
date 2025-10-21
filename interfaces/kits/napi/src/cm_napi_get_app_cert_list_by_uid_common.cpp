/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "cm_napi_get_app_cert_list_by_uid.h"
#include "cm_napi_get_app_cert_list_by_uid_common.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_util.h"
#include "cm_napi_common.h"

namespace CMNapi {
namespace {
constexpr int CM_NAPI_GET_APP_CERT_BY_UID_MIN_ARGS = 1;
}  // namespace

GetAppCertListByUidAsyncContext CreateGetAppCertListByUidAsyncContext()
{
    GetAppCertListByUidAsyncContext context =
        static_cast<GetAppCertListByUidAsyncContext>(CmMalloc(sizeof(GetAppCertListByUidAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(GetAppCertListByUidAsyncContextT), 0, sizeof(GetAppCertListByUidAsyncContextT));
    }
    return context;
}

void DeleteGetAppCertListByUidAsyncContext(napi_env env, GetAppCertListByUidAsyncContext &context)
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

static napi_value ParseString2Uint32(napi_env env, napi_value object, uint32_t &value)
{
    struct CmBlob *blob = nullptr;
    napi_value result = ParseString(env, object, blob);
    if (result == nullptr ||
        CmIsNumeric(reinterpret_cast<char *>(blob->data), static_cast<size_t>(blob->size), &value) != CM_SUCCESS) {
        CM_LOG_E("parse string to uint32 failed");
        if (blob != nullptr) {
            CM_FREE_PTR(blob->data);
            CmFree(blob);
        }
        return nullptr;
    }

    CM_FREE_PTR(blob->data);
    CM_FREE_PTR(blob);
    return GetInt32(env, 0);
}

napi_value GetAppCertListByUidParseParams(
    napi_env env, napi_callback_info info, GetAppCertListByUidAsyncContext context)
{
    size_t argc = CM_NAPI_GET_APP_CERT_BY_UID_MIN_ARGS;
    napi_value argv[CM_NAPI_GET_APP_CERT_BY_UID_MIN_ARGS] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc != CM_NAPI_GET_APP_CERT_BY_UID_MIN_ARGS) {
        ThrowError(env, PARAM_ERROR, "Missing parameter, arguments count need between 0 and 1.");
        CM_LOG_E("Missing parameter");
        return nullptr;
    }
    
    size_t index = 0;
    napi_value result = ParseString2Uint32(env, argv[index], context->appUid);
    if (result == nullptr) {
        ThrowError(env, PARAM_ERROR, "appUid is not a string or the length is 0 or too long.");
        CM_LOG_E("could not get key appUid");
        return nullptr;
    }

    return GetInt32(env, 0);
}

napi_value GetAppCertListByUidWriteResult(napi_env env, GetAppCertListByUidAsyncContext context)
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

static void InitAppCertList(struct CredentialList *credentialList)
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

static void GetAppCertListByUidExecute(napi_env env, void *data)
{
    GetAppCertListByUidAsyncContext context = static_cast<GetAppCertListByUidAsyncContext>(data);
    context->credentialList = static_cast<struct CredentialList *>(CmMalloc(sizeof(struct CredentialList)));
    if (context->credentialList != nullptr) {
        InitAppCertList(context->credentialList);
    }
    context->result = CmGetAppCertListByUid(context->store, context->appUid, context->credentialList);
}

static void GetAppCertListByUidComplete(napi_env env, napi_status status, void *data)
{
    GetAppCertListByUidAsyncContext context = static_cast<GetAppCertListByUidAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->result == CM_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
        result[1] = GetAppCertListByUidWriteResult(env, context);
    } else {
        result[0] = GenerateBusinessError(env, context->result);
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    }
    GeneratePromise(env, context->deferred, context->result, result, CM_ARRAY_SIZE(result));
    DeleteGetAppCertListByUidAsyncContext(env, context);
    CM_LOG_D("get app cert list end");
}

napi_value GetAppCertListByUidAsyncWork(napi_env env, GetAppCertListByUidAsyncContext asyncContext)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, asyncContext->callback, &asyncContext->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "GetAppCertListByUidAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env,
        nullptr,
        resourceName,
        GetAppCertListByUidExecute,
        GetAppCertListByUidComplete,
        static_cast<void *>(asyncContext),
        &asyncContext->asyncWork)
    );
    napi_status napiStatus = napi_queue_async_work(env, asyncContext->asyncWork);
    if (napiStatus != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteGetAppCertListByUidAsyncContext(env, asyncContext);
        CM_LOG_E("get app cert list could not queue async work");
        return nullptr;
    }
    return promise;
}

napi_value CMNapiGetAppCertListByUidCommon(napi_env env, napi_callback_info info, uint32_t store)
{
    CM_LOG_I("get app cert list by uid enter, store = %u", store);

    GetAppCertListByUidAsyncContext context = CreateGetAppCertListByUidAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        return nullptr;
    }

    context->store = store;

    napi_value result = GetAppCertListByUidParseParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("could not parse params");
        DeleteGetAppCertListByUidAsyncContext(env, context);
        return nullptr;
    }
    result = GetAppCertListByUidAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("could not start async work");
        DeleteGetAppCertListByUidAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("get app cert list by uid end");
    return result;
}
}  // namespace CertManagerNapi
