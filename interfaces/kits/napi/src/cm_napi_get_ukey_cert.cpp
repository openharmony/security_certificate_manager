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

#include "cm_napi_get_ukey_cert.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_util.h"
#include "cm_napi_common.h"

namespace CMNapi {
namespace {
constexpr int CM_NAPI_GET_UKEY_CERT_LIST_ARGS = 2;
}  // namespace

struct GetUkeyCertAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    struct CmBlob *keyUri = nullptr;
    struct UkeyInfo *ukeyInfo = nullptr;
    struct CredentialDetailList *certificateList = nullptr;
    int32_t result = 0;
};
using GetUkeyCertAsyncContext = GetUkeyCertAsyncContextT *;

static GetUkeyCertAsyncContext CreateGetUkeyCertAsyncContext()
{
    GetUkeyCertAsyncContext context =
        static_cast<GetUkeyCertAsyncContext>(CmMalloc(sizeof(GetUkeyCertAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(
            context, sizeof(GetUkeyCertAsyncContextT), 0, sizeof(GetUkeyCertAsyncContextT));
    }
    return context;
}

static void DeleteGetUkeyCertAsyncContext(napi_env env, GetUkeyCertAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    DeleteNapiContext(env, context->asyncWork, context->callback);

    if (context->keyUri != nullptr) {
        FreeCmBlob(context->keyUri);
    }

    if (context->certificateList != nullptr) {
        FreeUkeyCertList(context->certificateList);
    }

    if (context->ukeyInfo != nullptr) {
        CM_FREE_PTR(context->ukeyInfo);
    }

    CmFree(context);
    context = nullptr;
}

static napi_value GetUkeyCertWriteResult(napi_env env, GetUkeyCertAsyncContext context)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));
    napi_value certificateListValue = GenerateCredentialArray(env,
        context->certificateList->credential, context->certificateList->credentialCount);
    if (certificateListValue != nullptr) {
        napi_set_named_property(env, result, CM_RESULT_PROPERTY_CREDENTIAL_DETAIL_LIST.c_str(), certificateListValue);
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &result));
    }
    return result;
}

static bool CheckCertPurpose(uint32_t certPurpose)
{
    switch (certPurpose) {
        case CM_CERT_PURPOSE_DEFAULT:
        case CM_CERT_PURPOSE_ALL:
        case CM_CERT_PURPOSE_SIGN:
        case CM_CERT_PURPOSE_ENCRYPT:
            return true;
        default:
            CM_LOG_E("invalid cert purpose: %u", certPurpose);
            return false;
    }
}

static napi_value ParseUkeyInfo(napi_env env, napi_value object, GetUkeyCertAsyncContext context)
{
    bool hasProperty = false;
    napi_status status = napi_has_named_property(env, object, CM_CERT_PURPOSE.c_str(), &hasProperty);
    if (status != napi_ok) {
        CM_LOG_E("Failed to check certPurpose");
        return nullptr;
    }
    if (!hasProperty) {
        CM_LOG_E("certPurpose is undefined, set certPurpose value is default");
        if (context->ukeyInfo == nullptr) {
            CM_LOG_E("ukeyInfo is nullptr");
            return nullptr;
        }
        context->ukeyInfo->certPurpose = CM_CERT_PURPOSE_DEFAULT;
        return GetInt32(env, 0);
    }
    napi_value certPurposeValue = nullptr;
    status = napi_get_named_property(env, object, CM_CERT_PURPOSE.c_str(), &certPurposeValue);
    if (status != napi_ok || certPurposeValue == nullptr) {
        CM_LOG_E("Failed to get certPurpose");
        return nullptr;
    }
    napi_valuetype type = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, certPurposeValue, &type));
    if (type == napi_undefined) {
        context->ukeyInfo->certPurpose = CM_CERT_PURPOSE_DEFAULT;
        CM_LOG_D("certPurpose is undefined, set digest value is default");
        return GetInt32(env, 0);
    }
    if (type != napi_number) {
        CM_LOG_E("arguments invalid, type of cert purpose is not number.");
        return nullptr;
    }
    uint32_t certPurpose = CM_CERT_PURPOSE_DEFAULT;
    if (ParseUint32(env, certPurposeValue, certPurpose) == nullptr) {
        CM_LOG_E("parse uint32 failed");
        return nullptr;
    }
    // check support certPurpose
    if (!CheckCertPurpose(certPurpose)) {
        return nullptr;
    }
    context->ukeyInfo->certPurpose = static_cast<enum CmCertificatePurpose>(certPurpose);
    return GetInt32(env, 0);
}

static bool CheckParamsType(napi_env env, napi_value* argv)
{
    size_t index = 0;
    napi_value keyUriObj = argv[index];
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, keyUriObj, &valueType);
    if (status != napi_ok) {
        CM_LOG_E("Failed to get object type");
        return false;
    }
    if (valueType != napi_string) {
        CM_LOG_E("the type of param is not string");
        return false;
    }
    ++index;
    napi_value ukeyInfoObj = argv[index];
    status = napi_typeof(env, ukeyInfoObj, &valueType);
    if (status != napi_ok) {
        CM_LOG_E("Failed to get object type");
        return false;
    }
    if (valueType == napi_null) {
        CM_LOG_E("the type of param is null");
        return false;
    }
    return true;
}

static napi_value GetUkeyCertParseParams(
    napi_env env, napi_callback_info info, GetUkeyCertAsyncContext context)
{
    size_t argc = CM_NAPI_GET_UKEY_CERT_LIST_ARGS;
    napi_value argv[CM_NAPI_GET_UKEY_CERT_LIST_ARGS] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc != CM_NAPI_GET_UKEY_CERT_LIST_ARGS) {
        ThrowError(env, PARAM_ERROR, "Missing parameter, arguments count need 2.");
        CM_LOG_E("Missing parameter");
        return nullptr;
    }
    if (!CheckParamsType(env, argv)) {
        ThrowError(env, PARAM_ERROR, "The parameter type is invalid.");
        CM_LOG_E("Invalid parameter type");
        return nullptr;
    }
    
    size_t index = 0;
    napi_value result = ParseString(env, argv[index], context->keyUri);
    if (result == nullptr) {
        ThrowError(env, PARAMETER_VALIDATION_FAILED, "failed to get keyUri.");
        CM_LOG_E("could not get keyUri");
        return nullptr;
    }
    ++index;
    context->ukeyInfo = static_cast<UkeyInfo *>(CmMalloc(sizeof(UkeyInfo)));
    if (context->ukeyInfo == nullptr) {
        CM_LOG_E("malloc ukeyInfo failed");
        return nullptr;
    }
    result = ParseUkeyInfo(env, argv[index], context);
    if (result == nullptr) {
        ThrowError(env, PARAMETER_VALIDATION_FAILED, "failed to get ukey info.");
        CM_LOG_E("could not get ukey info");
        return nullptr;
    }

    return GetInt32(env, 0);
}

static void GetUkeyCertExecute(napi_env env, void *data)
{
    GetUkeyCertAsyncContext context = static_cast<GetUkeyCertAsyncContext>(data);
    context->certificateList = static_cast<struct CredentialDetailList *>(
        CmMalloc(sizeof(struct CredentialDetailList)));
    if (context->certificateList != nullptr) {
        GenerateUkeyCertList(context->certificateList);
    }
    context->keyUri->size -= 1;
    context->result = CmGetUkeyCert(context->keyUri, context->ukeyInfo, context->certificateList);
}

static void GetUkeyCertComplete(napi_env env, napi_status status, void *data)
{
    GetUkeyCertAsyncContext context = static_cast<GetUkeyCertAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->result == CM_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
        result[1] = GetUkeyCertWriteResult(env, context);
    } else {
        result[0] = GenerateBusinessError(env, context->result);
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    }
    GeneratePromise(env, context->deferred, context->result, result, CM_ARRAY_SIZE(result));
    DeleteGetUkeyCertAsyncContext(env, context);
}

static napi_value GetUkeyCertAsyncWork(napi_env env, GetUkeyCertAsyncContext asyncContext)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, asyncContext->callback, &asyncContext->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "GetUkeyCertAsyncWork", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(
        env,
        nullptr,
        resourceName,
        GetUkeyCertExecute,
        GetUkeyCertComplete,
        static_cast<void *>(asyncContext),
        &asyncContext->asyncWork)
    );
    napi_status napiStatus = napi_queue_async_work(env, asyncContext->asyncWork);
    if (napiStatus != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteGetUkeyCertAsyncContext(env, asyncContext);
        CM_LOG_E("get app cert list could not queue async work");
        return nullptr;
    }
    return promise;
}

napi_value CMNapiGetUkeyCert(napi_env env, napi_callback_info info)
{
    CM_LOG_I("get ukey cert enter");

    GetUkeyCertAsyncContext context = CreateGetUkeyCertAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = GetUkeyCertParseParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("could not parse params");
        DeleteGetUkeyCertAsyncContext(env, context);
        return nullptr;
    }
    result = GetUkeyCertAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("could not start async work");
        DeleteGetUkeyCertAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("get ukey cert list end");
    return result;
}
}  // namespace CertManagerNapi
