/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cm_napi_grant.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_napi_common.h"

namespace CMNapi {
namespace {
constexpr int CM_NAPI_GRANT_ARGS_CNT = 3;
constexpr int CM_NAPI_IS_AUTHED_ARGS_CNT = 2;
constexpr int CM_NAPI_CALLBACK_ARG_CNT = 1;

constexpr uint32_t OUT_AUTH_URI_SIZE = 1000;
constexpr uint32_t OUT_AUTH_LIST_SIZE = 512;
constexpr uint32_t OUT_UINT32_STRING_SIZE = 16;
} // namespace

struct GrantAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t errCode = 0;
    uint32_t appUid = 0;
    struct CmBlob *keyUri = nullptr;
    struct CmBlob *authUri = nullptr;
    struct CmAppUidList *uidList = nullptr;
};
using GrantAsyncContext = GrantAsyncContextT *;

static GrantAsyncContext InitGrantAsyncContext(void)
{
    GrantAsyncContext context = static_cast<GrantAsyncContext>(CmMalloc(sizeof(GrantAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(GrantAsyncContextT), 0, sizeof(GrantAsyncContextT));
    }
    return context;
}

static void FreeGrantAsyncContext(napi_env env, GrantAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    DeleteNapiContext(env, context->asyncWork, context->callback);
    FreeCmBlob(context->keyUri);
    FreeCmBlob(context->authUri);
    if (context->uidList != nullptr) {
        CM_FREE_PTR(context->uidList->appUid);
        CM_FREE_PTR(context->uidList);
    }
    CM_FREE_PTR(context);
}

static napi_value ParseString2Uint32(napi_env env, napi_value object, uint32_t &value)
{
    struct CmBlob *blob = nullptr;
    napi_value result = ParseString(env, object, blob);
    if (result == nullptr) {
        CM_LOG_E("parse string to blob failed");
        if (blob != nullptr) {
            CM_FREE_PTR(blob->data);
            CmFree(blob);
        }
        return nullptr;
    }

    value = static_cast<uint32_t>(atoi(reinterpret_cast<char *>(blob->data)));
    CM_FREE_PTR(blob->data);
    CM_FREE_PTR(blob);
    return GetInt32(env, 0);
}

static napi_value ParseGrantUidParams(napi_env env, napi_callback_info info, GrantAsyncContext context)
{
    size_t argc = CM_NAPI_GRANT_ARGS_CNT;
    napi_value argv[CM_NAPI_GRANT_ARGS_CNT] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if ((argc != CM_NAPI_GRANT_ARGS_CNT) && (argc != (CM_NAPI_GRANT_ARGS_CNT - CM_NAPI_CALLBACK_ARG_CNT))) {
        ThrowParamsError(env, PARAM_ERROR, "arguments count invalid when grant or remove uid");
        CM_LOG_E("arguments count is not expected when grant or remove uid");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseString(env, argv[index], context->keyUri);
    if (result == nullptr) {
        ThrowParamsError(env, PARAM_ERROR, "keyUri type error");
        CM_LOG_E("get uri failed when grant or remove uid");
        return nullptr;
    }

    index++;
    result = ParseString2Uint32(env, argv[index], context->appUid);
    if (result == nullptr) {
        ThrowParamsError(env, PARAM_ERROR, "appUid type error");
        CM_LOG_E("get app uid failed when grant or remove uid ");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
        if (context->callback == nullptr) {
            ThrowParamsError(env, PARAM_ERROR, "Get callback type error");
            CM_LOG_E("get callback function failed when grant or remove uid");
            return nullptr;
        }
    }

    return GetInt32(env, 0);
}

static napi_value ParseRemoveUidParams(napi_env env, napi_callback_info info, GrantAsyncContext context)
{
    return ParseGrantUidParams(env, info, context);
}

static napi_value ParseIsAuthedParams(napi_env env, napi_callback_info info, GrantAsyncContext context)
{
    size_t argc = CM_NAPI_IS_AUTHED_ARGS_CNT;
    napi_value argv[CM_NAPI_IS_AUTHED_ARGS_CNT] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if ((argc != CM_NAPI_IS_AUTHED_ARGS_CNT) && (argc != (CM_NAPI_IS_AUTHED_ARGS_CNT - CM_NAPI_CALLBACK_ARG_CNT))) {
        ThrowParamsError(env, PARAM_ERROR, "arguments count invalid when using isAuthed");
        CM_LOG_E("arguments count is not expected when using isAuthed");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseString(env, argv[index], context->keyUri);
    if (result == nullptr) {
        ThrowParamsError(env, PARAM_ERROR, "keyUri type error");
        CM_LOG_E("get uri failed when using isAuthed");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
        if (context->callback == nullptr) {
            ThrowParamsError(env, PARAM_ERROR, "Get callback type error");
            CM_LOG_E("get callback function failed when using isAuthed");
            return nullptr;
        }
    }

    return GetInt32(env, 0);
}


static napi_value ParseGetUidListParams(napi_env env, napi_callback_info info, GrantAsyncContext context)
{
    return ParseIsAuthedParams(env, info, context);
}

static void GrantUidExecute(napi_env env, void *data)
{
    GrantAsyncContext context = static_cast<GrantAsyncContext>(data);
    context->authUri = static_cast<CmBlob *>(CmMalloc(sizeof(CmBlob)));
    if (context->authUri == nullptr) {
        CM_LOG_E("malloc authUri failed");
        context->errCode = CMR_ERROR_MALLOC_FAIL;
        return;
    }
    (void)memset_s(context->authUri, sizeof(CmBlob), 0, sizeof(CmBlob));

    context->authUri->data = static_cast<uint8_t *>(CmMalloc(OUT_AUTH_URI_SIZE));
    if (context->authUri->data == nullptr) {
        CM_LOG_E("malloc authUri.data failed");
        context->errCode = CMR_ERROR_MALLOC_FAIL;
        return;
    }
    (void)memset_s(context->authUri->data, OUT_AUTH_URI_SIZE, 0, OUT_AUTH_URI_SIZE);
    context->authUri->size = OUT_AUTH_URI_SIZE;

    context->errCode = CmGrantAppCertificate(context->keyUri, context->appUid, context->authUri);
}

static napi_value ConvertResultAuthUri(napi_env env, const CmBlob *authUri)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));

    napi_value authUriNapi = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env,
        reinterpret_cast<const char *>(authUri->data), NAPI_AUTO_LENGTH, &authUriNapi));
    NAPI_CALL(env, napi_set_named_property(env, result, "uri", authUriNapi));

    return result;
}

static void GrantUidComplete(napi_env env, napi_status status, void *data)
{
    GrantAsyncContext context = static_cast<GrantAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->errCode == CM_SUCCESS) {
        napi_create_uint32(env, 0, &result[0]);
        result[1] = ConvertResultAuthUri(env, context->authUri);
    } else {
        result[0] = GenerateBusinessError(env, context->errCode, "grant uid failed");
        napi_get_undefined(env, &result[1]);
    }

    if (context->deferred != nullptr) {
        GeneratePromise(env, context->deferred, context->errCode, result, sizeof(result));
    } else {
        GenerateCallback(env, context->callback, result, sizeof(result));
    }
    FreeGrantAsyncContext(env, context);
}

static void RemoveUidExecute(napi_env env, void *data)
{
    GrantAsyncContext context = static_cast<GrantAsyncContext>(data);
    context->errCode = CmRemoveGrantedApp(context->keyUri, context->appUid);
}

static void RemoveOrIsAuthedComplete(napi_env env, napi_status status, void *data)
{
    GrantAsyncContext context = static_cast<GrantAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->errCode == CM_SUCCESS) {
        napi_create_uint32(env, 0, &result[0]);
        napi_get_boolean(env, true, &result[1]);
    } else {
        result[0] = GenerateBusinessError(env, context->errCode, "remove or check is authed process failed");
        napi_get_undefined(env, &result[1]);
    }

    if (context->deferred != nullptr) {
        GeneratePromise(env, context->deferred, context->errCode, result, sizeof(result));
    } else {
        GenerateCallback(env, context->callback, result, sizeof(result));
    }
    FreeGrantAsyncContext(env, context);
}

static void IsAuthedExecute(napi_env env, void *data)
{
    GrantAsyncContext context = static_cast<GrantAsyncContext>(data);
    context->errCode = CmIsAuthorizedApp(context->keyUri);
}

static void GetUidListExecute(napi_env env, void *data)
{
    GrantAsyncContext context = static_cast<GrantAsyncContext>(data);
    context->uidList = static_cast<CmAppUidList *>(CmMalloc(sizeof(CmAppUidList)));
    if (context->uidList == nullptr) {
        CM_LOG_E("malloc uid list failed");
        context->errCode = CMR_ERROR_MALLOC_FAIL;
        return;
    }
    (void)memset_s(context->uidList, sizeof(CmAppUidList), 0, sizeof(CmAppUidList));

    uint32_t uidListSize = OUT_AUTH_LIST_SIZE * sizeof(uint32_t);
    context->uidList->appUid = static_cast<uint32_t *>(CmMalloc(uidListSize));
    if (context->uidList->appUid == nullptr) {
        CM_LOG_E("malloc uid_list.appUid failed");
        context->errCode = CMR_ERROR_MALLOC_FAIL;
        return;
    }
    (void)memset_s(context->uidList->appUid, uidListSize, 0, uidListSize);
    context->uidList->appUidCount = OUT_AUTH_LIST_SIZE;

    context->errCode = CmGetAuthorizedAppList(context->keyUri, context->uidList);
}

static napi_value ConvertResultAuthList(napi_env env, const CmAppUidList *appUidList)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));

    napi_value uidListArray = nullptr;
    NAPI_CALL(env, napi_create_array(env, &uidListArray));

    for (uint32_t i = 0; i < appUidList->appUidCount; ++i) {
        char uidStr[OUT_UINT32_STRING_SIZE] = {0};
        if (snprintf_s(uidStr, sizeof(uidStr), sizeof(uidStr) - 1, "%u", appUidList->appUid[i]) < 0) {
            CM_LOG_E("uid to string failed");
            return result;
        }

        napi_value element = nullptr;
        NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(uidStr), NAPI_AUTO_LENGTH, &element));
        NAPI_CALL(env, napi_set_element(env, uidListArray, i, element));
    }

    NAPI_CALL(env, napi_set_named_property(env, result, "appUidList", uidListArray));
    return result;
}

static void GetUidListComplete(napi_env env, napi_status status, void *data)
{
    GrantAsyncContext context = static_cast<GrantAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->errCode == CM_SUCCESS) {
        napi_create_uint32(env, 0, &result[0]);
        result[1] = ConvertResultAuthList(env, context->uidList);
    } else {
        result[0] = GenerateBusinessError(env, context->errCode, "get authed uid list failed");
        napi_get_undefined(env, &result[1]);
    }

    if (context->deferred != nullptr) {
        GeneratePromise(env, context->deferred, context->errCode, result, sizeof(result));
    } else {
        GenerateCallback(env, context->callback, result, sizeof(result));
    }
    FreeGrantAsyncContext(env, context);
}

static napi_value GrantUidAsyncWork(napi_env env, GrantAsyncContext context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "grantAppCertificate", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName,
        GrantUidExecute,
        GrantUidComplete,
        static_cast<void *>(context),
        &context->asyncWork));

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        ThrowParamsError(env, PARAM_ERROR, "queue asyncWork error");
        CM_LOG_E("get async work failed when granting uid");
        return nullptr;
    }
    return promise;
}

static napi_value RemoveUidAsyncWork(napi_env env, GrantAsyncContext context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "removeGrantedAppCertificate", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName,
        RemoveUidExecute,
        RemoveOrIsAuthedComplete,
        static_cast<void *>(context),
        &context->asyncWork));

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        ThrowParamsError(env, PARAM_ERROR, "queue asyncWork error");
        CM_LOG_E("queue async work failed when removing uid");
        return nullptr;
    }
    return promise;
}

static napi_value IsAuthedAsyncWork(napi_env env, GrantAsyncContext context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "isAuthorizedApp", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName,
        IsAuthedExecute,
        RemoveOrIsAuthedComplete,
        static_cast<void *>(context),
        &context->asyncWork));

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        ThrowParamsError(env, PARAM_ERROR, "queue asyncWork error");
        CM_LOG_E("queue async work failed when using isAuthed");
        return nullptr;
    }
    return promise;
}

static napi_value GetUidListAsyncWork(napi_env env, GrantAsyncContext context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "getAuthorizedAppList", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName,
        GetUidListExecute,
        GetUidListComplete,
        static_cast<void *>(context),
        &context->asyncWork));

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        ThrowParamsError(env, PARAM_ERROR, "queue asyncWork error");
        CM_LOG_E("queue async work failed when getting authed uid list");
        return nullptr;
    }
    return promise;
}

napi_value CMNapiGrantAppCertificate(napi_env env, napi_callback_info info)
{
    GrantAsyncContext context = InitGrantAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("init grant uid context failed");
        return nullptr;
    }

    napi_value result = ParseGrantUidParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("parse grant uid params failed");
        FreeGrantAsyncContext(env, context);
        return nullptr;
    }

    result = GrantUidAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("start grant uid async work failed");
        FreeGrantAsyncContext(env, context);
        return nullptr;
    }

    return result;
}

napi_value CMNapiIsAuthorizedApp(napi_env env, napi_callback_info info)
{
    GrantAsyncContext context = InitGrantAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("init is authed uid context failed");
        return nullptr;
    }

    napi_value result = ParseIsAuthedParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("parse is authed uid params failed");
        FreeGrantAsyncContext(env, context);
        return nullptr;
    }

    result = IsAuthedAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("start is authed uid async work failed");
        FreeGrantAsyncContext(env, context);
        return nullptr;
    }

    return result;
}

napi_value CMNapiGetAuthorizedAppList(napi_env env, napi_callback_info info)
{
    GrantAsyncContext context = InitGrantAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("init get authed uid list context failed");
        return nullptr;
    }

    napi_value result = ParseGetUidListParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("parse get uid list params failed");
        FreeGrantAsyncContext(env, context);
        return nullptr;
    }

    result = GetUidListAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("start get uid list async work failed");
        FreeGrantAsyncContext(env, context);
        return nullptr;
    }

    return result;
}

napi_value CMNapiRemoveGrantedApp(napi_env env, napi_callback_info info)
{
    GrantAsyncContext context = InitGrantAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("init remove uid context failed");
        return nullptr;
    }

    napi_value result = ParseRemoveUidParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("parse remove uid params failed");
        FreeGrantAsyncContext(env, context);
        return nullptr;
    }

    result = RemoveUidAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("start remove uid async work failed");
        FreeGrantAsyncContext(env, context);
        return nullptr;
    }

    return result;
}
}  // namespace CMNapi

