/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "cm_napi_user_trusted_cert.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_napi_common.h"

namespace CMNapi {
namespace {
constexpr int CM_NAPI_USER_INSTALL_ARGS_CNT = 2;
constexpr int CM_NAPI_USER_INSTALL_SYNC_ARGS_CNT = 2;
constexpr int CM_NAPI_USER_UNINSTALL_ARGS_CNT = 2;
constexpr int CM_NAPI_USER_UNINSTALL_ALL_ARGS_CNT = 1;
constexpr int CM_NAPI_USER_UNINSTALL_SYNC_ARGS_CNT = 1;
constexpr int CM_NAPI_CALLBACK_ARG_CNT = 1;
constexpr uint32_t OUT_AUTH_URI_SIZE = 1000;
} // namespace

struct UserCertAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    int32_t errCode = 0;

    struct CmBlob *userCert = nullptr;
    struct CmBlob *certAlias = nullptr;
    struct CmBlob *certUri = nullptr;
    struct CertUriList *certUriList = nullptr;
    CmCertFileFormat certFormat = PEM_DER;
    CmCertScope certScope = CM_ALL_USER;
};
using UserCertAsyncContext = UserCertAsyncContextT *;

static UserCertAsyncContext InitUserCertAsyncContext(void)
{
    UserCertAsyncContext context = static_cast<UserCertAsyncContext>(CmMalloc(sizeof(UserCertAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(context, sizeof(UserCertAsyncContextT), 0, sizeof(UserCertAsyncContextT));
    }
    return context;
}

static void FreeCertUriList(struct CertUriList *certUriList)
{
    if (certUriList == NULL || certUriList->uriList == NULL) {
        return;
    }
    for (int32_t i = 0; i < certUriList->certCount; ++i) {
        CM_FREE_BLOB(certUriList->uriList[i]);
    }
    CM_FREE_PTR(certUriList->uriList);
    certUriList->certCount = 0;
    certUriList->maxCapacity = 0;
}

static void FreeUserCertAsyncContext(napi_env env, UserCertAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    DeleteNapiContext(env, context->asyncWork, context->callback);
    FreeCmBlob(context->userCert);
    FreeCmBlob(context->certAlias);
    FreeCmBlob(context->certUri);
    FreeCertUriList(context->certUriList);
    CM_FREE_PTR(context->certUriList);
    CM_FREE_PTR(context);
}

static int32_t GetUserCertData(napi_env env, napi_value object, CmBlob **outCert)
{
    CmBlob *userCert = static_cast<CmBlob *>(CmMalloc(sizeof(CmBlob)));
    if (userCert == nullptr) {
        CM_LOG_E("could not alloc userCert blob memory");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(userCert, sizeof(CmBlob), 0, sizeof(CmBlob));

    napi_value result = GetUint8Array(env, object, *(userCert));
    if (result == nullptr) {
        CM_LOG_E("could not get userCert data");
        CM_FREE_PTR(userCert);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    *outCert = userCert;
    return CM_SUCCESS;
}

static int32_t GetCertAliasData(napi_env env, napi_value object, UserCertAsyncContext context)
{
    napi_value result = ParseCertAlias(env, object, context->certAlias);
    if (result == nullptr) {
        CM_LOG_E("could not get certAlias data");
        return CMR_ERROR_INVALID_OPERATION;
    }

    return CM_SUCCESS;
}

static napi_value ParseCertFormat(napi_env env, napi_value object, UserCertAsyncContext context) {
    napi_value certFormatValue = nullptr;
    napi_status status = napi_get_named_property(env, object, "certFormat", &certFormatValue);
    if (status != napi_ok || certFormatValue == nullptr) {
        return GetInt32(env, 0);
    }
    uint32_t certFormat = PEM_DER;
    if (ParseUint32(env, certFormatValue, certFormat) == nullptr) {
        return nullptr;
    }
    // check support certFormat
    switch (certFormat) {
        case PEM_DER:
        case P7B:
            break;
        default:
            CM_LOG_E("invalid cert format: %u", certFormat);
            return nullptr;
    }
    context->certFormat = static_cast<enum CmCertFileFormat>(certFormat);
    return GetInt32(env, 0);
}

static napi_value ParseCertScope(napi_env env, napi_value object, UserCertAsyncContext context) {
    napi_value certScopeValue = nullptr;
    napi_status status = napi_get_named_property(env, object, "certScope", &certScopeValue);
    if (status != napi_ok || certScopeValue == nullptr) {
        return GetInt32(env, 0);
    }
    uint32_t certScope = PEM_DER;
    if (ParseUint32(env, certScopeValue, certScope) == nullptr) {
        return nullptr;
    }
    // check support certScope
    switch (certScope) {
        case CM_ALL_USER:
        case CM_GLOBAL_USER:
        case CM_CURRENT_USER:
            break;
        default:
            CM_LOG_E("invalid cert scope: %u", certScope);
            return nullptr;
    }
    context->certScope = static_cast<enum CmCertScope>(certScope);
    return GetInt32(env, 0);
}

static napi_value ParseCertInfo(napi_env env, napi_value object, UserCertAsyncContext context)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, object, &type));
    if (type != napi_object) {
        CM_LOG_E("type of param CertBlob is not object");
        return nullptr;
    }

    napi_value userCertValue = nullptr;
    napi_status status = napi_get_named_property(env, object, "inData", &userCertValue);
    if (status != napi_ok || userCertValue == nullptr) {
        CM_LOG_E("get inData failed");
        return nullptr;
    }

    napi_value certAliasValue = nullptr;
    status = napi_get_named_property(env, object, "alias", &certAliasValue);
    if (status != napi_ok || certAliasValue == nullptr) {
        CM_LOG_E("get cert alias failed");
        return nullptr;
    }

    // parse certFormat
    if (ParseCertFormat(env, object, context) == nullptr) {
        CM_LOG_E("parse cert file format failed");
        return nullptr;
    }

    // parse certScope
    if (ParseCertScope(env, object, context) == nullptr) {
        CM_LOG_E("parse cert scope failed");
        return nullptr;
    }

    int32_t ret = GetUserCertData(env, userCertValue, &context->userCert);
    if (ret != CM_SUCCESS) {
        return nullptr;
    }

    ret = GetCertAliasData(env, certAliasValue, context);
    if (ret != CM_SUCCESS) {
        return nullptr;
    }

    return GetInt32(env, 0);
}

static napi_value ParseInstallUserCertParams(napi_env env, napi_callback_info info, UserCertAsyncContext context)
{
    size_t argc = CM_NAPI_USER_INSTALL_ARGS_CNT;
    napi_value argv[CM_NAPI_USER_INSTALL_ARGS_CNT] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if ((argc != CM_NAPI_USER_INSTALL_ARGS_CNT) &&
        (argc != (CM_NAPI_USER_INSTALL_ARGS_CNT - CM_NAPI_CALLBACK_ARG_CNT))) {
        ThrowError(env, PARAM_ERROR, "arguments count invalid when installing user cert");
        CM_LOG_E("arguments count is not expected when installing user cert");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseCertInfo(env, argv[index], context);
    if (result == nullptr) {
        ThrowError(env, PARAM_ERROR, "get context type error");
        CM_LOG_E("get CertBlob failed when installing user cert");
        return nullptr;
    }

    index++;
    if (index < argc) {
        int32_t ret = GetCallback(env, argv[index], context->callback);
        if (ret != CM_SUCCESS) {
            ThrowError(env, PARAM_ERROR, "Get callback type failed.");
            CM_LOG_E("get callback function failed when install user cert");
            return nullptr;
        }
    }

    return GetInt32(env, 0);
}

static napi_value ParseUninstallUserCertParams(napi_env env, napi_callback_info info, UserCertAsyncContext context)
{
    size_t argc = CM_NAPI_USER_UNINSTALL_ARGS_CNT;
    napi_value argv[CM_NAPI_USER_UNINSTALL_ARGS_CNT] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if ((argc != CM_NAPI_USER_UNINSTALL_ARGS_CNT) &&
        (argc != (CM_NAPI_USER_UNINSTALL_ARGS_CNT - CM_NAPI_CALLBACK_ARG_CNT))) {
        ThrowError(env, PARAM_ERROR, "arguments count invalid when uninstalling user cert");
        CM_LOG_E("arguments count is not expected when uninstalling user cert");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseString(env, argv[index], context->certUri);
    if (result == nullptr) {
        ThrowError(env, PARAM_ERROR, "get certUri type error");
        CM_LOG_E("get CertBlob failed when uninstalling user cert");
        return nullptr;
    }

    index++;
    if (index < argc) {
        int32_t ret = GetCallback(env, argv[index], context->callback);
        if (ret != CM_SUCCESS) {
            ThrowError(env, PARAM_ERROR, "Get callback type failed.");
            CM_LOG_E("get callback function failed when uninstalling user cert");
            return nullptr;
        }
    }

    return GetInt32(env, 0);
}

static int32_t ParseUninstallUserCertSyncParams(napi_env env, napi_callback_info info, UserCertAsyncContext context)
{
    size_t argc = CM_NAPI_USER_UNINSTALL_SYNC_ARGS_CNT;
    napi_value argv[CM_NAPI_USER_UNINSTALL_SYNC_ARGS_CNT] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    if (argc != CM_NAPI_USER_UNINSTALL_SYNC_ARGS_CNT) {
        CM_LOG_E("arguments count is not expected when uninstalling user cert sync");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    napi_value result = ParseString(env, argv[0], context->certUri);
    if (result == nullptr) {
        CM_LOG_E("get certUri failed when uninstalling user cert sync");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    return CM_SUCCESS;
}

static int32_t ParseInstallUserCertSyncParams(napi_env env, napi_callback_info info, CmBlob **userCert,
    CmCertScope &installScope)
{
    size_t argc = CM_NAPI_USER_INSTALL_SYNC_ARGS_CNT;
    napi_value argv[CM_NAPI_USER_INSTALL_SYNC_ARGS_CNT] = { nullptr };
    napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);

    if (argc != CM_NAPI_USER_INSTALL_SYNC_ARGS_CNT) {
        CM_LOG_E("arguments count is not expected when installing user cert sync");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    size_t index = 0;
    int32_t ret = GetUserCertData(env, argv[index], userCert);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("could not get userCert");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    index++;
    uint32_t scope = CM_ALL_USER;
    napi_value result = ParseUint32(env, argv[index], scope);
    if (result == nullptr) {
        CM_LOG_E("could not get install scope");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    installScope = static_cast<CmCertScope>(scope);
    return CM_SUCCESS;
}

static napi_value ParseUninstallAllUserCertParams(napi_env env, napi_callback_info info, UserCertAsyncContext context)
{
    size_t argc = CM_NAPI_USER_UNINSTALL_ALL_ARGS_CNT;
    napi_value argv[CM_NAPI_USER_UNINSTALL_ALL_ARGS_CNT] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if ((argc != CM_NAPI_USER_UNINSTALL_ALL_ARGS_CNT) &&
        (argc != (CM_NAPI_USER_UNINSTALL_ALL_ARGS_CNT - CM_NAPI_CALLBACK_ARG_CNT))) {
        ThrowError(env, PARAM_ERROR, "arguments count invalid when uninstalling all user cert");
        CM_LOG_E("arguments count is not expected when uninstalling all user cert");
        return nullptr;
    }

    size_t index = 0;
    if (index < argc) {
        int32_t ret = GetCallback(env, argv[index], context->callback);
        if (ret != CM_SUCCESS) {
            ThrowError(env, PARAM_ERROR, "Get callback type failed.");
            CM_LOG_E("get callback function failed when uninstalling all user cert");
            return nullptr;
        }
    }

    return GetInt32(env, 0);
}

static int32_t InitCertUri(UserCertAsyncContext context)
{
    context->certUri = static_cast<CmBlob *>(CmMalloc(sizeof(CmBlob)));
    if (context->certUri == nullptr) {
        CM_LOG_E("malloc certUri failed");
        context->errCode = CMR_ERROR_MALLOC_FAIL;
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(context->certUri, sizeof(CmBlob), 0, sizeof(CmBlob));

    context->certUri->data = static_cast<uint8_t *>(CmMalloc(OUT_AUTH_URI_SIZE));
    if (context->certUri->data == nullptr) {
        CM_LOG_E("malloc certUri.data failed");
        context->errCode = CMR_ERROR_MALLOC_FAIL;
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(context->certUri->data, OUT_AUTH_URI_SIZE, 0, OUT_AUTH_URI_SIZE);
    context->certUri->size = OUT_AUTH_URI_SIZE;
    return CM_SUCCESS;
}

static int32_t InitCertUriList(UserCertAsyncContext context)
{
    CertUriList *certUriList = static_cast<CertUriList *>(CmMalloc(sizeof(CertUriList)));
    if (certUriList == nullptr) {
        context->errCode = CMR_ERROR_MALLOC_FAIL;
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(certUriList, sizeof(CertUriList), 0, sizeof(CertUriList));
    certUriList->certCount = 0;
    certUriList->maxCapacity = MAX_P7B_INSTALL_COUNT;
    context->certUriList = certUriList;
    return CM_SUCCESS;
}

static void InstallUserCertExecute(napi_env env, void *data)
{
    UserCertAsyncContext context = static_cast<UserCertAsyncContext>(data);
    
    int32_t ret = CM_SUCCESS;
    uint32_t userId = 0;
    if (context->certScope == CM_CURRENT_USER) {
        userId = INIT_INVALID_VALUE;
    } else if (context->certScope == CM_GLOBAL_USER) {
        userId = 0;
    } else {
        CM_LOG_E("invalid certificate scope");
        context->errCode = CMR_ERROR_INVALID_ARGUMENT;
        return;
    }

    if (context->certFormat == P7B) {
        ret = InitCertUriList(context);
        if (ret != CM_SUCCESS) {
            context->errCode = ret;
            return;
        }
        CmInstallCertInfo installCertInfo = {
            .userCert = context->userCert,
            .certAlias = context->certAlias,
            .userId = userId
        };
        context->errCode = CmInstallUserTrustedP7BCert(&installCertInfo, true, context->certUriList);
        return;
    }

    ret = InitCertUri(context);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("init certUri failed");
        context->errCode = ret;
        return;
    }
    context->errCode = CmInstallUserCACert(context->userCert, context->certAlias, userId, true, context->certUri);
    return;
}

static napi_value ConvertResultCertUri(napi_env env, const CmBlob *certUri)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));

    napi_value certUriNapi = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, reinterpret_cast<const char *>(certUri->data),
        NAPI_AUTO_LENGTH, &certUriNapi));
    NAPI_CALL(env, napi_set_named_property(env, result, "uri", certUriNapi));

    return result;
}

static napi_value ConvertResultCertUriList(napi_env env, const CertUriList *certUriList)
{
    if (certUriList == nullptr) {
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));

    napi_value uriArray = nullptr;
    NAPI_CALL(env, napi_create_array(env, &uriArray));

    for (uint32_t i = 0; i < certUriList->certCount; ++i) {
        napi_value certUri = nullptr;
        NAPI_CALL(env, napi_create_string_latin1(env, reinterpret_cast<const char *>(certUriList->uriList[i].data),
            NAPI_AUTO_LENGTH, &certUri));
        NAPI_CALL(env, napi_set_element(env, uriArray, i, certUri));
    }

    NAPI_CALL(env, napi_set_named_property(env, result, "uriList", uriArray));
    return result;
}

static napi_value ConvertInstallCertResult(napi_env env, const UserCertAsyncContext context)
{
    if (context->certFormat == P7B) {
        return ConvertResultCertUriList(env, context->certUriList);
    }
    return ConvertResultCertUri(env, context->certUri);
}

static void InstallUserCertComplete(napi_env env, napi_status status, void *data)
{
    UserCertAsyncContext context = static_cast<UserCertAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->errCode == CM_SUCCESS) {
        napi_create_uint32(env, 0, &result[0]);
        result[1] = ConvertInstallCertResult(env, context);
    } else {
        result[0] = GenerateBusinessError(env, context->errCode);
        napi_get_undefined(env, &result[1]);
    }

    if (context->deferred != nullptr) {
        GeneratePromise(env, context->deferred, context->errCode, result, CM_ARRAY_SIZE(result));
    } else {
        GenerateCallback(env, context->callback, result, CM_ARRAY_SIZE(result), context->errCode);
    }
    FreeUserCertAsyncContext(env, context);
}

static napi_value InstallUserCertAsyncWork(napi_env env, UserCertAsyncContext context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "installUserCertAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName,
        InstallUserCertExecute,
        InstallUserCertComplete,
        static_cast<void *>(context),
        &context->asyncWork));

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        ThrowError(env, PARAM_ERROR, "queue async work error");
        CM_LOG_E("queue async work failed when installing user cert");
        return nullptr;
    }
    return promise;
}

static void UninstallUserCertExecute(napi_env env, void *data)
{
    UserCertAsyncContext context = static_cast<UserCertAsyncContext>(data);
    context->errCode = CmUninstallUserTrustedCert(context->certUri);
}

static void UninstallComplete(napi_env env, napi_status status, void *data)
{
    UserCertAsyncContext context = static_cast<UserCertAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->errCode == CM_SUCCESS) {
        napi_create_uint32(env, 0, &result[0]);
        napi_get_boolean(env, true, &result[1]);
    } else {
        result[0] = GenerateBusinessError(env, context->errCode);
        napi_get_undefined(env, &result[1]);
    }

    if (context->deferred != nullptr) {
        GeneratePromise(env, context->deferred, context->errCode, result, CM_ARRAY_SIZE(result));
    } else {
        GenerateCallback(env, context->callback, result, CM_ARRAY_SIZE(result), context->errCode);
    }
    FreeUserCertAsyncContext(env, context);
}

static napi_value UninstallUserCertAsyncWork(napi_env env, UserCertAsyncContext context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "uninstallUserCertAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName,
        UninstallUserCertExecute,
        UninstallComplete,
        static_cast<void *>(context),
        &context->asyncWork));

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        ThrowError(env, PARAM_ERROR, "queue async work error");
        CM_LOG_E("queue async work failed when uninstalling user cert");
        return nullptr;
    }
    return promise;
}

static void UninstallAllUserCertExecute(napi_env env, void *data)
{
    UserCertAsyncContext context = static_cast<UserCertAsyncContext>(data);
    context->errCode = CmUninstallAllUserTrustedCert();
}

static napi_value UninstallAllUserCertAsyncWork(napi_env env, UserCertAsyncContext context)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, context->callback, &context->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "uninstallAllUserCertAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName,
        UninstallAllUserCertExecute,
        UninstallComplete,
        static_cast<void *>(context),
        &context->asyncWork));

    napi_status status = napi_queue_async_work(env, context->asyncWork);
    if (status != napi_ok) {
        ThrowError(env, PARAM_ERROR, "queue async work error");
        CM_LOG_E("queue async work failed uninstall all user cert");
        return nullptr;
    }
    return promise;
}

static int32_t InstallUserCertSyncExecute(CmBlob *userCert, const CmCertScope scope, CmBlob *certUri)
{
    int32_t ret;
    // alias is empty string
    uint8_t alias[1] = { 0 };
    CmBlob certAlias = { .size = sizeof(alias), .data = alias };

    uint32_t userId = 0;
    if (scope == CM_CURRENT_USER) {
        userId = INIT_INVALID_VALUE;
    } else if (scope == CM_GLOBAL_USER) {
        userId = 0;
    } else {
        CM_LOG_E("invalid certificate scope");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    ret = CmInstallUserCACert(userCert, &certAlias, userId, true, certUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("install user cert sync, init certUri failed");
        return ret;
    }
    return ret;
}

napi_value CMNapiInstallUserTrustedCert(napi_env env, napi_callback_info info)
{
    CM_LOG_I("install user trusted cert enter");

    UserCertAsyncContext context = InitUserCertAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("init install user cert context failed");
        return nullptr;
    }

    napi_value result = ParseInstallUserCertParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("parse install user cert params failed");
        FreeUserCertAsyncContext(env, context);
        return nullptr;
    }

    result = InstallUserCertAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("start install user cert async work failed");
        FreeUserCertAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("install user trusted cert end");
    return result;
}

napi_value CMNapiInstallUserTrustedCertSync(napi_env env, napi_callback_info info)
{
    CM_LOG_I("install user trusted cert sync enter");

    CmBlob *userCert = nullptr;
    CmCertScope installScope;
    uint8_t uri[OUT_AUTH_URI_SIZE] = { 0 };
    CmBlob certUri = { sizeof(uri), uri };

    int32_t ret = CM_SUCCESS;
    do {
        ret = ParseInstallUserCertSyncParams(env, info, &userCert, installScope);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("parse install user cert sync params failed");
            break;
        }

        ret = InstallUserCertSyncExecute(userCert, installScope, &certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("install user cert sync execute failed");
            break;
        }
    } while (0);

    FreeCmBlob(userCert);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("install user cert sync failed, ret = %d", ret);
        napi_throw(env, GenerateBusinessError(env, ret));
        return nullptr;
    }
    
    napi_value result = ConvertResultCertUri(env, &certUri);
    CM_LOG_I("install user trusted cert sync end");
    return result;
}

napi_value CMNapiUninstallUserTrustedCert(napi_env env, napi_callback_info info)
{
    CM_LOG_I("uninstall user trusted cert enter");

    UserCertAsyncContext context = InitUserCertAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("init uninstall user cert context failed");
        return nullptr;
    }

    napi_value result = ParseUninstallUserCertParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("parse uninstall user cert params failed");
        FreeUserCertAsyncContext(env, context);
        return nullptr;
    }

    result = UninstallUserCertAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("start uninstall user cert async work failed");
        FreeUserCertAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("uninstall user trusted cert end");
    return result;
}

napi_value CMNapiUninstallAllUserTrustedCert(napi_env env, napi_callback_info info)
{
    CM_LOG_I("uninstall all user trusted cert enter");

    UserCertAsyncContext context = InitUserCertAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("init uninstall all user cert context failed");
        return nullptr;
    }

    napi_value result = ParseUninstallAllUserCertParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("parse uninstall all user cert params failed");
        FreeUserCertAsyncContext(env, context);
        return nullptr;
    }

    result = UninstallAllUserCertAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("start uninstall all user cert async work failed");
        FreeUserCertAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("uninstall all user trusted cert end");
    return result;
}

napi_value CMNapiUninstallUserCertSync(napi_env env, napi_callback_info info)
{
    CM_LOG_I("uninstall user trusted cert sync enter");

    UserCertAsyncContext context = InitUserCertAsyncContext();
    int32_t ret;
    do {
        if (context == nullptr) {
            ret = CMR_ERROR_NULL_POINTER;
            CM_LOG_E("init uninstall user cert context failed");
            break;
        }

        ret = ParseUninstallUserCertSyncParams(env, info, context);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("parse uninstall user cert params failed");
            break;
        }

        ret = CmUninstallUserTrustedCert(context->certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("start uninstall user cert sync work failed");
            break;
        }
    } while (0);

    if (ret != CM_SUCCESS) {
        CM_LOG_E("uninstall user cert sync failed, ret = %d", ret);
        napi_throw(env, GenerateBusinessError(env, ret));
    }

    FreeUserCertAsyncContext(env, context);

    CM_LOG_I("uninstall user trusted cert sync end");
    return nullptr;
}
}  // namespace CMNapi

