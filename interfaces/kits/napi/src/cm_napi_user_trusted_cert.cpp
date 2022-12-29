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
constexpr int CM_NAPI_USER_UNINSTALL_ARGS_CNT = 2;
constexpr int CM_NAPI_USER_UNINSTALL_ALL_ARGS_CNT = 1;
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

static void FreeUserCertAsyncContext(napi_env env, UserCertAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    DeleteNapiContext(env, context->asyncWork, context->callback);
    FreeCmBlob(context->userCert);
    FreeCmBlob(context->certAlias);
    FreeCmBlob(context->certUri);
    CM_FREE_PTR(context);
}

static int32_t GetUserCertData(napi_env env, napi_value object, UserCertAsyncContext context)
{
    context->userCert = static_cast<CmBlob *>(CmMalloc(sizeof(CmBlob)));
    if (context->userCert == nullptr) {
        CM_LOG_E("could not alloc userCert blob memory");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(context->userCert, sizeof(CmBlob), 0, sizeof(CmBlob));

    napi_value result = GetUint8Array(env, object, *(context->userCert));
    if (result == nullptr) {
        CM_LOG_E("could not get userCert data");
        return CMR_ERROR_INVALID_OPERATION;
    }

    return CM_SUCCESS;
}

static int32_t GetCertAliasData(napi_env env, napi_value object, UserCertAsyncContext context)
{
    napi_value result = ParseString(env, object, context->certAlias);
    if (result == nullptr) {
        CM_LOG_E("could not get certAlias data");
        return CMR_ERROR_INVALID_OPERATION;
    }

    return CM_SUCCESS;
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

    int32_t ret = GetUserCertData(env, userCertValue, context);
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
        ThrowParamsError(env, PARAM_ERROR, "arguments count invalid when installing user cert");
        CM_LOG_E("arguments count is not expected when installing user cert");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseCertInfo(env, argv[index], context);
    if (result == nullptr) {
        ThrowParamsError(env, PARAM_ERROR, "get context type error");
        CM_LOG_E("get CertBlob failed when installing user cert");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
        if (context->callback == nullptr) {
            ThrowParamsError(env, PARAM_ERROR, "get callback type error");
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
        ThrowParamsError(env, PARAM_ERROR, "arguments count invalid when uninstalling user cert");
        CM_LOG_E("arguments count is not expected when uninstalling user cert");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseString(env, argv[index], context->certUri);
    if (result == nullptr) {
        ThrowParamsError(env, PARAM_ERROR, "get certUri type error");
        CM_LOG_E("get CertBlob failed when uninstalling user cert");
        return nullptr;
    }

    index++;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
        if (context->callback == nullptr) {
            ThrowParamsError(env, PARAM_ERROR, "get callback type error");
            CM_LOG_E("get callback function failed when uninstalling user cert");
            return nullptr;
        }
    }

    return GetInt32(env, 0);
}

static napi_value ParseUninstallAllUserCertParams(napi_env env, napi_callback_info info, UserCertAsyncContext context)
{
    size_t argc = CM_NAPI_USER_UNINSTALL_ALL_ARGS_CNT;
    napi_value argv[CM_NAPI_USER_UNINSTALL_ALL_ARGS_CNT] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if ((argc != CM_NAPI_USER_UNINSTALL_ALL_ARGS_CNT) &&
        (argc != (CM_NAPI_USER_UNINSTALL_ALL_ARGS_CNT - CM_NAPI_CALLBACK_ARG_CNT))) {
        ThrowParamsError(env, PARAM_ERROR, "arguments count invalid when uninstalling all user cert");
        CM_LOG_E("arguments count is not expected when uninstalling all user cert");
        return nullptr;
    }

    size_t index = 0;
    if (index < argc) {
        context->callback = GetCallback(env, argv[index]);
        if (context->callback == nullptr) {
            ThrowParamsError(env, PARAM_ERROR, "get callback type error");
            CM_LOG_E("get callback function failed when uninstalling all user cert");
            return nullptr;
        }
    }

    return GetInt32(env, 0);
}

static void InstallUserCertExecute(napi_env env, void *data)
{
    UserCertAsyncContext context = static_cast<UserCertAsyncContext>(data);
    context->certUri = static_cast<CmBlob *>(CmMalloc(sizeof(CmBlob)));
    if (context->certUri == nullptr) {
        CM_LOG_E("malloc certUri failed");
        context->errCode = CMR_ERROR_MALLOC_FAIL;
        return;
    }
    (void)memset_s(context->certUri, sizeof(CmBlob), 0, sizeof(CmBlob));

    context->certUri->data = static_cast<uint8_t *>(CmMalloc(OUT_AUTH_URI_SIZE));
    if (context->certUri->data == nullptr) {
        CM_LOG_E("malloc certUri.data failed");
        context->errCode = CMR_ERROR_MALLOC_FAIL;
        return;
    }
    (void)memset_s(context->certUri->data, OUT_AUTH_URI_SIZE, 0, OUT_AUTH_URI_SIZE);
    context->certUri->size = OUT_AUTH_URI_SIZE;

    context->errCode = CmInstallUserTrustedCert(context->userCert, context->certAlias, context->certUri);
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

static void InstallUserCertComplete(napi_env env, napi_status status, void *data)
{
    UserCertAsyncContext context = static_cast<UserCertAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->errCode == CM_SUCCESS) {
        napi_create_uint32(env, 0, &result[0]);
        result[1] = ConvertResultCertUri(env, context->certUri);
    } else {
        result[0] = GenerateBusinessError(env, context->errCode, "install user cert failed");
        napi_get_undefined(env, &result[1]);
    }

    if (context->deferred != nullptr) {
        GeneratePromise(env, context->deferred, context->errCode, result, sizeof(result));
    } else {
        GenerateCallback(env, context->callback, result, sizeof(result));
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
        ThrowParamsError(env, PARAM_ERROR, "queue async work error");
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
        result[0] = GenerateBusinessError(env, context->errCode, "uninstall failed");
        napi_get_undefined(env, &result[1]);
    }

    if (context->deferred != nullptr) {
        GeneratePromise(env, context->deferred, context->errCode, result, sizeof(result));
    } else {
        GenerateCallback(env, context->callback, result, sizeof(result));
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
        ThrowParamsError(env, PARAM_ERROR, "queue async work error");
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
        ThrowParamsError(env, PARAM_ERROR, "queue async work error");
        CM_LOG_E("queue async work failed uninstall all user cert");
        return nullptr;
    }
    return promise;
}

napi_value CMNapiInstallUserTrustedCert(napi_env env, napi_callback_info info)
{
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

    return result;
}

napi_value CMNapiUninstallUserTrustedCert(napi_env env, napi_callback_info info)
{
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

    return result;
}

napi_value CMNapiUninstallAllUserTrustedCert(napi_env env, napi_callback_info info)
{
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

    return result;
}
}  // namespace CMNapi

