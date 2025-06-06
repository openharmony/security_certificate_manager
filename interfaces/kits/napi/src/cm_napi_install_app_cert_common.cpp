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

static napi_value GetCredAlias(napi_env env, napi_value napiObject, CmBlob *&certAlias, uint32_t store)
{
    if (store == APPLICATION_PRIVATE_CERTIFICATE_STORE) {
        return ParseString(env, napiObject, certAlias);
    }
    return ParseCertAlias(env, napiObject, certAlias);
}

static napi_value GetLevelOrCallback(napi_env env, InstallAppCertAsyncContext context, napi_value napiObject)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, napiObject, &type));
    if (type == napi_number) {
        uint32_t level = CM_AUTH_STORAGE_LEVEL_EL1;
        napi_value result = ParseUint32(env, napiObject, level);
        if (result == nullptr || CM_LEVEL_CHECK(level)) {
            ThrowError(env, PARAM_ERROR, "level is not a uint32 or level is invalid.");
            CM_LOG_E("could not get level");
            return nullptr;
        }
        context->level = (enum CmAuthStorageLevel)level;
    } else {
        int32_t ret = GetCallback(env, napiObject, context->callback);
        if (ret != CM_SUCCESS) {
            ThrowError(env, PARAM_ERROR, "Get callback failed, callback must be a function.");
            CM_LOG_E("get callback function faild when install application cert");
            return nullptr;
        }
    }
    return GetInt32(env, 0);
}

napi_value InstallAppCertParseParams(
    napi_env env, napi_callback_info info, InstallAppCertAsyncContext context, uint32_t store)
{
    size_t argc = CM_NAPI_INSTALL_APP_CERT_MAX_ARGS;
    napi_value argv[CM_NAPI_INSTALL_APP_CERT_MAX_ARGS] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if ((argc != CM_NAPI_INSTALL_APP_CERT_MIN_ARGS) && (argc != CM_NAPI_INSTALL_APP_CERT_MAX_ARGS)) {
        ThrowError(env, PARAM_ERROR, "arguments count invalid, arguments count need between 3 and 4.");
        CM_LOG_E("arguments count invalid. argc = %d", argc);
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
        ThrowError(env, PARAM_ERROR, "keystore is not a uint8Array or the length is 0 or too long.");
        CM_LOG_E("could not get keystore");
        return nullptr;
    }

    index++;
    result = ParsePasswd(env, argv[index], context->keystorePwd);
    if (result == nullptr) {
        ThrowError(env, PARAM_ERROR, "keystore Pwd is not a string or the length is 0 or too long.");
        CM_LOG_E("could not get keystore Pwd");
        return nullptr;
    }

    index++;
    result = GetCredAlias(env, argv[index], context->keyAlias, store);
    if (result == nullptr) {
        ThrowError(env, PARAM_ERROR, "keyAlias is not a string or the length is 0 or too long.");
        CM_LOG_E("could not get uri");
        return nullptr;
    }

    index++;
    context->level = CM_AUTH_STORAGE_LEVEL_EL1;
    if (index < argc) {
        if (GetLevelOrCallback(env, context, argv[index]) == nullptr) {
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

static napi_value GenAppCertBusinessError(napi_env env, int32_t errorCode, uint32_t store)
{
    if ((errorCode == CMR_ERROR_PASSWORD_IS_ERR) && (store == APPLICATION_PRIVATE_CERTIFICATE_STORE)) {
        errorCode = CMR_ERROR_INVALID_CERT_FORMAT;
    }
    return GenerateBusinessError(env, errorCode);
}

static void InstallAppCertExecute(napi_env env, void *data)
{
    InstallAppCertAsyncContext context = static_cast<InstallAppCertAsyncContext>(data);
    InitKeyUri(context->keyUri);
    if (context->store == CM_PRI_CREDENTIAL_STORE) {
        struct CmAppCertParam certParam = { (struct CmBlob *)context->keystore, (struct CmBlob *)context->keystorePwd,
            (struct CmBlob *)context->keyAlias, context->store, INIT_INVALID_VALUE, context->level };

        context->result = CmInstallAppCertEx(&certParam, context->keyUri);
    } else {
        context->result = CmInstallAppCert(context->keystore,
            context->keystorePwd, context->keyAlias, context->store, context->keyUri);
    }
}

static void InstallAppCertComplete(napi_env env, napi_status status, void *data)
{
    InstallAppCertAsyncContext context = static_cast<InstallAppCertAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->result == CM_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
        result[1] = InstallAppCertWriteResult(env, context);
    } else {
        result[0] = GenAppCertBusinessError(env, context->result, context->store);
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    }
    if (context->deferred != nullptr) {
        GeneratePromise(env, context->deferred, context->result, result, CM_ARRAY_SIZE(result));
    } else {
        GenerateCallback(env, context->callback, result, CM_ARRAY_SIZE(result), context->result);
    }
    DeleteInstallAppCertAsyncContext(env, context);
}

napi_value InstallAppCertAsyncWork(napi_env env, InstallAppCertAsyncContext asyncContext)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, asyncContext->callback, &asyncContext->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "InstallAppCertAsyncWork", NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resourceName,
        InstallAppCertExecute,
        InstallAppCertComplete,
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
    CM_LOG_I("install app cert enter, store = %u", store);

    InstallAppCertAsyncContext context = CreateInstallAppCertAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        return nullptr;
    }

    context->store = store;

    napi_value result = InstallAppCertParseParams(env, info, context, store);
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

    CM_LOG_I("install app cert end");
    return result;
}
}  // namespace CertManagerNapi
