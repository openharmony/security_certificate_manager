/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "cm_napi_import_ukey_cert.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_util.h"
#include "cm_napi_common.h"
#include "cm_type_free.h"

namespace CMNapi {
namespace {
constexpr int CM_NAPI_IMPORT_UKEY_CERT_ARGS = 3;
}  // namespace

struct ImportUkeyCertAsyncContextT {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_ref callback = nullptr;

    struct CmBlob *keyUri = nullptr;
    struct CmBlob cert = { 0 };
    struct UkeyInfo ukeyInfo = { CM_CERT_PURPOSE_DEFAULT };
    int32_t result = 0;
};
using ImportUkeyCertAsyncContext = ImportUkeyCertAsyncContextT *;

static ImportUkeyCertAsyncContext CreateImportUkeyCertAsyncContext()
{
    ImportUkeyCertAsyncContext context =
        static_cast<ImportUkeyCertAsyncContext>(CmMalloc(sizeof(ImportUkeyCertAsyncContextT)));
    if (context != nullptr) {
        (void)memset_s(
            context, sizeof(ImportUkeyCertAsyncContextT), 0, sizeof(ImportUkeyCertAsyncContextT));
    }
    return context;
}

static void DeleteImportUkeyCertAsyncContext(napi_env env, ImportUkeyCertAsyncContext &context)
{
    if (context == nullptr) {
        return;
    }

    DeleteNapiContext(env, context->asyncWork, context->callback);

    if (context->keyUri != nullptr) {
        FreeCmBlob(context->keyUri);
    }

    CM_FREE_BLOB(context->cert);

    CmFree(context);
    context = nullptr;
}

static bool CheckCertPurpose(uint32_t certPurpose)
{
    switch (certPurpose) {
        case CM_CERT_PURPOSE_DEFAULT:
        case CM_CERT_PURPOSE_SIGN:
        case CM_CERT_PURPOSE_ENCRYPT:
            return true;
        default:
            CM_LOG_E("invalid cert purpose: %u", certPurpose);
            return false;
    }
}

static napi_value ParseUkeyInfo(napi_env env, napi_value object, ImportUkeyCertAsyncContext context)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, object, &valueType));
    if (valueType != napi_object) {
        ThrowError(env, PARAM_ERROR, "parameter type invalid.");
        CM_LOG_E("parameter type invalid");
        return nullptr;
    }
    bool hasProperty = false;
    napi_status status = napi_has_named_property(env, object, CM_CERT_PURPOSE.c_str(), &hasProperty);
    if (status != napi_ok) {
        CM_LOG_E("Failed to check certPurpose");
        ThrowError(env, PARAM_ERROR, "Failed to get certPurpose.");
        return nullptr;
    }
    if (!hasProperty) {
        context->ukeyInfo.certPurpose = CM_CERT_PURPOSE_DEFAULT;
        return GetInt32(env, 0);
    }
    napi_value certPurposeValue = nullptr;
    status = napi_get_named_property(env, object, CM_CERT_PURPOSE.c_str(), &certPurposeValue);
    if (status != napi_ok || certPurposeValue == nullptr) {
        CM_LOG_E("Failed to get certPurpose");
        ThrowError(env, PARAM_ERROR, "Failed to get certPurpose.");
        return nullptr;
    }
    napi_valuetype type = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, certPurposeValue, &type));
    if (type == napi_undefined) {
        context->ukeyInfo.certPurpose = CM_CERT_PURPOSE_DEFAULT;
        return GetInt32(env, 0);
    }
    if (type != napi_number) {
        CM_LOG_E("arguments invalid, type of cert purpose is not number.");
        ThrowError(env, PARAM_ERROR, "cert purpose is not number.");
        return nullptr;
    }
    uint32_t certPurpose = CM_CERT_PURPOSE_DEFAULT;
    if (ParseUint32(env, certPurposeValue, certPurpose) == nullptr) {
        CM_LOG_E("parse uint32 failed");
        ThrowError(env, PARAMETER_VALIDATION_FAILED, "parse cert purpose failed.");
        return nullptr;
    }
    if (!CheckCertPurpose(certPurpose)) {
        ThrowError(env, PARAMETER_VALIDATION_FAILED, "invalid cert purpose.");
        return nullptr;
    }
    context->ukeyInfo.certPurpose = static_cast<enum CmCertificatePurpose>(certPurpose);
    return GetInt32(env, 0);
}

static napi_value ParseKeyUri(napi_env env, napi_value object, CmBlob *&stringBlob)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, object, &valueType));
    if (valueType != napi_string) {
        ThrowError(env, PARAM_ERROR, "parameter type invalid.");
        CM_LOG_E("parameter type invalid");
        return nullptr;
    }

    napi_value result = ParseString(env, object, stringBlob);
    if (result == nullptr) {
        CM_LOG_E("could not get keyUri");
        ThrowError(env, PARAMETER_VALIDATION_FAILED, "failed to get cert.");
        return nullptr;
    }
    if (stringBlob->size == 0) {
        CM_LOG_E("keyUri is empty");
        ThrowError(env, PARAMETER_VALIDATION_FAILED, "keyUri is empty.");
        return nullptr;
    }
    return GetInt32(env, 0);
}

static napi_value ParseCert(napi_env env, napi_value object, CmBlob &arrayBlob)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, object, &valueType));
    if (valueType != napi_object) {
        ThrowError(env, PARAM_ERROR, "parameter type invalid.");
        CM_LOG_E("parameter type invalid");
        return nullptr;
    }

    napi_value result = GetUint8Array(env, object, arrayBlob);
    if (result == nullptr) {
        ThrowError(env, PARAMETER_VALIDATION_FAILED, "failed to get cert.");
        CM_LOG_E("could not get cert");
        return nullptr;
    }
    if (arrayBlob.size == 0) {
        ThrowError(env, PARAMETER_VALIDATION_FAILED, "cert is empty.");
        CM_LOG_E("cert is empty");
        return nullptr;
    }
    return GetInt32(env, 0);
}

static napi_value ParseImportParams(
    napi_env env, napi_callback_info info, ImportUkeyCertAsyncContext context)
{
    size_t argc = CM_NAPI_IMPORT_UKEY_CERT_ARGS;
    napi_value argv[CM_NAPI_IMPORT_UKEY_CERT_ARGS] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));

    if (argc != CM_NAPI_IMPORT_UKEY_CERT_ARGS) {
        ThrowError(env, PARAM_ERROR, "Missing parameter, arguments count need 3.");
        CM_LOG_E("Missing parameter");
        return nullptr;
    }

    size_t index = 0;
    napi_value result = ParseKeyUri(env, argv[index], context->keyUri);
    if (result == nullptr) {
        ThrowError(env, PARAMETER_VALIDATION_FAILED, "failed to get keyUri.");
        CM_LOG_E("parse keyUri failed");
        return nullptr;
    }

    ++index;
    result = ParseCert(env, argv[index], context->cert);
    if (result == nullptr) {
        CM_LOG_E("could not get cert");
        return nullptr;
    }

    ++index;
    result = ParseUkeyInfo(env, argv[index], context);
    if (result == nullptr) {
        CM_LOG_E("could not get ukey info");
        return nullptr;
    }

    return GetInt32(env, 0);
}

static void ImportUkeyCertExecute(napi_env env, void *data)
{
    ImportUkeyCertAsyncContext context = static_cast<ImportUkeyCertAsyncContext>(data);
    context->keyUri->size -= 1;
    context->result = CmImportUkeyCert(context->keyUri, &context->cert, &context->ukeyInfo);
}

static void ImportUkeyCertComplete(napi_env env, napi_status status, void *data)
{
    ImportUkeyCertAsyncContext context = static_cast<ImportUkeyCertAsyncContext>(data);
    napi_value result[RESULT_NUMBER] = { nullptr };
    if (context->result == CM_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    } else {
        result[0] = GenerateBusinessError(env, context->result);
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    }
    GeneratePromise(env, context->deferred, context->result, result, CM_ARRAY_SIZE(result));
    DeleteImportUkeyCertAsyncContext(env, context);
}

static napi_value ImportUkeyCertAsyncWork(napi_env env, ImportUkeyCertAsyncContext asyncContext)
{
    napi_value promise = nullptr;
    GenerateNapiPromise(env, asyncContext->callback, &asyncContext->deferred, &promise);

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "ImportUkeyCertAsyncWork", NAPI_AUTO_LENGTH, &resourceName));
    NAPI_CALL(env, napi_create_async_work(
        env,
        nullptr,
        resourceName,
        ImportUkeyCertExecute,
        ImportUkeyCertComplete,
        static_cast<void *>(asyncContext),
        &asyncContext->asyncWork)
    );
    napi_status napiStatus = napi_queue_async_work(env, asyncContext->asyncWork);
    if (napiStatus != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        DeleteImportUkeyCertAsyncContext(env, asyncContext);
        CM_LOG_E("import ukey cert could not queue async work");
        return nullptr;
    }
    return promise;
}

napi_value CMNapiImportUkeyCert(napi_env env, napi_callback_info info)
{
    CM_LOG_I("import ukey cert enter");

    ImportUkeyCertAsyncContext context = CreateImportUkeyCertAsyncContext();
    if (context == nullptr) {
        CM_LOG_E("could not create context");
        return nullptr;
    }

    napi_value result = ParseImportParams(env, info, context);
    if (result == nullptr) {
        CM_LOG_E("could not parse params");
        DeleteImportUkeyCertAsyncContext(env, context);
        return nullptr;
    }
    result = ImportUkeyCertAsyncWork(env, context);
    if (result == nullptr) {
        CM_LOG_E("could not start async work");
        DeleteImportUkeyCertAsyncContext(env, context);
        return nullptr;
    }

    CM_LOG_I("import ukey cert end");
    return result;
}
}  // namespace CMNapi
