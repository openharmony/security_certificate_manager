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

#include "cm_napi_report_ukey_auth_result.h"

#include "securec.h"

#include "cert_manager_api.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_metrics.h"
#include "cm_napi_dialog_common.h"

namespace CMNapi {
namespace {
constexpr uint32_t CM_MAX_REQUEST_ID_LEN = 64;
}  // namespace

// Parse the requestId string (non-empty, at most CM_MAX_REQUEST_ID_LEN bytes).
// The blob carries the raw string bytes without the terminating zero: the SA
// compares it byte-for-byte against the session's requestId.
static bool ParseRequestId(napi_env env, napi_value arg, struct CmBlob &requestId)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, arg, &type);
    if (status != napi_ok || type != napi_string) {
        CM_LOG_E("requestId is not string");
        return false;
    }

    size_t length = 0;
    status = napi_get_value_string_utf8(env, arg, nullptr, 0, &length);
    if (status != napi_ok) {
        CM_LOG_E("could not get requestId length");
        return false;
    }
    if (length == 0 || length > CM_MAX_REQUEST_ID_LEN) {
        CM_LOG_E("requestId length invalid, length = %zu", length);
        return false;
    }

    char *data = static_cast<char *>(CmMalloc(length + 1));
    if (data == nullptr) {
        CM_LOG_E("could not alloc memory");
        return false;
    }
    (void)memset_s(data, length + 1, 0, length + 1);
    size_t copied = 0;
    status = napi_get_value_string_utf8(env, arg, data, length + 1, &copied);
    if (status != napi_ok) {
        CM_LOG_E("could not get requestId");
        CmFree(data);
        return false;
    }

    requestId.data = reinterpret_cast<uint8_t *>(data);
    requestId.size = static_cast<uint32_t>(length);
    return true;
}

static bool ParseResultCode(napi_env env, napi_value arg, int32_t &resultCode)
{
    napi_valuetype type = napi_undefined;
    napi_status status = napi_typeof(env, arg, &type);
    if (status != napi_ok || type != napi_number) {
        CM_LOG_E("resultCode is not number");
        return false;
    }
    if (napi_get_value_int32(env, arg, &resultCode) != napi_ok) {
        CM_LOG_E("could not get resultCode value");
        return false;
    }
    return true;
}

napi_value CMNapiReportUkeyAuthResult(napi_env env, napi_callback_info info)
{
    CM_LOG_I("report ukey auth result enter");
    OHOS::Security::CertManager::CmMetricsReport report("reportUkeyAuthResult",
        OHOS::Security::CertManager::CmMetricsKind::DIALOG);
    report.Start();
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    if (CheckSyscapReturnVoid(env, &result) != CM_SUCCESS) {
        report.Finish(DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED);
        return result;
    }

    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != PARAM_SIZE_TWO) {
        CM_LOG_E("params number mismatch");
        ThrowError(env, PARAM_ERROR, "parse report params failed", &report);
        return nullptr;
    }

    struct CmBlob requestId = { 0, nullptr };
    if (!ParseRequestId(env, argv[0], requestId)) {
        CM_LOG_E("parse requestId failed");
        ThrowError(env, PARAM_ERROR, "parse report params failed", &report);
        return nullptr;
    }

    int32_t resultCode = 0;
    if (!ParseResultCode(env, argv[1], resultCode)) {
        CM_LOG_E("parse resultCode failed");
        CM_FREE_PTR(requestId.data);
        ThrowError(env, PARAM_ERROR, "parse report params failed", &report);
        return nullptr;
    }

    napi_value undefined = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &undefined));
    napi_deferred deferred = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &result));
    int32_t ret = CmReportUkeyAuthResult(&requestId, resultCode);
    CM_FREE_PTR(requestId.data);
    if (ret == CM_SUCCESS) {
        report.Finish(CM_SUCCESS);
        NAPI_CALL(env, napi_resolve_deferred(env, deferred, undefined));
    } else {
        napi_value error = GenerateBusinessError(env, ret, &report);
        NAPI_CALL(env, napi_reject_deferred(env, deferred, error));
    }

    CM_LOG_I("report ukey auth result end");
    return result;
}
}  // namespace CMNapi
