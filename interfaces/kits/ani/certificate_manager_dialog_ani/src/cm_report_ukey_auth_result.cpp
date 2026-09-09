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

#include "cm_report_ukey_auth_result.h"
#include "securec.h"
#include "cert_manager_api.h"
#include "cm_mem.h"
#include "cm_ani_utils.h"
#include "cm_ani_common.h"
#include "cm_log.h"

namespace OHOS::Security::CertManager::Ani {
namespace {
constexpr uint32_t CM_MAX_REQUEST_ID_LEN = 64;
} // namespace

CmReportUkeyAuthResult::CmReportUkeyAuthResult(ani_env *env, ani_string aniRequestId,
    ani_double aniResultCode, ani_object callback)
    : CertManagerAniImpl(env, "reportUkeyAuthResult", CmMetricsKind::DIALOG)
{
    this->aniRequestId = aniRequestId;
    this->aniResultCode = aniResultCode;
    this->callback = callback;
}

int32_t CmReportUkeyAuthResult::Init()
{
    return CM_SUCCESS;
}

int32_t CmReportUkeyAuthResult::GetParamsFromEnv()
{
    if (this->env == nullptr) {
        CM_LOG_E("report ukey auth result failed, env is null.");
        return CMR_ERROR_NULL_POINTER;
    }

    std::string requestIdStr;
    int32_t ret = AniUtils::ParseString(this->env, this->aniRequestId, requestIdStr);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("parse requestId failed, ret = %d", ret);
        return ret;
    }
    if (requestIdStr.empty() || requestIdStr.size() > CM_MAX_REQUEST_ID_LEN) {
        CM_LOG_E("requestId length invalid, length = %zu", requestIdStr.size());
        return CMR_DIALOG_ERROR_PARAM_INVALID;
    }

    /* The blob carries the raw string bytes without the terminating zero: the
     * SA compares it byte-for-byte against the session's requestId. */
    this->requestId.data = static_cast<uint8_t *>(CmMalloc(requestIdStr.size()));
    if (this->requestId.data == nullptr) {
        CM_LOG_E("could not alloc memory");
        return CMR_ERROR_MALLOC_FAIL;
    }
    if (memcpy_s(this->requestId.data, requestIdStr.size(), requestIdStr.c_str(), requestIdStr.size()) != EOK) {
        CM_LOG_E("copy requestId failed");
        CM_FREE_PTR(this->requestId.data);
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    this->requestId.size = static_cast<uint32_t>(requestIdStr.size());
    this->reportedResultCode = static_cast<int32_t>(this->aniResultCode);
    return CM_SUCCESS;
}

int32_t CmReportUkeyAuthResult::InvokeInnerApi()
{
    return ::CmReportUkeyAuthResult(&this->requestId, this->reportedResultCode);
}

int32_t CmReportUkeyAuthResult::UnpackResult()
{
    /* the whole call is synchronous: settle the AsyncCallbackWrapper right
     * away so the promise resolves; failure paths never reach here and are
     * rejected by the ets layer through the returned NativeResult */
    ani_object businessError{};
    int32_t ret = AniUtils::GenerateBusinessError(this->env, CM_SUCCESS, "", businessError);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("generate businessError failed, ret = %d", ret);
        return CMR_DIALOG_ERROR_INTERNAL;
    }

    ani_ref nullRef{};
    ani_status status = this->env->GetNull(&nullRef);
    if (status != ANI_OK) {
        CM_LOG_E("get nullRef failed. status = %d", static_cast<int32_t>(status));
        return CMR_DIALOG_ERROR_INTERNAL;
    }

    status = this->env->Object_CallMethodByName_Void(this->callback, "invoke",
        "C{@ohos.base.BusinessError}Y:", businessError, nullRef);
    if (status != ANI_OK) {
        CM_LOG_E("invoke callback failed. status = %d", static_cast<int32_t>(status));
        return CMR_DIALOG_ERROR_INTERNAL;
    }
    return CM_SUCCESS;
}

void CmReportUkeyAuthResult::OnFinish()
{
    CM_FREE_BLOB(this->requestId);
}

ani_object CmReportUkeyAuthResult::GenerateResult()
{
    if (this->resultCode != CM_SUCCESS) {
        return GetAniDialogNativeResult(this->env, this->resultCode);
    }

    ani_object nativeResult{};
    int32_t ret = AniUtils::GenerateNativeResult(this->env, this->resultCode, nullptr, this->result,
        nativeResult);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("generate native result failed, ret = %d", ret);
        return nullptr;
    }
    return nativeResult;
}
}
