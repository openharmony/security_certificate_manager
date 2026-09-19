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

#include "ukey_auth_extension_context.h"

#include "ability_manager_client.h"
#include "cert_manager_api.h"
#include "cm_log.h"
#ifdef SUPPORT_SCREEN
#include "window.h"
#endif // SUPPORT_SCREEN

namespace OHOS {
namespace AbilityRuntime {
namespace {

void ReportToCertManager(const std::string &requestId, int32_t resultCode)
{
    if (requestId.empty()) {
        CM_LOG_E("requestId is empty, skip report");
        return;
    }
    struct CmBlob requestIdBlob = { static_cast<uint32_t>(requestId.size()),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(requestId.c_str())) };
    int32_t ret = CmReportUkeyAuthResult(&requestIdBlob, resultCode);
    CM_LOG_I("CmReportUkeyAuthResult resultCode=%d, ret=%d", resultCode, ret);
}
} // namespace

void UkeyAuthExtensionContext::SetSessionInfo(const sptr<AAFwk::SessionInfo> &sessionInfo)
{
    sessionInfo_ = sessionInfo;
}

void UkeyAuthExtensionContext::SetRequestId(const std::string &requestId)
{
    requestId_ = requestId;
}

ErrCode UkeyAuthExtensionContext::TerminateSelf()
{
    CM_LOG_D("begin");
    ReportToCertManager(requestId_, 0);
    return UIExtensionContext::TerminateSelf();
}

ErrCode UkeyAuthExtensionContext::TerminateSelfWithResultAndReport(int32_t resultCode, const AAFwk::Want &want)
{
    CM_LOG_D("begin");
    ReportToCertManager(requestId_, resultCode);
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->TransferAbilityResultForExtension(
        GetToken(), resultCode, want);
    if (err != ERR_OK) {
        CM_LOG_E("TransferAbilityResultForExtension failed, err = %d", err);
        // UkeyAuth terminates only when the result is delivered; a failed transfer surfaces the error to the caller.
        return err;
    }
#ifdef SUPPORT_SCREEN
    auto uiWindow = GetWindow();
    if (uiWindow == nullptr) {
        CM_LOG_E("null uiWindow");
        return AAFwk::INVALID_PARAMETERS_ERR;
    }
    auto ret = uiWindow->TransferAbilityResult(resultCode, want);
    if (ret != Rosen::WMError::WM_OK) {
        CM_LOG_E("TransferAbilityResult to window failed, ret = %d", ret);
        return AAFwk::INVALID_PARAMETERS_ERR;
    }
#endif // SUPPORT_SCREEN
    err = AAFwk::AbilityManagerClient::GetInstance()->TerminateUIExtensionAbility(sessionInfo_);
    if (err != ERR_OK) {
        CM_LOG_E("TerminateUIExtensionAbility failed, err = %d", err);
    }
    return err;
}
} // namespace AbilityRuntime
} // namespace OHOS
