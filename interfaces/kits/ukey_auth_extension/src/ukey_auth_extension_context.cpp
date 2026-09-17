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
#include "hilog_tag_wrapper.h"
#ifdef SUPPORT_SCREEN
#include "window.h"
#endif // SUPPORT_SCREEN

namespace OHOS {
namespace AbilityRuntime {
namespace {

void ReportToCertManager(const std::string &requestId, int32_t resultCode)
{
    if (requestId.empty()) {
        TAG_LOGE(AAFwkTag::UI_EXT, "requestId is empty, skip report");
        return;
    }
    struct CmBlob requestIdBlob = { static_cast<uint32_t>(requestId.size()),
        const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(requestId.c_str())) };
    int32_t ret = CmReportUkeyAuthResult(&requestIdBlob, resultCode);
    TAG_LOGI(AAFwkTag::UI_EXT, "CmReportUkeyAuthResult resultCode=%{public}d, ret=%{public}d", resultCode, ret);
}
} // namespace

void UkeyAuthExtensionContext::SetWindow(const sptr<Rosen::Window> &window)
{
#ifdef SUPPORT_SCREEN
    uiWindow_ = window;
#endif // SUPPORT_SCREEN
}

sptr<Rosen::Window> UkeyAuthExtensionContext::GetWindow() const
{
#ifdef SUPPORT_SCREEN
    return uiWindow_;
#else
    return nullptr;
#endif // SUPPORT_SCREEN
}

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
    TAG_LOGD(AAFwkTag::UI_EXT, "begin");
    ReportToCertManager(requestId_, 0);
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->TerminateAbility(GetToken(), -1, nullptr);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "ret = %{public}d", err);
    }
    return err;
}

ErrCode UkeyAuthExtensionContext::TerminateSelfWithResult(int32_t resultCode, const AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "begin");
    ReportToCertManager(requestId_, resultCode);
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->TransferAbilityResultForExtension(
        GetToken(), resultCode, want);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "TransferAbilityResultForExtension failed, err = %{public}d", err);
        // UkeyAuth terminates only when the result is delivered; a failed transfer surfaces the error to the caller.
        return err;
    }
#ifdef SUPPORT_SCREEN
    if (uiWindow_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null uiWindow");
        return AAFwk::INVALID_PARAMETERS_ERR;
    }
    auto ret = uiWindow_->TransferAbilityResult(resultCode, want);
    if (ret != Rosen::WMError::WM_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "TransferAbilityResult to window failed, ret = %{public}d", ret);
        return AAFwk::INVALID_PARAMETERS_ERR;
    }
#endif // SUPPORT_SCREEN
    err = AAFwk::AbilityManagerClient::GetInstance()->TerminateUIExtensionAbility(sessionInfo_);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "TerminateUIExtensionAbility failed, err = %{public}d", err);
    }
    return err;
}
} // namespace AbilityRuntime
} // namespace OHOS
