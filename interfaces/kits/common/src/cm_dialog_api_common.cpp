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

#include "cm_dialog_api_common.h"
#include "bundle_mgr_proxy.h"
#include "cm_log.h"
#include "cm_ukey_ability_type.h"
#include "cm_ukey_dialog_common.h"
#include "syspara/parameters.h"
#include "systemcapability.h"
#include "hks_api.h"
#include "cm_mem.h"

namespace OHOS::Security::CertManager::Dialog {
/* HUKS ability query buffer length */
constexpr static uint32_t HAP_INFO_MAX_LENGTH = 128;

static OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> GetBundleMgrProxy()
{
    auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        CM_LOG_E("fail to get system ability mgr.");
        return nullptr;
    }

    auto remoteObject = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        CM_LOG_E("fail to get bundle manager proxy.");
        return nullptr;
    }
    return OHOS::iface_cast<OHOS::AppExecFwk::IBundleMgr>(remoteObject);
}

int32_t GetCallerLabelName(std::shared_ptr<OHOS::AbilityRuntime::AbilityContext> abilityContext,
    std::string &labelName)
{
    if (abilityContext == nullptr) {
        CM_LOG_E("abilitContext is nullptr.");
        return CM_FAILURE;
    }
    OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    if (bundleMgrProxy == nullptr) {
        CM_LOG_E("Failed to get bundle manager proxy.");
        return CM_FAILURE;
    }

    OHOS::AppExecFwk::BundleInfo bundleInfo;
    int32_t flags = static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT) |
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION) |
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY);
    int32_t resCode = bundleMgrProxy->GetBundleInfoForSelf(flags, bundleInfo);
    if (resCode != CM_SUCCESS) {
        CM_LOG_E("Failed to get bundleInfo, resCode is %d", resCode);
        return CM_FAILURE;
    }

    if (abilityContext->GetResourceManager() == nullptr) {
        CM_LOG_E("context get resourcemanager faild");
        return CMR_ERROR_NULL_POINTER;
    }

    resCode = abilityContext->GetResourceManager()->GetStringById(bundleInfo.applicationInfo.labelId, labelName);
    if (resCode != CM_SUCCESS) {
        CM_LOG_E("getStringById is faild, resCode is %d", resCode);
        return CM_FAILURE;
    }
    return CM_SUCCESS;
}

bool IsEnableCACertDialog()
{
    bool isSupportSyscap = HasSystemCapability(CERT_MGR_DIALOG_SYSCAP.c_str());
    bool isPc = OHOS::system::GetParameter(CONST_NAME_DEVICETYPE, "") == DEVICETYPE_PC;
    bool isEnableCACertDialog = OHOS::system::GetBoolParameter(CONST_NAME_ENABLE_CA_DIALOG, false);
    return isSupportSyscap && (isPc || isEnableCACertDialog);
}

/* Assemble the system default UKey Pin dialog want (kit direct-launch
 * fallback path, spec v4 D22/D25 v2):
 * com.ohos.certmanager/CertPickerUIExtAbility (sys/commonUI, pageType=7).
 * customData is not delivered (the default dialog has no consumer, D18
 * semantics). */
int32_t GetDefaultUkeyAuthCertWant(const CmBlob *keyUri, OHOS::AAFwk::Want &want)
{
    want.SetElementName(CERT_MANAGER_BUNDLENAME, CERT_MANAGER_ABILITYNAME);
    want.SetParam(CERT_MANAGER_CALLER_UID, static_cast<int32_t>(getuid()));
    want.SetParam(PARAM_UI_EXTENSION_TYPE, SYS_COMMON_UI);
    want.SetParam(CERT_MANAGER_PAGE_TYPE, static_cast<int32_t>(CmDialogPageType::PAGE_UKEY_PIN_AUTHORIZE));
    std::string uriStr(reinterpret_cast<char *>(keyUri->data), keyUri->size);
    want.SetParam(CERT_MANAGER_CERT_KEY_URI, uriStr);
    return CM_SUCCESS;
}

static int32_t QueryAbilityInfo(const CmBlob *keyUri, std::string &abilityName,
    std::string &bundleName, uint32_t &abilityType)
{
    struct HksAbilityInfo abilityInfo{};
    abilityInfo.abilityName.data = (uint8_t*)CmMalloc(HAP_INFO_MAX_LENGTH);
    abilityInfo.bundleName.data = (uint8_t*)CmMalloc(HAP_INFO_MAX_LENGTH);
    if (abilityInfo.abilityName.data == nullptr || abilityInfo.bundleName.data == nullptr) {
        CM_LOG_E("app info malloc failed");
        CM_FREE_PTR(abilityInfo.abilityName.data);
        CM_FREE_PTR(abilityInfo.bundleName.data);
        return CMR_ERROR_MALLOC_FAIL;
    }
    abilityInfo.abilityName.size = HAP_INFO_MAX_LENGTH;
    abilityInfo.bundleName.size = HAP_INFO_MAX_LENGTH;
    struct HksBlob resourceId = {
        .size = keyUri->size,
        .data = keyUri->data
    };
    int32_t ret = HksQueryAbilityInfo(&resourceId, &abilityInfo);
    if (ret != HKS_SUCCESS) {
        CM_LOG_E("query ability info failed");
        CM_FREE_PTR(abilityInfo.abilityName.data);
        CM_FREE_PTR(abilityInfo.bundleName.data);
        return ret;
    }
    abilityName.assign(reinterpret_cast<char *>(abilityInfo.abilityName.data), abilityInfo.abilityName.size);
    bundleName.assign(reinterpret_cast<char *>(abilityInfo.bundleName.data), abilityInfo.bundleName.size);
    CM_FREE_PTR(abilityInfo.abilityName.data);
    CM_FREE_PTR(abilityInfo.bundleName.data);
    /* abilityType pass-through (HksAbilityInfo already has the field; when
     * the HUKS query implementation does not fill it yet, zero-initialization
     * keeps 0 = UIAbility, consistent with existing registration behavior) */
    abilityType = static_cast<uint32_t>(abilityInfo.abilityType);
    return CM_SUCCESS;
}

int32_t GetUkeyAbilityInfo(const CmBlob *keyUri, std::string &bundleName,
    std::string &abilityName, uint32_t &abilityType)
{
    if (keyUri == nullptr || keyUri->data == nullptr || keyUri->size == 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    abilityType = CM_UKEY_ABILITY_TYPE_UIABILITY;
    return QueryAbilityInfo(keyUri, abilityName, bundleName, abilityType);
}

int32_t GetCustomerAuthCertWant(const CmBlob *keyUri, const CmBlob *customData,
    OHOS::AAFwk::Want &want)
{
    if (keyUri == nullptr || keyUri->data == nullptr || keyUri->size == 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    std::string abilityName = "";
    std::string bundleName = "";
    uint32_t abilityType = CM_UKEY_ABILITY_TYPE_UIABILITY;
    int32_t ret = QueryAbilityInfo(keyUri, abilityName, bundleName, abilityType);
    /**
     * When the query for the custom dialog's ability information fails,
     * launch the default dialog of the certificate manager (spec §4.1).
     */
    if (ret != HKS_SUCCESS) {
        CM_LOG_E("query ability failed, ret = %d.", ret);
        GetDefaultUkeyAuthCertWant(keyUri, want);
        return CM_SUCCESS;
    }
    /* A UIExtension registration is launched via the SA session only on
     * PC/PC mode (caller-side precheck); reaching this direct-launch path
     * means a non-PC scenario, so fall back to the system default dialog per
     * D25 v2 - StartUIAbility must not be used on a UIExtension-type ability
     * (AMS type mismatch). */
    if (abilityType == CM_UKEY_ABILITY_TYPE_UIEXTENSION) {
        CM_LOG_I("uiextension pin dialog declined by sa path (non-pc), fall back to default");
        GetDefaultUkeyAuthCertWant(keyUri, want);
        return CM_SUCCESS;
    }

    want.SetElementName(bundleName, abilityName);
    want.SetAction(ACTION_UKEY_PIN_AUTH);
    want.SetParam(CERT_MANAGER_CALLER_UID, static_cast<int32_t>(getuid()));
    std::string uriStr(reinterpret_cast<char *>(keyUri->data), keyUri->size);
    want.SetParam(CERT_MANAGER_CERT_KEY_URI, uriStr);
    if (customData != nullptr && customData->size > 0) {
        /* Custom dialog passes customData through (base64, spec D18) */
        want.SetParam(CM_UKEY_DIALOG_PARAM_CUSTOM_DATA,
            CmBase64Encode(customData->data, customData->size));
    }
    return CM_SUCCESS;
}

bool IsSupportDialogSyscap()
{
    return HasSystemCapability(CERT_MGR_DIALOG_SYSCAP.c_str());
}
}
