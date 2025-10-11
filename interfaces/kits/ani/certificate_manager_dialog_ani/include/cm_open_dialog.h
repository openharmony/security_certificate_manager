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

#ifndef CM_OPEN_DIALOG_H
#define CM_OPEN_DIALOG_H

#include "ani.h"
#include "cm_type.h"
#include "ability_context.h"
#include "ui_content.h"
#include "iservice_registry.h"
#include "bundle_mgr_proxy.h"
#include "system_ability_definition.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"

namespace OHOS::Security::CertManager::Ani {
const std::string PARAM_UI_EXTENSION_TYPE = "ability.want.params.uiExtensionType";
const std::string SYS_COMMON_UI = "sys/commonUI";
const std::string CERT_MANAGER_BUNDLENAME = "com.ohos.certmanager";
const std::string CERT_MANAGER_ABILITYNAME = "CertPickerUIExtAbility";
const std::string CERT_MANAGER_PAGE_TYPE = "pageType";
const std::string CERT_MANAGER_CERTSCOPE_TYPE = "certScope";
const std::string CERT_MANAGER_CERTIFICATE_DATA = "cert";
const std::string CERT_MANAGER_CALLER_BUNDLENAME = "bundleName";
const std::string CERT_MANAGER_CALLER_UID = "appUid";
const std::string CERT_MANAGER_CERT_URI = "certUri";
const std::string CERT_MANAGER_OPERATION_TYPE = "operationType";
const std::string CERT_MANAGER_SHOW_INSTALL_BUTTON = "showInstallButton";

constexpr int32_t PARAM0 = 0;
constexpr int32_t PARAM1 = 1;
constexpr int32_t PARAM2 = 2;
constexpr int32_t PARAM3 = 3;
constexpr int32_t PARAM_SIZE_TWO = 2;
constexpr int32_t PARAM_SIZE_THREE = 3;
constexpr int32_t PARAM_SIZE_FOUR = 4;

enum CmDialogPageType {
    PAGE_MAIN = 1,
    PAGE_CA_CERTIFICATE = 2,
    PAGE_CREDENTIAL = 3,
    PAGE_INSTALL_CERTIFICATE = 4,
    PAGE_INSTALL_CA_GUIDE = 5,
    PAGE_REQUEST_AUTHORIZE = 6
};

enum CmCertificateType {
    CA_CERT = 1
};

enum CertificateScope {
    NOT_SPECIFIED = 0,
    CURRENT_USER = 1,
    GLOBAL_USER = 2
};

struct CmOpeonInstallDialogParams {
    ani_enum_item aniCertType;
    ani_enum_item aniCertScope;
    ani_string aniCert;
};

enum OperationType {
    DIALOG_OPERATION_INSTALL = 1,
    DIALOG_OPERATION_UNINSTALL = 2,
    DIALOG_OPERATION_DETAIL = 3,
};

using namespace OHOS::AbilityRuntime;

class CmAniUIExtensionCallback {
public:
    CmAniUIExtensionCallback(ani_vm *vm, std::shared_ptr<AbilityContext> context, ani_ref aniCallback);
    virtual ~CmAniUIExtensionCallback();
    void SetSessionId(const int32_t sessionId);
    void OnRelease(const int32_t releaseCode);
    void OnResult(const int32_t resultCode, const OHOS::AAFwk::Want &result);
    void OnError(const int32_t code, const std::string &name, const std::string &message);
    void OnRemoteReady(const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy> &uiProxy);
    void OnDestroy();
    void invokeCallback(ani_env *env, int32_t code, ani_object result);
    virtual void OnReceive(const OHOS::AAFwk::WantParams &request);
    virtual ani_object GetDefaultResult(ani_env *env);

protected:
    ani_vm *vm = nullptr;
    ani_ref aniCallback = nullptr;
    bool isReleased = false;
    int32_t sessionId = 0;
    std::shared_ptr<AbilityContext> context = nullptr;
    std::mutex lockIsReleased;
};

class CmAniUIExtensionCallbackString : public CmAniUIExtensionCallback {
public:
    CmAniUIExtensionCallbackString(ani_vm *vm, std::shared_ptr<AbilityContext> context, ani_ref aniCallback);
    ~CmAniUIExtensionCallbackString() {}
    void OnReceive(const OHOS::AAFwk::WantParams &request) override;
    ani_object GetDefaultResult(ani_env *env) override;
};

int32_t StartUIExtensionAbility(std::shared_ptr<AbilityContext> context, OHOS::AAFwk::Want want,
    std::shared_ptr<CmAniUIExtensionCallback> uiExtCallback);
};
#endif