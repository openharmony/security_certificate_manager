/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not this file except in compliance with the License.
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

#ifndef CM_SYSTEM_DIALOG_CONNECTION_H
#define CM_SYSTEM_DIALOG_CONNECTION_H

#include <mutex>
#include <string>

#include "ability_connect_callback_stub.h"
#include "message_parcel.h"

#include "cm_ukey_auth_dialog_manager.h"

namespace OHOS::Security::CertManager {

/* System dialog service connection object: once connected, sends the
 * START_DIALOG command to the service stub in the useriam message format
 * (three key-value pairs: bundleName / abilityName / parameters); on
 * disconnect, notifies the manager to enter the grace period. */
class CmSystemDialogConnection : public AAFwk::AbilityConnectionStub {
public:
    CmSystemDialogConnection(const std::string &requestId, const std::string &bundle,
        const std::string &ability, const std::string &paramsJson);
    ~CmSystemDialogConnection() override = default;

    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int32_t resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
        int32_t resultCode) override;
    /* At session end (total timeout / normal finish), ask the dialog service
     * to destroy the window: ON_REMOTE_STATE_CHANGED. When remoteObject is
     * null, use the service proxy saved at connect time (if no longer held,
     * send nothing). */
    void ReleaseWindow(const sptr<IRemoteObject> &remoteObject);

    /* Privacy (spec R10): the parameters JSON may contain customData base64; scrub before session end. */
    void ScrubParams();

    /* parameters JSON sent down to the driver dialog (including timeout); tests use it to verify content */
    const std::string &GetParamsJson() const { return paramsJson_; }

private:
    std::string requestId_;
    std::string bundle_;
    std::string ability_;
    std::string paramsJson_;
    sptr<IRemoteObject> dialogRemoteObject_;
    bool released_ = false; /* ignore late connection callbacks after session end (R8) */
    std::mutex mutex_;
};

/* Production launcher: connects fixedly to com.ohos.systemui / com.ohos.systemui.dialog. */
class RealSystemDialogLauncher : public SystemDialogLauncher {
public:
    int32_t Connect(const sptr<IAbilityConnection> &conn) override;
    void Disconnect(const sptr<IAbilityConnection> &conn) override;
};
} // namespace OHOS::Security::CertManager
#endif // CM_SYSTEM_DIALOG_CONNECTION_H
