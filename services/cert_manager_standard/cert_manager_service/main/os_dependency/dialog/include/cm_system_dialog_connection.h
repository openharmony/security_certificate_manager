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

/* 系统弹窗服务连接对象：连接成功后按 useriam 报文格式（bundleName/abilityName/
 * parameters 三组 key-value）向服务 stub 发送 START_DIALOG 命令；断连时通知
 * manager 进入宽限期。 */
class CmSystemDialogConnection : public AAFwk::AbilityConnectionStub {
public:
    CmSystemDialogConnection(const std::string &requestId, const std::string &bundle,
        const std::string &ability, const std::string &paramsJson);
    ~CmSystemDialogConnection() override = default;

    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int32_t resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
        int32_t resultCode) override;
    /* 会话收尾（总超时/正常结束）时通知弹窗服务销毁窗口：ON_REMOTE_STATE_CHANGED。
     * remoteObject 为空时使用连接成功时保存的服务代理（不再持有则不发）。 */
    void ReleaseWindow(const sptr<IRemoteObject> &remoteObject);

private:
    std::string requestId_;
    std::string bundle_;
    std::string ability_;
    std::string paramsJson_;
    sptr<IRemoteObject> dialogRemoteObject_;
    bool released_ = false; /* 会话收尾后忽略迟到的连接回调（R8） */
    std::mutex mutex_;
};

/* 生产装配的 launcher：固定连接 com.ohos.systemui / com.ohos.systemui.dialog。 */
class RealSystemDialogLauncher : public SystemDialogLauncher {
public:
    int32_t Connect(const sptr<IAbilityConnection> &conn) override;
    void Disconnect(const sptr<IAbilityConnection> &conn) override;
};
} // namespace OHOS::Security::CertManager
#endif // CM_SYSTEM_DIALOG_CONNECTION_H
