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

#include "cm_system_dialog_connection.h"

#include <algorithm>

#include "ability_connect_callback_interface.h"
#include "errors.h"
#include "extension_manager_client.h"
#include "ipc_skeleton.h"
#include "string_ex.h"
#include "want.h"

#include "cm_log.h"

namespace OHOS::Security::CertManager {
namespace {
/* START_DIALOG 报文 key-value 组数，对齐 useriam SIGNAL_NUM */
constexpr int32_t START_DIALOG_SIGNAL_NUM = 3;
constexpr const char *SYSTEM_DIALOG_BUNDLE = "com.ohos.systemui";
constexpr const char *SYSTEM_DIALOG_ABILITY = "com.ohos.systemui.dialog";
}

CmSystemDialogConnection::CmSystemDialogConnection(const std::string &requestId,
    const std::string &bundle, const std::string &ability, const std::string &paramsJson)
    : requestId_(requestId), bundle_(bundle), ability_(ability), paramsJson_(paramsJson)
{
}

void CmSystemDialogConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    if (remoteObject == nullptr) {
        CM_LOG_E("dialog service remote object is null, request id: %s", requestId_.c_str());
        CmUkeyAuthDialogManager::GetInstance().OnDialogDisconnected(requestId_);
        return;
    }

    /* 与 ScrubParams 互斥地快照参数与代理：收尾擦除后不再补发启动命令 */
    std::string paramsSnapshot;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (released_) { return; } /* ReleaseWindow 之后不再补发启动命令 */
        paramsSnapshot = paramsJson_;
        dialogRemoteObject_ = remoteObject;
    }

    /* 报文格式逐字段对齐 useriam ui_extension_ability_connection.cpp:47-57 */
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    option.SetFlags(MessageOption::TF_ASYNC);
    data.WriteInt32(START_DIALOG_SIGNAL_NUM);
    data.WriteString16(u"bundleName");
    data.WriteString16(Str8ToStr16(bundle_));
    data.WriteString16(u"abilityName");
    data.WriteString16(Str8ToStr16(ability_));
    data.WriteString16(u"parameters");
    data.WriteString16(Str8ToStr16(paramsSnapshot));
    int32_t err = remoteObject->SendRequest(IAbilityConnection::ON_ABILITY_CONNECT_DONE, data, reply, option);
    if (err != 0) {
        CM_LOG_E("start dialog cmd failed %{public}d", err);
        CmUkeyAuthDialogManager::GetInstance().OnDialogDisconnected(requestId_);
        return;
    }
    CM_LOG_I("start dialog cmd sent, request id: %s", requestId_.c_str());
}

void CmSystemDialogConnection::ScrubParams()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::fill(paramsJson_.begin(), paramsJson_.end(), '\0');
    paramsJson_.clear();
}

void CmSystemDialogConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
    int32_t resultCode)
{
    CM_LOG_I("dialog service disconnected, request id: %s", requestId_.c_str());
    CmUkeyAuthDialogManager::GetInstance().OnDialogDisconnected(requestId_);
}

void CmSystemDialogConnection::ReleaseWindow(const sptr<IRemoteObject> &remoteObject)
{
    sptr<IRemoteObject> target = remoteObject;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        released_ = true;
        if (target == nullptr) {
            target = dialogRemoteObject_;
        }
        dialogRemoteObject_ = nullptr;
    }
    if (target == nullptr) {
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    option.SetFlags(MessageOption::TF_ASYNC);
    int32_t err = target->SendRequest(IAbilityConnection::ON_REMOTE_STATE_CHANGED, data, reply, option);
    CM_LOG_I("release dialog window result %{public}d", err);
}

int32_t RealSystemDialogLauncher::Connect(const sptr<IAbilityConnection> &conn)
{
    if (conn == nullptr || conn->AsObject() == nullptr) {
        CM_LOG_E("dialog connection object is null");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    AAFwk::Want want;
    want.SetElementName(SYSTEM_DIALOG_BUNDLE, SYSTEM_DIALOG_ABILITY);
    /* 以 SA 身份发起连接（对齐 useriam widget_context.cpp:552-558） */
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    auto ret = AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(
        want, conn->AsObject(), nullptr, -1);
    IPCSkeleton::SetCallingIdentity(identity);
    if (ret != ERR_OK) {
        CM_LOG_E("connect system dialog service failed, ret: %d", ret);
    }
    return ret;
}

void RealSystemDialogLauncher::Disconnect(const sptr<IAbilityConnection> &conn)
{
    if (conn == nullptr || conn->AsObject() == nullptr) {
        return;
    }
    auto ret = AAFwk::ExtensionManagerClient::GetInstance().DisconnectAbility(conn->AsObject());
    if (ret != ERR_OK) {
        /* 已断连（服务死亡/从未连接成功）等错误安全，可忽略 */
        CM_LOG_W("disconnect system dialog service ret: %d", ret);
    }
}
} // namespace OHOS::Security::CertManager
