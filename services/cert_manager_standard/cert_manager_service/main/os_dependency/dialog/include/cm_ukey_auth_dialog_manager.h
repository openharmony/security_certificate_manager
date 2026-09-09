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

#ifndef CM_UKEY_AUTH_DIALOG_MANAGER_H
#define CM_UKEY_AUTH_DIALOG_MANAGER_H

#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include "ability_connect_callback_interface.h"
#include "event_handler.h"
#include "iremote_object.h"
#include "iremote_stub.h"
#include "nocopyable.h"

#include "cm_type.h"

namespace OHOS::Security::CertManager {
using OHOS::AAFwk::IAbilityConnection;

constexpr uint32_t CM_UKEY_DIALOG_TOTAL_TIMEOUT_MS = 300000; // 5min, spec D5
constexpr uint32_t CM_UKEY_DIALOG_GRACE_TIMEOUT_MS = 10000;  // 10s, spec D5

// 结果回调分发命令码（SA->client 回调 stub 的 SendRequest code）
constexpr uint32_t CM_UKEY_DIALOG_CALLBACK_CMD = 1;

class SystemDialogLauncher {           // T3 提供真实实现，T2 单测注入 fake
public:
    virtual ~SystemDialogLauncher() = default;
    virtual int32_t Connect(const sptr<IAbilityConnection> &conn) = 0;
    virtual void Disconnect(const sptr<IAbilityConnection> &conn) = 0;
};

// ability 查询注入点（生产环境由 T4 装配为 HksQueryAbilityInfo 适配函数：
// 仅返回 bundle/ability 名，查询失败即视为"未注册自定义弹框"——类型不经 HUKS，D3）
using AbilityQuerier = std::function<int32_t(const struct CmBlob *keyUri,
    std::string &bundleName, std::string &abilityName)>;

class CmUkeyAuthDialogManager {
public:
    static CmUkeyAuthDialogManager &GetInstance();

    void SetLauncher(std::shared_ptr<SystemDialogLauncher> launcher);
    void SetAbilityQuerier(AbilityQuerier querier);
    void SetTimeoutForTest(uint32_t totalMs, uint32_t graceMs);
    // 同步返回校验码（CM_SUCCESS / -1016 / -1017 / -1018 / CMR_DIALOG_ERROR_INTERNAL）
    int32_t OpenDialog(const struct CmBlob *keyUri, uint32_t callerUid,
        const sptr<IRemoteObject> &clientCallback);
    // 返回 CM_SUCCESS（已接受）或 CMR_DIALOG_ERROR_INTERNAL（会话不存在/身份不符/终态）
    int32_t OnReport(const std::string &requestId, const std::string &callerBundleName,
        int32_t resultCode);
    void OnDialogDisconnected(const std::string &requestId);

    std::string GetRequestIdForTest();

private:
    CmUkeyAuthDialogManager() = default;
    ~CmUkeyAuthDialogManager() = default;
    DISALLOW_COPY_AND_MOVE(CmUkeyAuthDialogManager);

    struct UkeyAuthSession {
        enum State { LAUNCHING, WAITING_REPORT, GRACE_WAITING, DONE };
        std::string requestId;                 // 32 字符 hex（/dev/urandom 16 字节）
        std::string driverBundleName;          // 来自 HksQueryAbilityInfo，上报身份校验用
        uint32_t callerUid = 0;                // 原客户端 uid（弹框参数 appUid 用）
        sptr<IRemoteObject> clientCallback;    // 客户端回调 stub
        State state = LAUNCHING;
    };

    void AbortActiveSessionLocked();
    bool EnsureTimerHandlerLocked();
    void StartTimerLocked(const std::string &taskName, uint32_t delayMs,
        const std::function<void()> &callback);
    void FinishSessionLocked(const std::string &requestId, int32_t resultCode);
    void HandleTotalTimeout(const std::string &requestId);
    void HandleGraceTimeout(const std::string &requestId);

    std::mutex mutex_;
    std::shared_ptr<SystemDialogLauncher> launcher_;
    AbilityQuerier querier_;
    uint32_t totalTimeoutMs_ = CM_UKEY_DIALOG_TOTAL_TIMEOUT_MS;
    uint32_t graceTimeoutMs_ = CM_UKEY_DIALOG_GRACE_TIMEOUT_MS;
    std::shared_ptr<AppExecFwk::EventHandler> timerHandler_; // "cm_ukey_dialog" 专用线程
    std::shared_ptr<UkeyAuthSession> session_;
};
} // namespace OHOS::Security::CertManager
#endif // CM_UKEY_AUTH_DIALOG_MANAGER_H
