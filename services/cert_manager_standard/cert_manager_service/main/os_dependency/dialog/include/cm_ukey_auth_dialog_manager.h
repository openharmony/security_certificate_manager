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
#include "want.h"

#include "cm_type.h"
#include "cm_ukey_ability_type.h"
#include "cm_ukey_dialog_common.h"
#include "cert_manager_service_ipc_interface_code.h" // CM_UKEY_DIALOG_CALLBACK_CMD

namespace OHOS::Security::CertManager {
using OHOS::AAFwk::IAbilityConnection;

class CmSystemDialogConnection; // 生产装配的真实连接对象（T3）

/* 认证超时上限（spec D5 修订：openUkeyAuthDialog 可选 timeout 入参，不传默认取
 * 该最大值；超过该值的服务端 clamp 到最大值） */
constexpr uint32_t CM_UKEY_DIALOG_MAX_TOTAL_TIMEOUT_MS = 600000; // 10 min
constexpr uint32_t CM_UKEY_DIALOG_GRACE_TIMEOUT_MS = 10000;  // 10s, spec D5
/* 会话保活周期（spec §9.4）：须小于 SA 空闲卸载延时 60s（cm_sa.cpp DELAY_TIME），
 * 会话期间无 IPC 进来，靠周期续期钩子重置空闲卸载计时。 */
constexpr uint32_t CM_UKEY_DIALOG_KEEPALIVE_INTERVAL_MS = 30000;

class SystemDialogLauncher {           // T3 提供真实实现，T2 单测注入 fake
public:
    virtual ~SystemDialogLauncher() = default;
    virtual int32_t Connect(const sptr<IAbilityConnection> &conn) = 0;
    virtual void Disconnect(const sptr<IAbilityConnection> &conn) = 0;
};

// ability 查询注入点（生产环境由 InitRealDependencies 装配为 HksQueryAbilityInfo
// 适配函数：返回 bundle/ability 名与 abilityType；查询失败即视为"未注册自定义弹框"，
// 路由进系统默认弹框（spec §4.1，联调期可经桩固定返回）
using AbilityQuerier = std::function<int32_t(const struct CmBlob *keyUri,
    std::string &bundleName, std::string &abilityName, uint32_t &abilityType)>;

// PC / PC 模式判定注入点（spec D15：仅 UIExtension 路径消费；生产装配读
// const.product.devicetype=="2in1" 或 persist.sceneboard.ispcmode）
using PcChecker = std::function<bool()>;

// UIAbility 拉起注入点（spec §9.2：无 context 的 UIAbility 驱动弹框经
// AbilityManagerClient::StartAbility(want) 拉起；生产装配见 InitRealDependencies）
using AbilityStarter = std::function<int32_t(const AAFwk::Want &)>;

class CmUkeyAuthDialogManager {
public:
    static CmUkeyAuthDialogManager &GetInstance();

    void SetLauncher(std::shared_ptr<SystemDialogLauncher> launcher);
    void SetAbilityQuerier(AbilityQuerier querier);
    void SetPcChecker(PcChecker checker);
    void SetAbilityStarter(AbilityStarter starter);
    void SetTimeoutForTest(uint32_t totalMs, uint32_t graceMs);
    /* SA 空闲卸载续期钩子（F1）：会话活跃期间由周期保活任务调用；由 SA 侧
     * （cm_sa.cpp Init）注入 DelayUnload，弹框静态库不得依赖 cm_sa.h。 */
    void SetUnloadRenewal(std::function<void()> renewal);
    void SetKeepAliveIntervalForTest(uint32_t intervalMs);
    /* PostTask 故障注入（F8 测试）：仅影响 StartTimerLocked 的投递结果，
     * 不中止活跃会话（需在存活会话前后切换）。 */
    void SetTimerPostFailForTest(bool fail);
    /* 生产装配入口（幂等懒初始化）：RealSystemDialogLauncher + HUKS ability
     * 查询适配；由 SA OnStart/处理器首次调用时触发（T4）。 */
    void InitRealDependencies();
    // 同步返回校验码（CM_SUCCESS / -1017 / -1018 / -1019 / -1020 / CMR_DIALOG_ERROR_*）；
    // customData 仅在同步拉起期间消费（写入弹框参数），不随会话保留
    int32_t OpenDialog(const struct CmBlob *keyUri, uint32_t callerUid, uint32_t timeoutMs,
        uint32_t scene, const struct CmBlob *customData, const sptr<IRemoteObject> &clientCallback);
    // 返回 CM_SUCCESS（已接受）或 CMR_DIALOG_ERROR_INTERNAL（会话不存在/身份不符/终态）
    int32_t OnReport(const std::string &requestId, const std::string &callerBundleName,
        int32_t resultCode);
    void OnDialogDisconnected(const std::string &requestId);
    /* 客户端死亡回调（F2）：由会话注册的 DeathRecipient 调用；活跃会话匹配时
     * 直接中止（不向已死客户端回投结果），未知/过期 requestId 为 no-op。 */
    void OnClientDied(const std::string &requestId);

    std::string GetRequestIdForTest();

private:
    CmUkeyAuthDialogManager() = default;
    ~CmUkeyAuthDialogManager() = default;
    DISALLOW_COPY_AND_MOVE(CmUkeyAuthDialogManager);

    struct UkeyAuthSession {
        enum DialogKind { DEFAULT_DIALOG, UIABILITY_DIALOG, UIEXTENSION_DIALOG };
        enum State { LAUNCHING, WAITING_REPORT, GRACE_WAITING, DONE };
        std::string requestId;                 // 32 字符 hex（CSPRNG 16 字节）
        DialogKind kind = DEFAULT_DIALOG;      // 拉起策略（spec §4.1 路由矩阵）
        uint32_t scene = CM_UKEY_AUTH_SCENE_LOGIN; // 透传给弹框的场景
        std::string ownerBundleName;           // 上报责任方 bundle：驱动 bundle 或默认弹框
                                              // 所属 com.ohos.certmanager（spec §9.2）
        uint32_t callerUid = 0;                // 原客户端 uid（弹框参数 appUid 用）
        sptr<IRemoteObject> clientCallback;    // 客户端回调 stub
        sptr<IRemoteObject::DeathRecipient> clientDeathRecipient; // 客户端死亡监听（F2）
        sptr<CmSystemDialogConnection> connection; // 系统弹窗服务连接（UIAbility 会话为空）
        State state = LAUNCHING;
    };

    void AbortActiveSessionLocked();
    bool EnsureTimerHandlerLocked();
    bool StartTimerLocked(const std::string &taskName, uint32_t delayMs,
        const std::function<void()> &callback);
    void RegisterClientDeathRecipientLocked(const std::shared_ptr<UkeyAuthSession> &session);
    void RemoveClientDeathRecipientLocked(const std::shared_ptr<UkeyAuthSession> &session);
    void StartKeepAliveLocked(const std::string &requestId);
    void HandleKeepAlive(const std::string &requestId);
    void FinishSessionLocked(const std::string &requestId, int32_t resultCode);
    void HandleTotalTimeout(const std::string &requestId);
    void HandleGraceTimeout(const std::string &requestId);

    std::mutex mutex_;
    std::shared_ptr<SystemDialogLauncher> launcher_;
    AbilityQuerier querier_;
    PcChecker pcChecker_;                      // 缺省视为非 PC（fail-closed，spec D15）
    AbilityStarter abilityStarter_;            // UIAbility 拉起（生产装配见 InitRealDependencies）
    std::function<void()> unloadRenewal_;  // SA 空闲卸载续期钩子（注入，F1）
    bool realDepsInited_ = false;          // InitRealDependencies 幂等标记
    uint32_t totalTimeoutMs_ = CM_UKEY_DIALOG_MAX_TOTAL_TIMEOUT_MS;
    uint32_t graceTimeoutMs_ = CM_UKEY_DIALOG_GRACE_TIMEOUT_MS;
    uint32_t keepAliveIntervalMs_ = CM_UKEY_DIALOG_KEEPALIVE_INTERVAL_MS;
    bool timerPostFailForTest_ = false;    // PostTask 故障注入（F8 测试）
    std::shared_ptr<AppExecFwk::EventHandler> timerHandler_; // "cm_ukey_dialog" 专用线程
    std::shared_ptr<UkeyAuthSession> session_;
};
} // namespace OHOS::Security::CertManager
#endif // CM_UKEY_AUTH_DIALOG_MANAGER_H
