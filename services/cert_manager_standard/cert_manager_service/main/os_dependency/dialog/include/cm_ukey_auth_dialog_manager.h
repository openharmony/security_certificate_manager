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

/* 认证超时（spec D5 v2：openUkeyAuthDialog 可选 timeoutDuration 入参，单位秒）：
 * 未传（0）取默认 300s；显式值由服务端 clamp 到 [3min, 10min] 区间 */
constexpr uint32_t CM_UKEY_DIALOG_MIN_TOTAL_TIMEOUT_SEC = 180;     // 3 min
constexpr uint32_t CM_UKEY_DIALOG_DEFAULT_TOTAL_TIMEOUT_SEC = 300; // 5 min
constexpr uint32_t CM_UKEY_DIALOG_MAX_TOTAL_TIMEOUT_SEC = 600;     // 10 min
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
// 适配函数：返回 bundle/ability 名与 abilityType；查询失败即视为"未注册"，
// 同步拒绝（spec v4 §4.1/D22，联调期可经桩固定返回）
using AbilityQuerier = std::function<int32_t(const struct CmBlob *keyUri,
    std::string &bundleName, std::string &abilityName, uint32_t &abilityType)>;

// PC 门禁注入点（spec D15：仅 UIExtension 路径消费；生产装配为两级判定
// CmUkeyIsPcPlatformOrPcMode——PC 平台构建（CM_TARGET_PLATFORM_PC 宏，经
// frameworks/common public config 传播）编译期放行，非 PC 平台构建读 PC 模式
// 参数（persist.sceneboard.ispcmode）判定，不读 devicetype（neverallow 管控）；
// 测试可注入自定义 checker）
using PcChecker = std::function<bool()>;

// 驱动弹框扩展 BMS 预校验注入点（spec v4 D23：ForDriver 路径消费；生产装配经
// BundleMgr 查询 (bundleName, abilityName) 存在且为 UKEY_AUTH 类型扩展；userId 由
// IPC 层经 CmGetProcessInfoForIPC 解出传入，弹框静态库不得依赖 idl 层）
using DriverAbilityChecker = std::function<bool(const std::string &bundleName,
    const std::string &abilityName, int32_t userId)>;

    /* openAuthDialogForUkeyProvider 的 SA 入口参数集（spec v4 §4.1/D23）：拆自原
     * 9 参签名以控制入参数量；callerBundleName 由 IPC 层从 IPC token 解出（客户端
     * 不可伪造）；customData.size == 0 表示缺省（不携带） */
    struct UkeyDriverDialogRequest {
        struct CmBlob abilityName;   /* 驱动弹框扩展名 blob（可能带结尾 NUL） */
        uint32_t abilityType = 0;    /* 仅 CM_UKEY_ABILITY_TYPE_UIEXTENSION */
        struct CmBlob keyUri;        /* ukey 凭据 uri */
        uint32_t callerUid = 0;      /* 原客户端 uid（弹框参数 appUid 用） */
        std::string callerBundleName; /* 上报责任方 bundle（IPC token 来源） */
        int32_t userId = 0;          /* BMS 查询用（CmGetProcessInfoForIPC 解出） */
        uint32_t timeoutSec = 0;     /* 秒，0 = 服务端默认，服务端 clamp */
        struct CmBlob customData;    /* 可选调用方不透明数据（size 0 = 缺省） */
        sptr<IRemoteObject> clientCallback; /* 客户端回调 stub */
    };

    /* UIExtension 弹窗会话公共拉起参数（OpenDialog/OpenDriverDialog 汇聚后传入
     * LaunchUiExtensionSessionLocked）：目标 bundle/ability 已定、PC 门禁已过；
     * timeoutSec 已归一化；customData.size == 0 表示缺省 */
    struct UkeyDialogLaunchParams {
        std::string bundleName;      /* 目标扩展 bundle */
        std::string abilityName;     /* 目标 UIExtension ability 名（已剥 NUL） */
        struct CmBlob keyUri;        /* ukey 凭据 uri */
        uint32_t callerUid = 0;      /* 原客户端 uid（弹框参数 appUid 用） */
        uint32_t timeoutSec = 0;     /* 已归一化的会话超时（秒） */
        struct CmBlob customData;    /* 可选调用方不透明数据（size 0 = 缺省） */
        sptr<IRemoteObject> clientCallback; /* 客户端回调 stub */
    };

class CmUkeyAuthDialogManager {
public:
    static CmUkeyAuthDialogManager &GetInstance();

    void SetLauncher(std::shared_ptr<SystemDialogLauncher> launcher);
    void SetAbilityQuerier(AbilityQuerier querier);
    void SetPcChecker(PcChecker checker);
    void SetDriverAbilityChecker(DriverAbilityChecker checker);
    void SetTimeoutRangeForTest(uint32_t minSec, uint32_t defaultSec, uint32_t maxSec, uint32_t graceMs);
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
    // 同步返回校验码（CM_SUCCESS / -1017 / -1018 / -1019 未注册 / -1020 /
    // CMR_DIALOG_ERROR_*）；customData 仅在同步拉起期间消费（写入弹框参数），
    // 不随会话保留
    int32_t OpenDialog(const struct CmBlob *keyUri, uint32_t callerUid, uint32_t timeoutSec,
        const struct CmBlob *customData, const sptr<IRemoteObject> &clientCallback);
    /* openAuthDialogForUkeyProvider 的 SA 入口（spec v4 §4.1/D23）：参数见
     * UkeyDriverDialogRequest；abilityType 仅接受 CM_UKEY_ABILITY_TYPE_UIEXTENSION，
     * BMS 校验经 driverAbilityChecker_。返回值契约同 OpenDialog。 */
    int32_t OpenDriverDialog(const UkeyDriverDialogRequest &req);
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
        enum State { LAUNCHING, WAITING_REPORT, GRACE_WAITING, DONE };
        std::string requestId;                 // 32 字符 hex（CSPRNG 16 字节）
        std::string ownerBundleName;           // 上报责任方 bundle：驱动 bundle（spec §9.2）
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
    /* 从 OpenDialog/OpenDriverDialog 公共拉起序列抽出（目标 bundle/ability 已定，
     * PC 门禁已过）：requestId→会话→连接→总超时。返回同步码。 */
    int32_t LaunchUiExtensionSessionLocked(const UkeyDialogLaunchParams &params);
    /* 组装弹框参数并建立系统弹窗连接（自 LaunchUiExtensionSessionLocked 拆出）；
     * 失败返回 nullptr 且 ret 带回具体错误码 */
    sptr<CmSystemDialogConnection> CreateDialogConnectionLocked(
        const std::shared_ptr<UkeyAuthSession> &session, const UkeyDialogLaunchParams &params,
        int32_t &ret);
    /* 投递会话总超时定时器（自 LaunchUiExtensionSessionLocked 拆出）：失败时
     * 回滚已建立的连接并返回 false */
    bool ArmTotalTimeoutLocked(const std::shared_ptr<UkeyAuthSession> &session,
        const std::string &requestId, uint32_t timeoutSec);
    uint32_t NormalizeTimeoutSecLocked(uint32_t timeoutSec);
    /* OpenDriverDialog 锁前入参组合校验（spec v4 D23/D24），供主体分摊复杂度 */
    static int32_t ValidateDriverDialogRequest(const UkeyDriverDialogRequest &req);

    std::mutex mutex_;
    std::shared_ptr<SystemDialogLauncher> launcher_;
    AbilityQuerier querier_;
    PcChecker pcChecker_;                      // 缺省视为非 PC（fail-closed，spec D15）
    DriverAbilityChecker driverAbilityChecker_;  // 缺省视为校验失败（fail-closed）
    std::function<void()> unloadRenewal_;  // SA 空闲卸载续期钩子（注入，F1）
    bool realDepsInited_ = false;          // InitRealDependencies 幂等标记
    uint32_t minTimeoutSec_ = CM_UKEY_DIALOG_MIN_TOTAL_TIMEOUT_SEC;
    uint32_t defaultTimeoutSec_ = CM_UKEY_DIALOG_DEFAULT_TOTAL_TIMEOUT_SEC;
    uint32_t maxTimeoutSec_ = CM_UKEY_DIALOG_MAX_TOTAL_TIMEOUT_SEC;
    uint32_t graceTimeoutMs_ = CM_UKEY_DIALOG_GRACE_TIMEOUT_MS;
    uint32_t keepAliveIntervalMs_ = CM_UKEY_DIALOG_KEEPALIVE_INTERVAL_MS;
    bool timerPostFailForTest_ = false;    // PostTask 故障注入（F8 测试）
    std::shared_ptr<AppExecFwk::EventHandler> timerHandler_; // "cm_ukey_dialog" 专用线程
    std::shared_ptr<UkeyAuthSession> session_;
};
} // namespace OHOS::Security::CertManager
#endif // CM_UKEY_AUTH_DIALOG_MANAGER_H
