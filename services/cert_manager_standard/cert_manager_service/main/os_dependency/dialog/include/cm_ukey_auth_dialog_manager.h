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

class CmSystemDialogConnection; // real connection object for production assembly (T3)

/* Auth timeout (spec D5 v2: openUkeyAuthDialog optional timeoutDuration
 * input, unit seconds): not passed (0) takes the default 300s; explicit
 * values are clamped server-side to [3min, 10min] */
constexpr uint32_t CM_UKEY_DIALOG_MIN_TOTAL_TIMEOUT_SEC = 180;     // 3 min
constexpr uint32_t CM_UKEY_DIALOG_DEFAULT_TOTAL_TIMEOUT_SEC = 300; // 5 min
constexpr uint32_t CM_UKEY_DIALOG_MAX_TOTAL_TIMEOUT_SEC = 600;     // 10 min
constexpr uint32_t CM_UKEY_DIALOG_GRACE_TIMEOUT_MS = 10000;  // 10s, spec D5
/* Session keep-alive period (spec §9.4): must be smaller than the SA
 * idle-unload delay of 60s (cm_sa.cpp DELAY_TIME); no IPC arrives while the
 * session is up, so the periodic renewal hook resets the idle-unload timer. */
constexpr uint32_t CM_UKEY_DIALOG_KEEPALIVE_INTERVAL_MS = 30000;

class SystemDialogLauncher {           // T3 provides the real implementation, T2 unit tests inject a fake
public:
    virtual ~SystemDialogLauncher() = default;
    virtual int32_t Connect(const sptr<IAbilityConnection> &conn) = 0;
    virtual void Disconnect(const sptr<IAbilityConnection> &conn) = 0;
};

// Ability query injection point (in production InitRealDependencies assembles
// it into the HksQueryAbilityInfo adapter: returns the bundle/ability names
// and abilityType; a query failure counts as "not registered" and is
// rejected synchronously (spec v4 §4.1/D22; during integration a stub can
// return a fixed value)
using AbilityQuerier = std::function<int32_t(const struct CmBlob *keyUri,
    std::string &bundleName, std::string &abilityName, uint32_t &abilityType)>;

// PC gate injection point (spec D15: consumed only by the UIExtension path;
// production assembly is the two-level check CmUkeyIsPcPlatformOrPcMode -
// PC platform builds (CM_TARGET_PLATFORM_PC macro, propagated via the
// frameworks/common public config) pass at compile time, non-PC builds read
// the PC mode parameter (persist.sceneboard.ispcmode); devicetype is not
// read (neverallow governance); tests can inject a custom checker)
using PcChecker = std::function<bool()>;

// Driver dialog extension BMS precheck injection point (spec v4 D23:
// consumed by the ForDriver path; production assembly queries BundleMgr that
// (bundleName, abilityName) exists and is a UKEY_AUTH-type extension; userId
// is resolved by the IPC layer via CmGetProcessInfoForIPC and passed in; the
// dialog static library must not depend on the idl layer)
using DriverAbilityChecker = std::function<bool(const std::string &bundleName,
    const std::string &abilityName, int32_t userId)>;

    /* SA entry parameter set of openAuthDialogForUkeyProvider (spec v4
     * §4.1/D23): split out of the original 9-arg signature to cap the
     * argument count; callerBundleName is resolved by the IPC layer from the
     * IPC token (not forgeable by the client); customData.size == 0 means
     * absent (not carried) */
    struct UkeyDriverDialogRequest {
        struct CmBlob abilityName;   /* driver dialog extension name blob (may carry a trailing NUL) */
        uint32_t abilityType = 0;    /* CM_UKEY_ABILITY_TYPE_UIEXTENSION only */
        struct CmBlob keyUri;        /* ukey credential uri */
        uint32_t callerUid = 0;      /* original client uid (used as dialog param appUid) */
        std::string callerBundleName; /* bundle of the reporting responsible party (IPC token source) */
        int32_t userId = 0;          /* for the BMS query (resolved by CmGetProcessInfoForIPC) */
        uint32_t timeoutSec = 0;     /* seconds, 0 = server default, clamped server-side */
        struct CmBlob customData;    /* optional caller-opaque data (size 0 = absent) */
        sptr<IRemoteObject> clientCallback; /* client callback stub */
    };

    /* Common launch params of the UIExtension dialog session (passed into
     * LaunchUiExtensionSessionLocked after OpenDialog/OpenDriverDialog
     * converge): target bundle/ability fixed and the PC gate already passed;
     * timeoutSec normalized; customData.size == 0 means absent */
    struct UkeyDialogLaunchParams {
        std::string bundleName;      /* target extension bundle */
        std::string abilityName;     /* target UIExtension ability name (NUL stripped) */
        struct CmBlob keyUri;        /* ukey credential uri */
        uint32_t callerUid = 0;      /* original client uid (used as dialog param appUid) */
        uint32_t timeoutSec = 0;     /* normalized session timeout (seconds) */
        struct CmBlob customData;    /* optional caller-opaque data (size 0 = absent) */
        sptr<IRemoteObject> clientCallback; /* client callback stub */
    };

class CmUkeyAuthDialogManager {
public:
    static CmUkeyAuthDialogManager &GetInstance();

    void SetLauncher(std::shared_ptr<SystemDialogLauncher> launcher);
    void SetAbilityQuerier(AbilityQuerier querier);
    void SetPcChecker(PcChecker checker);
    void SetDriverAbilityChecker(DriverAbilityChecker checker);
    void SetTimeoutRangeForTest(uint32_t minSec, uint32_t defaultSec, uint32_t maxSec, uint32_t graceMs);
    /* SA idle-unload renewal hook (F1): called by the periodic keep-alive
     * task while a session is active; the SA side (cm_sa.cpp Init) injects
     * DelayUnload; the dialog static library must not depend on cm_sa.h. */
    void SetUnloadRenewal(std::function<void()> renewal);
    void SetKeepAliveIntervalForTest(uint32_t intervalMs);
    /* PostTask fault injection (F8 tests): affects only the post result of
     * StartTimerLocked; does not abort an active session (must be toggleable
     * around a live session). */
    void SetTimerPostFailForTest(bool fail);
    /* Production assembly entry (idempotent lazy init):
     * RealSystemDialogLauncher + HUKS ability query adapter; triggered on the
     * first call from SA OnStart / a handler (T4). */
    void InitRealDependencies();
    // Returns the validation code synchronously (CM_SUCCESS / -1017 / -1018 /
    // -1019 not registered / -1020 / CMR_DIALOG_ERROR_*); customData is
    // consumed only during the synchronous launch (written into dialog
    // params) and is not kept with the session
    int32_t OpenDialog(const struct CmBlob *keyUri, uint32_t callerUid, uint32_t timeoutSec,
        const struct CmBlob *customData, const sptr<IRemoteObject> &clientCallback);
    /* SA entry of openAuthDialogForUkeyProvider (spec v4 §4.1/D23): params in
     * UkeyDriverDialogRequest; abilityType accepts only
     * CM_UKEY_ABILITY_TYPE_UIEXTENSION; BMS validation goes through
     * driverAbilityChecker_. Return contract is the same as OpenDialog. */
    int32_t OpenDriverDialog(const UkeyDriverDialogRequest &req);
    // Returns CM_SUCCESS (accepted) or CMR_DIALOG_ERROR_INTERNAL (session not
    // found / identity mismatch / terminal state)
    int32_t OnReport(const std::string &requestId, const std::string &callerBundleName,
        int32_t resultCode);
    void OnDialogDisconnected(const std::string &requestId);
    /* Client death callback (F2): invoked by the DeathRecipient registered
     * with the session; when an active session matches, abort it directly
     * (no result reported back to the dead client); unknown/stale requestId
     * is a no-op. */
    void OnClientDied(const std::string &requestId);

    std::string GetRequestIdForTest();

private:
    CmUkeyAuthDialogManager() = default;
    ~CmUkeyAuthDialogManager() = default;
    DISALLOW_COPY_AND_MOVE(CmUkeyAuthDialogManager);

    struct UkeyAuthSession {
        enum State { LAUNCHING, WAITING_REPORT, GRACE_WAITING, DONE };
        std::string requestId;                 // 32-char hex (16 CSPRNG bytes)
        std::string ownerBundleName;           // bundle of the reporting responsible party: driver bundle (spec §9.2)
        uint32_t callerUid = 0;                // original client uid (used as dialog param appUid)
        sptr<IRemoteObject> clientCallback;    // client callback stub
        sptr<IRemoteObject::DeathRecipient> clientDeathRecipient; // client death watch (F2)
        sptr<CmSystemDialogConnection> connection; // system dialog service connection (null for UIAbility sessions)
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
    /* Extracted from the common OpenDialog/OpenDriverDialog launch sequence
     * (target bundle/ability fixed, PC gate passed): requestId -> session ->
     * connection -> total timeout. Returns the sync code. */
    int32_t LaunchUiExtensionSessionLocked(const UkeyDialogLaunchParams &params);
    /* Assemble dialog params and establish the system dialog connection
     * (split out of LaunchUiExtensionSessionLocked); returns nullptr on
     * failure with the specific error code in ret */
    sptr<CmSystemDialogConnection> CreateDialogConnectionLocked(
        const std::shared_ptr<UkeyAuthSession> &session, const UkeyDialogLaunchParams &params,
        int32_t &ret);
    /* Post the session total-timeout timer (split out of
     * LaunchUiExtensionSessionLocked): on failure, roll back the established
     * connection and return false */
    bool ArmTotalTimeoutLocked(const std::shared_ptr<UkeyAuthSession> &session,
        const std::string &requestId, uint32_t timeoutSec);
    uint32_t NormalizeTimeoutSecLocked(uint32_t timeoutSec);
    /* OpenDriverDialog pre-lock combined argument validation (spec v4 D23/D24), to share complexity with the body */
    static int32_t ValidateDriverDialogRequest(const UkeyDriverDialogRequest &req);

    std::mutex mutex_;
    std::shared_ptr<SystemDialogLauncher> launcher_;
    AbilityQuerier querier_;
    PcChecker pcChecker_;                      // default counts as non-PC (fail-closed, spec D15)
    DriverAbilityChecker driverAbilityChecker_;  // default counts as check failure (fail-closed)
    std::function<void()> unloadRenewal_;  // SA idle-unload renewal hook (injected, F1)
    bool realDepsInited_ = false;          // idempotency flag of InitRealDependencies
    uint32_t minTimeoutSec_ = CM_UKEY_DIALOG_MIN_TOTAL_TIMEOUT_SEC;
    uint32_t defaultTimeoutSec_ = CM_UKEY_DIALOG_DEFAULT_TOTAL_TIMEOUT_SEC;
    uint32_t maxTimeoutSec_ = CM_UKEY_DIALOG_MAX_TOTAL_TIMEOUT_SEC;
    uint32_t graceTimeoutMs_ = CM_UKEY_DIALOG_GRACE_TIMEOUT_MS;
    uint32_t keepAliveIntervalMs_ = CM_UKEY_DIALOG_KEEPALIVE_INTERVAL_MS;
    bool timerPostFailForTest_ = false;    // PostTask fault injection (F8 tests)
    std::shared_ptr<AppExecFwk::EventHandler> timerHandler_; // dedicated "cm_ukey_dialog" thread
    std::shared_ptr<UkeyAuthSession> session_;
};
} // namespace OHOS::Security::CertManager
#endif // CM_UKEY_AUTH_DIALOG_MANAGER_H
