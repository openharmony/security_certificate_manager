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

#include "cm_ukey_auth_dialog_manager.h"

#include <sys/random.h>

#include <algorithm>
#include <cstdio>
#include <ctime>

#include "bundle_mgr_interface.h"
#include "cJSON.h"
#include "extension_ability_info.h"
#include "hks_api.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "message_option.h"
#include "message_parcel.h"
#include "system_ability_definition.h"

#include "cm_log.h"
#include "cm_mem.h"
#include "cm_system_dialog_connection.h"

namespace OHOS::Security::CertManager {
namespace {
/* Result-code whitelist reported by the driver dialog (JS-layer protocol,
 * spec §9.3): 0 success / 29700001 generic failure / 29700002 user cancel /
 * 29700003 operation failure / 29700006 param validation failure; unknown
 * values fold to 29700001. */
constexpr int32_t REPORT_CODE_SUCCESS = 0;
constexpr int32_t REPORT_CODE_GENERIC_ERROR = 29700001;
constexpr int32_t REPORT_CODE_OPERATION_CANCELED = 29700002;
constexpr int32_t REPORT_CODE_INSTALL_FAILED = 29700003;
constexpr int32_t REPORT_CODE_PARAM_INVALID = 29700006;
constexpr int32_t EXTENSION_TYPE_UKEY_AUTH = 40;

/* HUKS ability query buffer length (aligned with the kits-layer cm_dialog_api_common.cpp convention) */
constexpr uint32_t HAP_INFO_MAX_LENGTH = 128;
/* sec -> ms conversion for timer posting (PostTask delays are in ms) */
constexpr uint32_t MS_PER_SECOND = 1000;
/* requestId CSPRNG random bytes; hex-encoded to a 2x-length string (spec D7) */
constexpr uint32_t REQUEST_ID_RANDOM_BYTES = 16;
/* hex encoding: one character per 4-bit nibble, 2 chars per byte */
constexpr uint32_t HEX_BITS_PER_CHAR = 4;
constexpr uint8_t HEX_NIBBLE_MASK = 0x0F;
constexpr uint32_t HEX_CHARS_PER_BYTE = 2;
/* /dev/urandom short-read retry count (masks occasional IO jitter) */
constexpr int32_t URANDOM_RETRY_COUNT = 3;
/* getrandom flags: 0 = default blocking semantics */
constexpr unsigned int GETRANDOM_FLAGS_NONE = 0;
/* BMS extension query flag: 0 = no extra filter (exact want + type match) */
constexpr int32_t BMS_QUERY_FLAG_DEFAULT = 0;
/* action value of the dialog parameters JSON (spec §6.2) */
constexpr const char *UKEY_DIALOG_ACTION = "UkeyPINAuth";
/* Launching an extension from UIExtensionComponent requires this want
 * parameter to identify the extension type (ukeyAuth = type 40 UKEY_AUTH);
 * when missing, AMS cannot recognize it as a ukeyAuth extension
 * (checkOptExtensionAbility error) and the driver ability is not launched */
constexpr const char *UKEY_DIALOG_UI_EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
constexpr const char *UKEY_DIALOG_UI_EXTENSION_TYPE = "ukeyAuth";

/* requestId is the session credential (the first line of defense in security
 * design D7) and must come from the kernel CSPRNG. If no random source is
 * available, refuse to open a session (fail-closed) - no predictable
 * downgraded seeds allowed.
 * REQUEST_ID_RANDOM_BYTES random bytes -> 2x hex chars */
bool GenerateRequestId(std::string &id)
{
    uint8_t buf[REQUEST_ID_RANDOM_BYTES] = {0};
    bool randomOk = false;
    /* Prefer the getrandom syscall (no filesystem dependency, blocks until
     * the kernel finishes entropy initialization) */
    ssize_t got = getrandom(buf, sizeof(buf), GETRANDOM_FLAGS_NONE);
    if (got == static_cast<ssize_t>(sizeof(buf))) {
        randomOk = true;
    } else {
        /* Fall back to /dev/urandom; short retries mask occasional IO jitter */
        for (int attempt = 0; attempt < URANDOM_RETRY_COUNT && !randomOk; attempt++) {
            FILE *f = fopen("/dev/urandom", "rb");
            if (f != nullptr) {
                randomOk = (fread(buf, 1, sizeof(buf), f) == sizeof(buf));
                fclose(f);
            }
        }
    }
    if (!randomOk) {
        CM_LOG_E("no usable random source for request id, refuse to open session");
        return false;
    }
    static const char hex[] = "0123456789abcdef";
    id.clear();
    id.reserve(REQUEST_ID_RANDOM_BYTES * HEX_CHARS_PER_BYTE);
    for (size_t i = 0; i < sizeof(buf); i++) {
        id += hex[buf[i] >> HEX_BITS_PER_CHAR];
        id += hex[buf[i] & HEX_NIBBLE_MASK];
    }
    return true;
}

/* Whitelist validation + unknown-code folding to generic failure (mapped to
 * internal CMR_DIALOG_ERROR_* codes sent down to the client) */
int32_t NormalizeReportCode(int32_t resultCode)
{
    switch (resultCode) {
        case REPORT_CODE_SUCCESS:
            return CM_SUCCESS;
        case REPORT_CODE_OPERATION_CANCELED:
            return CMR_DIALOG_ERROR_OPERATION_CANCELS;
        case REPORT_CODE_INSTALL_FAILED:
            return CMR_DIALOG_ERROR_INSTALL_FAILED;
        case REPORT_CODE_PARAM_INVALID:
            return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
        case REPORT_CODE_GENERIC_ERROR:
        default:
            return CMR_DIALOG_ERROR_INTERNAL;
    }
}

std::string TotalTimeoutTaskName(const std::string &requestId)
{
    return "ukey_total_timeout_" + requestId;
}

std::string GraceTimeoutTaskName(const std::string &requestId)
{
    return "ukey_grace_timeout_" + requestId;
}

std::string KeepAliveTaskName(const std::string &requestId)
{
    return "ukey_keepalive_" + requestId;
}

/* Client death watch (F2): holds the session requestId; the death
 * notification goes through a small testable manager entry */
class CmUkeyClientDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit CmUkeyClientDeathRecipient(const std::string &requestId) : requestId_(requestId) {}
    ~CmUkeyClientDeathRecipient() override = default;

    void OnRemoteDied(const wptr<IRemoteObject> &remoteObject) override
    {
        (void)remoteObject;
        CmUkeyAuthDialogManager::GetInstance().OnClientDied(requestId_);
    }

private:
    std::string requestId_;
};

/* customData base64 encoding and attachment (spec D18/R10: the base64
 * string is sensitive data derived from customData, scrubbed right after
 * use) */
bool AppendCustomDataToJson(cJSON *root, const struct CmBlob *customData)
{
    std::string customDataB64 = CmBase64Encode(customData->data, customData->size);
    cJSON *customItem = cJSON_CreateString(customDataB64.c_str());
    if (customItem == nullptr || !cJSON_AddItemToObject(root, CM_UKEY_DIALOG_PARAM_CUSTOM_DATA,
        customItem)) {
        if (customItem != nullptr) {
            cJSON_Delete(customItem);
        }
        return false;
    }
    std::fill(customDataB64.begin(), customDataB64.end(), '\0');
    return true;
}

/* Assemble the driver UIExtension dialog parameters JSON (spec v4 §6.2):
 * {"keyUri":"<uri>","appUid":<callerUid>,"requestId":"<id>","action":"UkeyPINAuth",
 *  "ability.want.params.uiExtensionType":"ukeyAuth","timeout":<seconds>,
 *  "customData":"<base64, present only when carried>"}
 * timeout is the actual session timeout (seconds) after normalization;
 * customData raw bytes are consumed only by this encoding, the base64 string
 * lives with the connection object and is scrubbed at session end (spec
 * R10). */
bool BuildUkeyDialogParams(const std::string &requestId, const UkeyDialogLaunchParams &params,
    std::string &paramsJson)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        CM_LOG_E("create params json root failed");
        return false;
    }

    std::string uriStr(reinterpret_cast<char *>(params.keyUri.data), params.keyUri.size);
    cJSON *items[] = {
        cJSON_CreateString(uriStr.c_str()),                              // keyUri
        cJSON_CreateNumber(static_cast<double>(params.callerUid)),       // appUid
        cJSON_CreateString(requestId.c_str()),                           // requestId
        cJSON_CreateString(UKEY_DIALOG_ACTION),                          // action
        cJSON_CreateString(UKEY_DIALOG_UI_EXTENSION_TYPE),              // uiExtensionType
        cJSON_CreateNumber(static_cast<double>(params.timeoutSec)),      // timeout
    };
    const char *names[] = { "keyUri", "appUid", "requestId", "action",
        UKEY_DIALOG_UI_EXTENSION_TYPE_KEY, "timeout" };
    bool ok = true;
    for (size_t i = 0; i < sizeof(items) / sizeof(items[0]); i++) {
        if (items[i] != nullptr && cJSON_AddItemToObject(root, names[i], items[i])) {
            items[i] = nullptr; // ownership transferred to root
        } else {
            ok = false;
            break;
        }
    }
    if (ok && params.customData.size > 0) {
        ok = AppendCustomDataToJson(root, &params.customData);
    }
    if (ok) {
        char *jsonStr = cJSON_PrintUnformatted(root);
        if (jsonStr != nullptr) {
            paramsJson.assign(jsonStr);
            cJSON_free(jsonStr);
        } else {
            ok = false;
        }
    }
    for (size_t i = 0; i < sizeof(items) / sizeof(items[0]); i++) {
        if (items[i] != nullptr) { // items not taken over by root are freed manually
            cJSON_Delete(items[i]);
        }
    }
    cJSON_Delete(root);
    return ok;
}

/* HUKS ability query adapter (production assembly, pattern aligned with the
 * kits-layer cm_dialog_api_common.cpp): a query failure counts as "not
 * registered" (spec v4 D22: no default-dialog fallback). */
int32_t QueryUkeyDriverAbility(const struct CmBlob *keyUri,
    std::string &bundleName, std::string &abilityName, uint32_t &abilityType)
{
    if (keyUri == nullptr || keyUri->data == nullptr || keyUri->size == 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct HksAbilityInfo abilityInfo = {};
    abilityInfo.abilityName.data = static_cast<uint8_t *>(CmMalloc(HAP_INFO_MAX_LENGTH));
    abilityInfo.bundleName.data = static_cast<uint8_t *>(CmMalloc(HAP_INFO_MAX_LENGTH));
    if (abilityInfo.abilityName.data == nullptr || abilityInfo.bundleName.data == nullptr) {
        CM_LOG_E("malloc hks ability info buffer failed");
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
        CM_LOG_E("HksQueryAbilityInfo failed, ret: %d", ret);
        CM_FREE_PTR(abilityInfo.abilityName.data);
        CM_FREE_PTR(abilityInfo.bundleName.data);
        return ret; // query failure == not registered; the caller routes into the default dialog
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

/* Driver dialog extension BMS precheck (production assembly, spec v4 D23):
 * (bundleName, abilityName) exists and is of type UKEY_AUTH
 * (ExtensionAbilityType=40). Query under the SA's own identity
 * (ResetCallingIdentity, so a leftover app token on the thread cannot affect
 * the BMS visibility decision). userId is resolved by the IPC layer via
 * CmGetProcessInfoForIPC and passed in (this static library must not depend
 * on the idl layer; deriving it from GetCallingUid is unreliable on the SA
 * entry thread). */
bool QueryDriverUkeyExtensionAbility(const std::string &bundleName,
    const std::string &abilityName, int32_t userId)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        CM_LOG_E("get system ability manager failed");
        return false;
    }
    auto remote = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remote == nullptr) {
        CM_LOG_E("get bundle mgr service failed");
        return false;
    }
    auto bundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remote);
    if (bundleMgr == nullptr) {
        CM_LOG_E("cast bundle mgr proxy failed");
        return false;
    }
    AAFwk::Want want;
    want.SetElementName(bundleName, abilityName);
    std::vector<AppExecFwk::ExtensionAbilityInfo> infos;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    int32_t type = EXTENSION_TYPE_UKEY_AUTH;
    bool ok = bundleMgr->QueryExtensionAbilityInfos(want,
        reinterpret_cast<AppExecFwk::ExtensionAbilityType>(type), 0, userId, infos);
    IPCSkeleton::SetCallingIdentity(identity);
    if (!ok) {
        CM_LOG_E("query extension ability infos failed, bundle: %s, ability: %s",
            bundleName.c_str(), abilityName.c_str());
        return false;
    }
    for (const auto &info : infos) {
        if (info.bundleName == bundleName && info.name == abilityName) {
            return true;
        }
    }
    return false;
}

/* OpenDialog pre-lock argument validation (aligned with the ForDriver
 * entry's ValidateDriverDialogRequest): blob validity and the customData
 * cap, same check order as the original inline implementation; session
 * single-flight and the ability routing stay inside the lock */
int32_t ValidateOpenDialogArguments(const struct CmBlob *keyUri,
    const struct CmBlob *customData, const sptr<IRemoteObject> &clientCallback)
{
    if (keyUri == nullptr || keyUri->data == nullptr || keyUri->size == 0 ||
        keyUri->size > MAX_LEN_URI || clientCallback == nullptr) {
        CM_LOG_E("invalid open dialog arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    /* customData re-check (already validated on the client side; defense in depth, spec D19) */
    if (customData != nullptr && customData->size > CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE) {
        CM_LOG_E("custom data too large: %u", customData->size);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    return CM_SUCCESS;
}
} // namespace

CmUkeyAuthDialogManager &CmUkeyAuthDialogManager::GetInstance()
{
    static CmUkeyAuthDialogManager instance;
    return instance;
}

void CmUkeyAuthDialogManager::SetLauncher(std::shared_ptr<SystemDialogLauncher> launcher)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AbortActiveSessionLocked();
    launcher_ = launcher;
}

void CmUkeyAuthDialogManager::SetAbilityQuerier(AbilityQuerier querier)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AbortActiveSessionLocked();
    querier_ = querier;
}

void CmUkeyAuthDialogManager::SetTimeoutRangeForTest(uint32_t minSec, uint32_t defaultSec,
    uint32_t maxSec, uint32_t graceMs)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AbortActiveSessionLocked();
    minTimeoutSec_ = minSec;
    defaultTimeoutSec_ = defaultSec;
    maxTimeoutSec_ = maxSec;
    graceTimeoutMs_ = graceMs;
}

void CmUkeyAuthDialogManager::SetUnloadRenewal(std::function<void()> renewal)
{
    /* Same reassembly semantics as SetLauncher: pending sessions bound to the old hook are aborted first */
    std::lock_guard<std::mutex> lock(mutex_);
    AbortActiveSessionLocked();
    unloadRenewal_ = std::move(renewal);
}

void CmUkeyAuthDialogManager::SetKeepAliveIntervalForTest(uint32_t intervalMs)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AbortActiveSessionLocked();
    keepAliveIntervalMs_ = intervalMs;
}

void CmUkeyAuthDialogManager::SetTimerPostFailForTest(bool fail)
{
    /* Fault-injection switch: must be toggleable around a live session, so the session is not aborted */
    std::lock_guard<std::mutex> lock(mutex_);
    timerPostFailForTest_ = fail;
}

void CmUkeyAuthDialogManager::SetPcChecker(PcChecker checker)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AbortActiveSessionLocked();
    pcChecker_ = std::move(checker);
}

void CmUkeyAuthDialogManager::SetDriverAbilityChecker(DriverAbilityChecker checker)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AbortActiveSessionLocked();
    driverAbilityChecker_ = std::move(checker);
}

uint32_t CmUkeyAuthDialogManager::NormalizeTimeoutSecLocked(uint32_t timeoutSec)
{
    /* timeoutDuration normalization (spec D5 v2, unit seconds): 0 (not
     * passed) takes the default; explicit values are clamped */
    if (timeoutSec == 0) {
        return defaultTimeoutSec_;
    }
    if (timeoutSec < minTimeoutSec_) {
        CM_LOG_W("timeout %u below min, clamp to %u", timeoutSec, minTimeoutSec_);
        return minTimeoutSec_;
    }
    if (timeoutSec > maxTimeoutSec_) {
        CM_LOG_W("timeout %u exceeds max, clamp to %u", timeoutSec, maxTimeoutSec_);
        return maxTimeoutSec_;
    }
    return timeoutSec;
}

/* Assemble dialog params and establish the system dialog connection (split
 * out of LaunchUiExtensionSessionLocked): returns nullptr on failure
 * (params already scrubbed on Connect failure; the session is not in the
 * table, so single-flight is not occupied) */
sptr<CmSystemDialogConnection> CmUkeyAuthDialogManager::CreateDialogConnectionLocked(
    const std::shared_ptr<UkeyAuthSession> &session, const UkeyDialogLaunchParams &params,
    int32_t &ret)
{
    std::string paramsJson;
    if (!BuildUkeyDialogParams(session->requestId, params, paramsJson)) {
        CM_LOG_E("build dialog params json failed");
        return nullptr;
    }
    sptr<CmSystemDialogConnection> connection = new (std::nothrow) CmSystemDialogConnection(
        session->requestId, params.bundleName, params.abilityName, paramsJson);
    if (connection == nullptr) {
        CM_LOG_E("create system dialog connection failed");
        ret = CMR_ERROR_MALLOC_FAIL;
        return nullptr;
    }
    if (launcher_->Connect(connection) != CM_SUCCESS) {
        CM_LOG_E("connect system dialog service failed");
        connection->ScrubParams();
        return nullptr;
    }
    return connection;
}

/* Post the session total-timeout timer (split out of
 * LaunchUiExtensionSessionLocked): on post failure, roll back the established
 * connection (session not in the table -> single-flight not occupied), to
 * avoid a pending session without timeout protection (F8). timeoutSec is
 * already normalized (<= max), * MS_PER_SECOND does not overflow. */
bool CmUkeyAuthDialogManager::ArmTotalTimeoutLocked(const std::shared_ptr<UkeyAuthSession> &session,
    const std::string &requestId, uint32_t timeoutSec)
{
    if (StartTimerLocked(TotalTimeoutTaskName(requestId), timeoutSec * MS_PER_SECOND, /* sec -> ms */
        [this, requestId] { HandleTotalTimeout(requestId); })) {
        return true;
    }
    sptr<CmSystemDialogConnection> connection = session->connection;
    if (connection != nullptr) {
        connection->ReleaseWindow(nullptr);
        connection->ScrubParams();
    }
    if (launcher_ != nullptr && connection != nullptr) {
        launcher_->Disconnect(connection);
    }
    return false;
}

/* Common launch sequence of OpenDialog/OpenDriverDialog (spec v4 §4.1):
 * bundle/ability already fixed and the PC gate already passed;
 * requestId -> session -> connection -> total timeout -> insert into table ->
 * death watch / keep-alive. Returns the sync code. */
int32_t CmUkeyAuthDialogManager::LaunchUiExtensionSessionLocked(const UkeyDialogLaunchParams &params)
{
    if (launcher_ == nullptr) {
        CM_LOG_E("system dialog launcher is null");
        return CMR_DIALOG_ERROR_INTERNAL;
    }

    /* The total timeout is the session's only safety net; when creating the
     * timer thread fails, reject outright to avoid a pending session without
     * timeout protection (single-flight permanently occupied). */
    if (!EnsureTimerHandlerLocked()) {
        return CMR_DIALOG_ERROR_INTERNAL;
    }

    auto session = std::make_shared<UkeyAuthSession>();
    if (!GenerateRequestId(session->requestId)) {
        /* fail-closed: requestId is the session credential; no CSPRNG, no session */
        CM_LOG_E("generate request id failed");
        return CMR_DIALOG_ERROR_INTERNAL;
    }
    session->ownerBundleName = params.bundleName; /* query result of OpenDialog / caller bundle of ForDriver */
    session->callerUid = params.callerUid;
    session->clientCallback = params.clientCallback;
    session->state = UkeyAuthSession::LAUNCHING;

    int32_t connRet = CMR_DIALOG_ERROR_INTERNAL;
    session->connection = CreateDialogConnectionLocked(session, params, connRet);
    if (session->connection == nullptr) {
        return connRet; /* params assembly / alloc / Connect failure (session
                          not in the table, single-flight not occupied) */
    }

    session->state = UkeyAuthSession::WAITING_REPORT;
    std::string requestId = session->requestId;
    /* The total timeout is the session's only safety net; on post failure,
     * roll back the connection and reject (F8, see ArmTotalTimeout) */
    if (!ArmTotalTimeoutLocked(session, requestId, params.timeoutSec)) {
        return CMR_DIALOG_ERROR_INTERNAL;
    }
    session_ = session;
    RegisterClientDeathRecipientLocked(session); // best-effort, failure only warns (F2)
    StartKeepAliveLocked(requestId);             // best-effort, failure only logs (F1)
    CM_LOG_I("open ukey auth dialog success, request id: %s", requestId.c_str());
    return CM_SUCCESS;
}

int32_t CmUkeyAuthDialogManager::OpenDialog(const struct CmBlob *keyUri, uint32_t callerUid,
    uint32_t timeoutSec, const struct CmBlob *customData,
    const sptr<IRemoteObject> &clientCallback)
{
    int32_t ret = ValidateOpenDialogArguments(keyUri, customData, clientCallback);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t effectiveTimeoutSec = NormalizeTimeoutSecLocked(timeoutSec);
    if (session_ != nullptr) {
        CM_LOG_E("another ukey auth dialog session is in progress");
        return CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS;
    }

    /* Routing (spec v4 §4.1/D22): the SA queries by itself and does not
     * trust the client-declared ability info (D20); only UIExtensionAbility
     * + PC is admitted to the SA session path; not registered / UIAbility
     * is rejected synchronously. */
    std::string bundleName;
    std::string abilityName;
    uint32_t abilityType = CM_UKEY_ABILITY_TYPE_UIABILITY;
    int32_t queryRet = (querier_ == nullptr) ? CM_FAILURE : querier_(keyUri, bundleName, abilityName, abilityType);
    if (queryRet != CM_SUCCESS) {
        CM_LOG_E("no ukey driver pin dialog registered for the key uri");
        return CMR_DIALOG_ERROR_NOT_REGISTERED;
    }
    if (abilityType == CM_UKEY_ABILITY_TYPE_UIABILITY) {
        CM_LOG_E("ukey driver ability type is UIAbility, not supported");
        return CMR_DIALOG_ERROR_UIABILITY_NOT_SUPPORTED;
    }
    if (abilityType != CM_UKEY_ABILITY_TYPE_UIEXTENSION) {
        CM_LOG_E("unknown ukey ability type: %u", abilityType);
        return CMR_DIALOG_ERROR_INTERNAL;
    }
    /* The PC gate is race defense: the kit has pre-checked; if the mode flips, fail-closed (D25 v2) */
    if (pcChecker_ == nullptr || !pcChecker_()) {
        CM_LOG_E("ukey uiextension dialog requires pc device or pc mode");
        return CMR_DIALOG_ERROR_NOT_PC_DEVICE;
    }
    UkeyDialogLaunchParams params;
    params.bundleName = bundleName;
    params.abilityName = abilityName;
    params.keyUri = *keyUri;
    params.callerUid = callerUid;
    params.timeoutSec = effectiveTimeoutSec;
    if (customData != nullptr) {
        params.customData = *customData;
    }
    params.clientCallback = clientCallback;
    return LaunchUiExtensionSessionLocked(params);
}

/* OpenDriverDialog pre-lock argument validation (D23/D24): blob validity and
 * the customData cap; keeps the same check order as the original
 * implementation (session single-flight and the abilityType check stay
 * inside the lock) */
int32_t CmUkeyAuthDialogManager::ValidateDriverDialogRequest(const UkeyDriverDialogRequest &req)
{
    if (req.abilityName.data == nullptr || req.abilityName.size == 0 ||
        req.abilityName.size > CM_UKEY_ABILITY_NAME_MAX_LEN + 1 || req.keyUri.data == nullptr ||
        req.keyUri.size == 0 || req.keyUri.size > MAX_LEN_URI || req.clientCallback == nullptr ||
        req.callerBundleName.empty()) {
        CM_LOG_E("invalid open driver dialog arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (req.customData.size > CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE) {
        CM_LOG_E("custom data too large: %u", req.customData.size);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    return CM_SUCCESS;
}

int32_t CmUkeyAuthDialogManager::OpenDriverDialog(const UkeyDriverDialogRequest &req)
{
    int32_t ret = ValidateDriverDialogRequest(req);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t effectiveTimeoutSec = NormalizeTimeoutSecLocked(req.timeoutSec);
    if (session_ != nullptr) {
        CM_LOG_E("another ukey auth dialog session is in progress");
        return CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS;
    }
    if (req.abilityType != CM_UKEY_ABILITY_TYPE_UIEXTENSION) {
        CM_LOG_E("driver dialog only supports uiextension type, got: %u", req.abilityType);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    std::string ability(reinterpret_cast<char *>(req.abilityName.data), req.abilityName.size);
    if (ability.back() == '\0') { /* the blob may carry a trailing NUL */
        ability.pop_back();
    }
    if (ability.empty()) { /* empty string after stripping the NUL: invalid argument (spec v4 D23) */
        CM_LOG_E("ability name is empty after trailing nul strip");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (driverAbilityChecker_ == nullptr ||
        !driverAbilityChecker_(req.callerBundleName, ability, req.userId)) {
        CM_LOG_E("driver ability check failed, bundle: %s, ability: %s",
            req.callerBundleName.c_str(), ability.c_str());
        return CMR_DIALOG_ERROR_NOT_REGISTERED;
    }
    if (pcChecker_ == nullptr || !pcChecker_()) {
        CM_LOG_E("ukey uiextension dialog requires pc device or pc mode");
        return CMR_DIALOG_ERROR_NOT_PC_DEVICE;
    }
    /* keyUri/customData point into the IPC-layer paramSet buffer; consumed
     * synchronously (written into dialog params) and never referenced after;
     * customData.size 0 = absent (not carried) */
    UkeyDialogLaunchParams params;
    params.bundleName = req.callerBundleName;
    params.abilityName = ability;
    params.keyUri = req.keyUri;
    params.callerUid = req.callerUid;
    params.timeoutSec = effectiveTimeoutSec;
    params.customData = req.customData;
    params.clientCallback = req.clientCallback;
    return LaunchUiExtensionSessionLocked(params);
}

int32_t CmUkeyAuthDialogManager::OnReport(const std::string &requestId,
    const std::string &callerBundleName, int32_t resultCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ == nullptr || session_->requestId != requestId) {
        CM_LOG_E("report rejected, session not found, request id: %s", requestId.c_str());
        return CMR_DIALOG_ERROR_INTERNAL;
    }
    if (session_->ownerBundleName != callerBundleName) {
        CM_LOG_E("report rejected, bundle name mismatch, expect: %s, got: %s",
            session_->ownerBundleName.c_str(), callerBundleName.c_str());
        return CMR_DIALOG_ERROR_INTERNAL;
    }

    int32_t deliverCode = NormalizeReportCode(resultCode);
    FinishSessionLocked(requestId, deliverCode);
    return CM_SUCCESS;
}

void CmUkeyAuthDialogManager::OnDialogDisconnected(const std::string &requestId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ == nullptr || session_->requestId != requestId ||
        session_->state != UkeyAuthSession::WAITING_REPORT) {
        return;
    }

    session_->state = UkeyAuthSession::GRACE_WAITING;
    if (timerHandler_ != nullptr) {
        timerHandler_->RemoveTask(TotalTimeoutTaskName(requestId));
    }
    if (!StartTimerLocked(GraceTimeoutTaskName(requestId), graceTimeoutMs_,
        [this, requestId] { HandleGraceTimeout(requestId); })) {
        /* Grace timer post failure: no timeout safety net is left, so finish
         * as user cancel instead of leaving a hanging session (F8) */
        FinishSessionLocked(requestId, CMR_DIALOG_ERROR_OPERATION_CANCELS);
        return;
    }
    CM_LOG_I("dialog disconnected, enter grace waiting, request id: %s", requestId.c_str());
}

void CmUkeyAuthDialogManager::OnClientDied(const std::string &requestId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ == nullptr || session_->requestId != requestId) {
        return; // unknown/stale requestId: no-op
    }
    /* Client already dead: the result has nowhere to deliver, so finish with
     * Abort semantics directly (no report-back, free the single-flight) */
    CM_LOG_W("client died during ukey dialog session, abort without result, request id: %s",
        requestId.c_str());
    AbortActiveSessionLocked();
}

void CmUkeyAuthDialogManager::HandleTotalTimeout(const std::string &requestId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ == nullptr || session_->requestId != requestId ||
        session_->state != UkeyAuthSession::WAITING_REPORT) {
        return;
    }

    CM_LOG_E("total timeout, provider did not report, request id: %s", requestId.c_str());
    FinishSessionLocked(requestId, CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT);
}

void CmUkeyAuthDialogManager::HandleGraceTimeout(const std::string &requestId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ == nullptr || session_->requestId != requestId ||
        session_->state != UkeyAuthSession::GRACE_WAITING) {
        return;
    }

    CM_LOG_E("grace timeout, treat as user cancel, request id: %s", requestId.c_str());
    FinishSessionLocked(requestId, CMR_DIALOG_ERROR_OPERATION_CANCELS);
}

std::string CmUkeyAuthDialogManager::GetRequestIdForTest()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return (session_ == nullptr) ? std::string() : session_->requestId;
}

bool CmUkeyAuthDialogManager::EnsureTimerHandlerLocked()
{
    if (timerHandler_ != nullptr) {
        return true;
    }
    auto runner = AppExecFwk::EventRunner::Create("cm_ukey_dialog");
    if (runner == nullptr) {
        CM_LOG_E("create timer event runner failed");
        return false;
    }
    timerHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    return true;
}

bool CmUkeyAuthDialogManager::StartTimerLocked(const std::string &taskName, uint32_t delayMs,
    const std::function<void()> &callback)
{
    if (!EnsureTimerHandlerLocked()) {
        return false;
    }
    bool posted = timerPostFailForTest_ ? false
        : timerHandler_->PostTask(callback, taskName, static_cast<int64_t>(delayMs));
    if (!posted) {
        CM_LOG_E("post timer task failed, task: %s", taskName.c_str());
    }
    return posted;
}

void CmUkeyAuthDialogManager::RegisterClientDeathRecipientLocked(
    const std::shared_ptr<UkeyAuthSession> &session)
{
    if (session->clientCallback == nullptr) {
        return;
    }
    sptr<IRemoteObject::DeathRecipient> recipient =
        new (std::nothrow) CmUkeyClientDeathRecipient(session->requestId);
    if (recipient == nullptr) {
        CM_LOG_E("create client death recipient failed, request id: %s",
            session->requestId.c_str());
        return;
    }
    if (!session->clientCallback->AddDeathRecipient(recipient)) {
        /* Local object / registration failure: the death watch is
         * best-effort, the total timeout remains the safety net */
        CM_LOG_W("add client death recipient failed, request id: %s",
            session->requestId.c_str());
        return;
    }
    session->clientDeathRecipient = recipient;
}

void CmUkeyAuthDialogManager::RemoveClientDeathRecipientLocked(
    const std::shared_ptr<UkeyAuthSession> &session)
{
    if (session->clientCallback != nullptr && session->clientDeathRecipient != nullptr) {
        session->clientCallback->RemoveDeathRecipient(session->clientDeathRecipient);
        session->clientDeathRecipient = nullptr;
    }
}

void CmUkeyAuthDialogManager::StartKeepAliveLocked(const std::string &requestId)
{
    if (unloadRenewal_ == nullptr || !EnsureTimerHandlerLocked()) {
        return; // no renewal hook registered or thread unavailable: no keep-alive task
    }
    if (!timerHandler_->PostTask([this, requestId] { HandleKeepAlive(requestId); },
        KeepAliveTaskName(requestId), static_cast<int64_t>(keepAliveIntervalMs_))) {
        /* Renewal is best-effort: failure only logs, the total timeout remains the safety net */
        CM_LOG_E("post keepalive task failed, request id: %s", requestId.c_str());
    }
}

void CmUkeyAuthDialogManager::HandleKeepAlive(const std::string &requestId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ == nullptr || session_->requestId != requestId) {
        return; // session already finished: no more renewal (late periodic task)
    }
    if (unloadRenewal_ != nullptr) {
        unloadRenewal_(); // reset the SA idle-unload timer (spec §9.4)
    }
    StartKeepAliveLocked(requestId); // periodic task: re-post while the session is still active
}

void CmUkeyAuthDialogManager::FinishSessionLocked(const std::string &requestId, int32_t resultCode)
{
    if (session_ == nullptr || session_->requestId != requestId) {
        return;
    }

    /* Result delivery: via clientCallback SendRequest(CM_UKEY_DIALOG_CALLBACK_CMD,
     * [int32 code], TF_ASYNC), followed by cleanup (stop timers -> ask the
     * dialog service to destroy the window -> disconnect -> drop the session). */
    sptr<IRemoteObject> clientCallback = session_->clientCallback;
    if (clientCallback != nullptr) {
        MessageParcel data;
        if (data.WriteInt32(resultCode)) {
            MessageParcel reply;
            MessageOption option(MessageOption::TF_ASYNC);
            int32_t ret = clientCallback->SendRequest(CM_UKEY_DIALOG_CALLBACK_CMD, data, reply, option);
            if (ret != ERR_NONE) {
                CM_LOG_E("send result to client failed, ret: %d, request id: %s",
                    ret, requestId.c_str());
            }
        } else {
            CM_LOG_E("write result code to parcel failed, request id: %s", requestId.c_str());
        }
    }

    if (timerHandler_ != nullptr) {
        timerHandler_->RemoveTask(TotalTimeoutTaskName(requestId));
        timerHandler_->RemoveTask(GraceTimeoutTaskName(requestId));
        timerHandler_->RemoveTask(KeepAliveTaskName(requestId));
    }
    RemoveClientDeathRecipientLocked(session_);
    sptr<CmSystemDialogConnection> connection = session_->connection;
    if (connection != nullptr) {
        connection->ReleaseWindow(nullptr); // send the destroy command only while the dialog service proxy is held
        connection->ScrubParams();          // scrub params that may contain customData base64 (R10)
    }
    if (launcher_ != nullptr && connection != nullptr) {
        launcher_->Disconnect(connection);
    }
    session_ = nullptr;
    CM_LOG_I("session finished, request id: %s, code: %d", requestId.c_str(), resultCode);
}

void CmUkeyAuthDialogManager::AbortActiveSessionLocked()
{
    /* Environment reassembled (test injection / re-init): pending sessions
     * bound to the old environment are dropped outright (no client
     * callback); stop timers, destroy the dialog, and disconnect the old
     * launcher. */
    if (session_ == nullptr) {
        return;
    }

    std::string requestId = session_->requestId;
    if (timerHandler_ != nullptr) {
        timerHandler_->RemoveTask(TotalTimeoutTaskName(requestId));
        timerHandler_->RemoveTask(GraceTimeoutTaskName(requestId));
        timerHandler_->RemoveTask(KeepAliveTaskName(requestId));
    }
    RemoveClientDeathRecipientLocked(session_);
    sptr<CmSystemDialogConnection> connection = session_->connection;
    if (connection != nullptr) {
        connection->ReleaseWindow(nullptr);
        connection->ScrubParams();
    }
    if (launcher_ != nullptr && connection != nullptr) {
        launcher_->Disconnect(connection);
    }
    session_ = nullptr;
    CM_LOG_W("active session aborted by reconfiguration, request id: %s", requestId.c_str());
}

void CmUkeyAuthDialogManager::InitRealDependencies()
{
    /* Idempotent lazy init: production assembly of RealSystemDialogLauncher +
     * HUKS ability query + PC check + UIAbility launch. Runs only when not
     * yet initialized; test injections (SetLauncher / SetAbilityQuerier /
     * SetPcChecker) are unaffected. */
    std::lock_guard<std::mutex> lock(mutex_);
    if (realDepsInited_) {
        return;
    }
    realDepsInited_ = true;
    launcher_ = std::make_shared<RealSystemDialogLauncher>();
    querier_ = QueryUkeyDriverAbility;
    if (pcChecker_ == nullptr) {
        /* Two-level PC gate (spec D15, user ruling): PC platform builds pass
         * at compile time; non-PC builds read the PC mode parameter
         * (persist.sceneboard.ispcmode); const.product.devicetype is not
         * read (governed by a SELinux neverallow rule) */
        pcChecker_ = CmUkeyIsPcPlatformOrPcMode;
    }
    if (driverAbilityChecker_ == nullptr) {
        driverAbilityChecker_ = QueryDriverUkeyExtensionAbility; /* spec v4 D23 */
    }
    CM_LOG_I("real dialog dependencies initialized");
}
} // namespace OHOS::Security::CertManager
