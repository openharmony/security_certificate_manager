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
/* 驱动弹窗上报的结果码白名单（JS 层协议，spec §9.3）：
 * 0 成功 / 29700001 通用失败 / 29700002 用户取消 / 29700003 操作失败 /
 * 29700006 参数校验失败；未知值折叠为 29700001。 */
constexpr int32_t REPORT_CODE_SUCCESS = 0;
constexpr int32_t REPORT_CODE_GENERIC_ERROR = 29700001;
constexpr int32_t REPORT_CODE_OPERATION_CANCELED = 29700002;
constexpr int32_t REPORT_CODE_INSTALL_FAILED = 29700003;
constexpr int32_t REPORT_CODE_PARAM_INVALID = 29700006;

/* HUKS ability 查询缓冲区长度（对齐 kits 层 cm_dialog_api_common.cpp 约定） */
constexpr uint32_t HAP_INFO_MAX_LENGTH = 128;
/* 弹框 parameters JSON 的 action 值（spec §6.2） */
constexpr const char *UKEY_DIALOG_ACTION = "UkeyPINAuth";
/* UIExtensionComponent 拉起扩展需以该 want 参数标识扩展类型（ukeyAuth = type 40
 * UKEY_AUTH），缺失时 AMS 侧无法识别为 ukeyAuth 扩展（checkOptExtensionAbility
 * error），驱动 ability 不会被拉起 */
constexpr const char *UKEY_DIALOG_UI_EXTENSION_TYPE_KEY = "ability.want.params.uiExtensionType";
constexpr const char *UKEY_DIALOG_UI_EXTENSION_TYPE = "ukeyAuth";

/* requestId 是会话凭证（安全设计 D7 的第一道防线），必须来自内核 CSPRNG。
 * 任何随机源不可用都拒绝开会话（fail-closed）——禁止可预测的降级种子。
 * 16 random bytes -> 32 hex chars */
bool GenerateRequestId(std::string &id)
{
    uint8_t buf[16] = {0};
    bool randomOk = false;
    /* 优先 getrandom 系统调用（不依赖文件系统，阻塞直至内核完成熵初始化） */
    ssize_t got = getrandom(buf, sizeof(buf), 0);
    if (got == static_cast<ssize_t>(sizeof(buf))) {
        randomOk = true;
    } else {
        /* 回退 /dev/urandom，短重试掩盖偶发 IO 抖动 */
        for (int attempt = 0; attempt < 3 && !randomOk; attempt++) {
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
    id.reserve(sizeof(buf) * 2);
    for (size_t i = 0; i < sizeof(buf); i++) {
        id += hex[buf[i] >> 4];
        id += hex[buf[i] & 0xF];
    }
    return true;
}

/* 白名单校验 + 未知码折叠为通用失败（映射为内部 CMR_DIALOG_ERROR_* 码下发客户端） */
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

/* 客户端死亡监听（F2）：持有会话 requestId，死亡通知转入 manager 的小型可测入口 */
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

/* 组装驱动 UIExtension 弹框 parameters JSON（spec v4 §6.2）：
 * {"keyUri":"<uri>","appUid":<callerUid>,"requestId":"<id>","action":"UkeyPINAuth",
 *  "ability.want.params.uiExtensionType":"ukeyAuth","timeout":<秒>,
 *  "customData":"<base64，仅携带时存在>"}
 * timeout 为本会话归一化后的实际超时时长（秒）；customData 原始字节仅在此编码消费，
 * base64 串随连接对象存活并在会话收尾擦除（spec R10）。 */
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
            items[i] = nullptr; // 所有权移交 root
        } else {
            ok = false;
            break;
        }
    }
    if (ok && params.customData.size > 0) {
        std::string customDataB64 = CmBase64Encode(params.customData.data, params.customData.size);
        cJSON *customItem = cJSON_CreateString(customDataB64.c_str());
        if (customItem == nullptr || !cJSON_AddItemToObject(root, CM_UKEY_DIALOG_PARAM_CUSTOM_DATA,
            customItem)) {
            if (customItem != nullptr) {
                cJSON_Delete(customItem);
            }
            ok = false;
        }
        /* base64 串为 customData 派生敏感数据，用后即擦（spec R10） */
        std::fill(customDataB64.begin(), customDataB64.end(), '\0');
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
        if (items[i] != nullptr) { // 未被 root 接管的项手工释放
            cJSON_Delete(items[i]);
        }
    }
    cJSON_Delete(root);
    return ok;
}

/* HUKS ability 查询适配（生产装配，模式对齐 kits 层 cm_dialog_api_common.cpp）：
 * 查询失败即视为"未注册"（spec v4 D22：无默认弹框回退）。 */
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
        return ret; // 查询失败 == 未注册，调用方路由进默认弹框
    }
    abilityName.assign(reinterpret_cast<char *>(abilityInfo.abilityName.data), abilityInfo.abilityName.size);
    bundleName.assign(reinterpret_cast<char *>(abilityInfo.bundleName.data), abilityInfo.bundleName.size);
    CM_FREE_PTR(abilityInfo.abilityName.data);
    CM_FREE_PTR(abilityInfo.bundleName.data);
    /* abilityType 透传（HksAbilityInfo 已有该字段；HUKS 查询实现尚未填充时，
     * 零初始化保持 0 = UIAbility，与存量注册行为一致） */
    abilityType = static_cast<uint32_t>(abilityInfo.abilityType);
    return CM_SUCCESS;
}

/* 驱动弹框扩展 BMS 预校验（生产装配，spec v4 D23）：(bundleName, abilityName)
 * 存在且类型为 UKEY_AUTH（ExtensionAbilityType=40）。以 SA 自身身份查询
 * （ResetCallingIdentity，避免线程上残留的 app token 影响 BMS 可见性判定）。
 * userId 由 IPC 层经 CmGetProcessInfoForIPC 解出传入（本静态库不得依赖 idl 层，
 * GetCallingUid 推导在 SA 入口线程上不可靠）。 */
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
    bool ok = bundleMgr->QueryExtensionAbilityInfos(want,
        AppExecFwk::ExtensionAbilityType::UKEY_AUTH, 0, userId, infos);
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
    /* 环境重新装配语义与 SetLauncher 一致：绑定旧钩子的挂起会话先行中止 */
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
    /* 故障注入开关：需可在存活会话前后切换，故不中止会话 */
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
    /* timeoutDuration 归一化（spec D5 v2，单位秒）：0（未传）取默认值；显式值 clamp */
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

/* OpenDialog/OpenDriverDialog 公共拉起序列（spec v4 §4.1）：bundle/ability 已定、
 * PC 门禁已过；requestId→会话→连接→总超时→入表→死亡监听/保活。返回同步码。 */
int32_t CmUkeyAuthDialogManager::LaunchUiExtensionSessionLocked(const UkeyDialogLaunchParams &params)
{
    if (launcher_ == nullptr) {
        CM_LOG_E("system dialog launcher is null");
        return CMR_DIALOG_ERROR_INTERNAL;
    }

    /* 总超时是会话唯一的安全网，定时线程创建失败时直接拒绝，避免产生
     * 无超时保护的挂起会话（单飞被永久占用）。 */
    if (!EnsureTimerHandlerLocked()) {
        return CMR_DIALOG_ERROR_INTERNAL;
    }

    auto session = std::make_shared<UkeyAuthSession>();
    if (!GenerateRequestId(session->requestId)) {
        /* fail-closed：requestId 是会话凭证，无 CSPRNG 即拒绝开会话 */
        CM_LOG_E("generate request id failed");
        return CMR_DIALOG_ERROR_INTERNAL;
    }
    session->ownerBundleName = params.bundleName; /* OpenDialog 查询所得 / ForDriver 调用方 bundle */
    session->callerUid = params.callerUid;
    session->clientCallback = params.clientCallback;
    session->state = UkeyAuthSession::LAUNCHING;

    {
        std::string paramsJson;
        if (!BuildUkeyDialogParams(session->requestId, params, paramsJson)) {
            CM_LOG_E("build dialog params json failed");
            return CMR_DIALOG_ERROR_INTERNAL;
        }
        sptr<CmSystemDialogConnection> connection = new (std::nothrow) CmSystemDialogConnection(
            session->requestId, params.bundleName, params.abilityName, paramsJson);
        if (connection == nullptr) {
            CM_LOG_E("create system dialog connection failed");
            return CMR_ERROR_MALLOC_FAIL;
        }
        if (launcher_->Connect(connection) != CM_SUCCESS) {
            CM_LOG_E("connect system dialog service failed");
            connection->ScrubParams();
            return CMR_DIALOG_ERROR_INTERNAL; // session not stored -> single-flight not occupied
        }
        session->connection = connection;
    }

    session->state = UkeyAuthSession::WAITING_REPORT;
    std::string requestId = session->requestId;
    /* 总超时是会话唯一的安全网，投递失败时直接拒绝并回滚已建立的连接
     * （会话不入表 -> 单飞不被占用），避免产生无超时保护的挂起会话（F8）。
     * timeoutSec 已归一化（≤ max），* 1000 无溢出。 */
    if (!StartTimerLocked(TotalTimeoutTaskName(requestId), params.timeoutSec * 1000, /* sec -> ms */
        [this, requestId] { HandleTotalTimeout(requestId); })) {
        sptr<CmSystemDialogConnection> connection = session->connection;
        if (connection != nullptr) {
            connection->ReleaseWindow(nullptr);
            connection->ScrubParams();
        }
        if (launcher_ != nullptr && connection != nullptr) {
            launcher_->Disconnect(connection);
        }
        return CMR_DIALOG_ERROR_INTERNAL;
    }
    session_ = session;
    RegisterClientDeathRecipientLocked(session); // best-effort，失败仅告警（F2）
    StartKeepAliveLocked(requestId);             // best-effort，失败仅记录（F1）
    CM_LOG_I("open ukey auth dialog success, request id: %s", requestId.c_str());
    return CM_SUCCESS;
}

int32_t CmUkeyAuthDialogManager::OpenDialog(const struct CmBlob *keyUri, uint32_t callerUid,
    uint32_t timeoutSec, const struct CmBlob *customData,
    const sptr<IRemoteObject> &clientCallback)
{
    if (keyUri == nullptr || keyUri->data == nullptr || keyUri->size == 0 ||
        keyUri->size > MAX_LEN_URI || clientCallback == nullptr) {
        CM_LOG_E("invalid open dialog arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    /* customData 复核（客户端已有校验，纵深防御，spec D19） */
    if (customData != nullptr && customData->size > CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE) {
        CM_LOG_E("custom data too large: %u", customData->size);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t effectiveTimeoutSec = NormalizeTimeoutSecLocked(timeoutSec);
    if (session_ != nullptr) {
        CM_LOG_E("another ukey auth dialog session is in progress");
        return CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS;
    }

    /* 路由（spec v4 §4.1/D22）：SA 自行查询，不信任客户端声明的 ability 信息（D20）；
     * 仅 UIExtensionAbility + PC 放行 SA 会话路径，未注册/UIAbility 同步拒绝。 */
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
    /* PC 门禁为竞态防御：Kit 已前置判定，模式翻转时 fail-closed（D25 v2） */
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

/* OpenDriverDialog 锁前入参校验（D23/D24）：blob 合法性与 customData 上限；
 * 保持与原实现一致的判定顺序（session 单飞与 abilityType 检查仍在锁内） */
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
    if (ability.back() == '\0') { /* blob 可能带结尾 NUL */
        ability.pop_back();
    }
    if (ability.empty()) { /* 剥离 NUL 后为空串：视为非法参数（spec v4 D23） */
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
    /* keyUri/customData 指向 IPC 层 paramSet 缓冲，同步消费（写入弹框参数）后不再引用；
     * customData.size 0 = 缺省（不携带） */
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
        /* 宽限期投递失败：已无任何超时兜底，按用户取消收尾而非悬挂会话（F8） */
        FinishSessionLocked(requestId, CMR_DIALOG_ERROR_OPERATION_CANCELS);
        return;
    }
    CM_LOG_I("dialog disconnected, enter grace waiting, request id: %s", requestId.c_str());
}

void CmUkeyAuthDialogManager::OnClientDied(const std::string &requestId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ == nullptr || session_->requestId != requestId) {
        return; // 未知/过期 requestId：no-op
    }
    /* 客户端已死：结果无处投递，直接按 Abort 语义收尾（不回投、释放单飞） */
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
        /* 本地对象/注册失败：死亡监控尽力而为，总超时仍是安全网 */
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
        return; // 未注册续期钩子或线程不可用：无保活任务
    }
    if (!timerHandler_->PostTask([this, requestId] { HandleKeepAlive(requestId); },
        KeepAliveTaskName(requestId), static_cast<int64_t>(keepAliveIntervalMs_))) {
        /* 续期尽力而为：失败仅记录，总超时仍是安全网 */
        CM_LOG_E("post keepalive task failed, request id: %s", requestId.c_str());
    }
}

void CmUkeyAuthDialogManager::HandleKeepAlive(const std::string &requestId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ == nullptr || session_->requestId != requestId) {
        return; // 会话已结束：不再续期（迟到的周期任务）
    }
    if (unloadRenewal_ != nullptr) {
        unloadRenewal_(); // 重置 SA 空闲卸载计时（spec §9.4）
    }
    StartKeepAliveLocked(requestId); // 周期任务：会话仍活跃时重新投递
}

void CmUkeyAuthDialogManager::FinishSessionLocked(const std::string &requestId, int32_t resultCode)
{
    if (session_ == nullptr || session_->requestId != requestId) {
        return;
    }

    /* 结果分发：经 clientCallback SendRequest(CM_UKEY_DIALOG_CALLBACK_CMD, [int32 code], TF_ASYNC)，
     * 随后清理（停定时器 -> 通知弹窗服务销毁窗口 -> 断连 -> 删会话）。 */
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
        connection->ReleaseWindow(nullptr); // 仅在仍持有弹窗服务代理时发送销毁命令
        connection->ScrubParams();          // 擦除可能含 customData base64 的参数（R10）
    }
    if (launcher_ != nullptr && connection != nullptr) {
        launcher_->Disconnect(connection);
    }
    session_ = nullptr;
    CM_LOG_I("session finished, request id: %s, code: %d", requestId.c_str(), resultCode);
}

void CmUkeyAuthDialogManager::AbortActiveSessionLocked()
{
    /* 环境被重新装配（测试注入/重新初始化）：绑定旧环境的挂起会话直接丢弃
     * （不回调客户端），停定时器、销毁弹窗并断连旧 launcher。 */
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
    /* 幂等懒初始化：生产装配 RealSystemDialogLauncher + HUKS ability 查询 +
     * PC 判定 + UIAbility 拉起。仅在未初始化时执行；测试注入（SetLauncher/
     * SetAbilityQuerier/SetPcChecker）不受影响。 */
    std::lock_guard<std::mutex> lock(mutex_);
    if (realDepsInited_) {
        return;
    }
    realDepsInited_ = true;
    launcher_ = std::make_shared<RealSystemDialogLauncher>();
    querier_ = QueryUkeyDriverAbility;
    if (pcChecker_ == nullptr) {
        /* PC 门禁两级判定（spec D15，用户裁定）：PC 平台构建编译期放行，
         * 非 PC 平台构建读 PC 模式参数（persist.sceneboard.ispcmode）判定，
         * 不读 const.product.devicetype（SELinux neverallow 管控） */
        pcChecker_ = CmUkeyIsPcPlatformOrPcMode;
    }
    if (driverAbilityChecker_ == nullptr) {
        driverAbilityChecker_ = QueryDriverUkeyExtensionAbility; /* spec v4 D23 */
    }
    CM_LOG_I("real dialog dependencies initialized");
}
} // namespace OHOS::Security::CertManager
