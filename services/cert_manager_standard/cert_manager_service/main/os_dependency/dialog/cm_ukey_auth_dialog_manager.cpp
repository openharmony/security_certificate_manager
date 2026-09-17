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
 *  "ability.want.params.uiExtensionType":"ukeyAuth","timeout":<ms>,
 *  "customData":"<base64，仅携带时存在>"}
 * timeout 为本会话归一化后的实际超时时长（ms）；customData 原始字节仅在此编码消费，
 * base64 串随连接对象存活并在会话收尾擦除（spec R10）。 */
bool BuildUkeyDialogParams(const std::string &requestId, const struct CmBlob *keyUri,
    uint32_t callerUid, uint32_t timeoutMs,
    const struct CmBlob *customData, std::string &paramsJson)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        CM_LOG_E("create params json root failed");
        return false;
    }

    std::string uriStr(reinterpret_cast<char *>(keyUri->data), keyUri->size);
    cJSON *items[] = {
        cJSON_CreateString(uriStr.c_str()),                 // keyUri
        cJSON_CreateNumber(static_cast<double>(callerUid)), // appUid
        cJSON_CreateString(requestId.c_str()),              // requestId
        cJSON_CreateString(UKEY_DIALOG_ACTION),             // action
        cJSON_CreateString(UKEY_DIALOG_UI_EXTENSION_TYPE), // uiExtensionType
        cJSON_CreateNumber(static_cast<double>(timeoutMs)), // timeout
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
    if (ok && customData != nullptr && customData->size > 0) {
        std::string customDataB64 = CmBase64Encode(customData->data, customData->size);
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

/* 组装系统默认弹框 parameters JSON（spec §6.2，弹框身份见 §9.2 / D14 修订）：
 * {"ability.want.params.uiExtensionType":"ukeyAuth","keyUri":"<uri>",
 *  "appUid":<callerUid>,"requestId":"<id>","scene":"Login|Custom"}
 * 默认弹框为 com.ohos.certmanager 的 ukeyAuth 类型扩展（复用 UKeyAuthSheet 页面），
 * 终止时经框架 UkeyAuthExtensionContext 上报；customData 不下发（D18）。 */
bool BuildDefaultDialogParams(const std::string &requestId, const struct CmBlob *keyUri,
    uint32_t callerUid, uint32_t scene, std::string &paramsJson)
{
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        CM_LOG_E("create default dialog params json root failed");
        return false;
    }

    std::string uriStr(reinterpret_cast<char *>(keyUri->data), keyUri->size);
    cJSON *items[] = {
        cJSON_CreateString(UKEY_DIALOG_UI_EXTENSION_TYPE), // uiExtensionType(ukeyAuth)
        cJSON_CreateString(uriStr.c_str()),                 // keyUri
        cJSON_CreateNumber(static_cast<double>(callerUid)), // appUid
        cJSON_CreateString(requestId.c_str()),              // requestId
        cJSON_CreateString(CmUkeySceneToString(scene)),     // scene
    };
    const char *names[] = { UKEY_DIALOG_UI_EXTENSION_TYPE_KEY,
        "keyUri", "appUid", "requestId", CM_UKEY_DIALOG_PARAM_SCENE };
    bool ok = true;
    for (size_t i = 0; i < sizeof(items) / sizeof(items[0]); i++) {
        if (items[i] != nullptr && cJSON_AddItemToObject(root, names[i], items[i])) {
            items[i] = nullptr; // 所有权移交 root
        } else {
            ok = false;
            break;
        }
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
 * 查询失败即视为"未注册自定义弹框"，由 OpenDialog 路由进系统默认弹框（spec §4.1）；
 */
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
 * （ResetCallingIdentity，避免线程上残留的 app token 影响 BMS 可见性判定）。 */
bool QueryDriverUkeyExtensionAbility(const std::string &bundleName,
    const std::string &abilityName)
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
    /* 调用方 userId 自 calling uid 推导（uid 高位编码 userId，对齐
     * print_service/common_event_service 等 SA 的既有模式） */
    constexpr int32_t UID_TRANSFORM_DIVISOR = 200000;
    int32_t userId = static_cast<int32_t>(IPCSkeleton::GetCallingUid()) / UID_TRANSFORM_DIVISOR;
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

void CmUkeyAuthDialogManager::SetTimeoutRangeForTest(uint32_t minMs, uint32_t defaultMs,
    uint32_t maxMs, uint32_t graceMs)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AbortActiveSessionLocked();
    minTimeoutMs_ = minMs;
    defaultTimeoutMs_ = defaultMs;
    maxTimeoutMs_ = maxMs;
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

uint32_t CmUkeyAuthDialogManager::NormalizeTimeoutMsLocked(uint32_t timeoutMs)
{
    /* timeoutDuration 归一化（spec D5 v2）：0（未传）取默认值；显式值 clamp */
    if (timeoutMs == 0) {
        return defaultTimeoutMs_;
    }
    if (timeoutMs < minTimeoutMs_) {
        CM_LOG_W("timeout %u below min, clamp to %u", timeoutMs, minTimeoutMs_);
        return minTimeoutMs_;
    }
    if (timeoutMs > maxTimeoutMs_) {
        CM_LOG_W("timeout %u exceeds max, clamp to %u", timeoutMs, maxTimeoutMs_);
        return maxTimeoutMs_;
    }
    return timeoutMs;
}

/* OpenDialog/OpenDriverDialog 公共拉起序列（spec v4 §4.1）：bundle/ability 已定、
 * PC 门禁已过；requestId→会话→连接→总超时→入表→死亡监听/保活。返回同步码。 */
int32_t CmUkeyAuthDialogManager::LaunchUiExtensionSessionLocked(const std::string &bundleName,
    const std::string &abilityName, const struct CmBlob *keyUri, uint32_t callerUid,
    uint32_t timeoutMs, const struct CmBlob *customData,
    const sptr<IRemoteObject> &clientCallback)
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
    session->kind = UkeyAuthSession::UIEXTENSION_DIALOG;
    session->ownerBundleName = bundleName; /* OpenDialog 查询所得 / ForDriver 调用方 bundle */
    session->callerUid = callerUid;
    session->clientCallback = clientCallback;
    session->state = UkeyAuthSession::LAUNCHING;

    {
        std::string paramsJson;
        if (!BuildUkeyDialogParams(session->requestId, keyUri, callerUid, timeoutMs,
            customData, paramsJson)) {
            CM_LOG_E("build dialog params json failed");
            return CMR_DIALOG_ERROR_INTERNAL;
        }
        sptr<CmSystemDialogConnection> connection = new (std::nothrow) CmSystemDialogConnection(
            session->requestId, bundleName, abilityName, paramsJson);
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
     * （会话不入表 -> 单飞不被占用），避免产生无超时保护的挂起会话（F8）。 */
    if (!StartTimerLocked(TotalTimeoutTaskName(requestId), timeoutMs,
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
    CM_LOG_I("open ukey auth dialog success, kind: UIEXTENSION_DIALOG, request id: %s",
        requestId.c_str());
    return CM_SUCCESS;
}

int32_t CmUkeyAuthDialogManager::OpenDialog(const struct CmBlob *keyUri, uint32_t callerUid,
    uint32_t timeoutMs, uint32_t scene, const struct CmBlob *customData,
    const sptr<IRemoteObject> &clientCallback)
{
    if (keyUri == nullptr || keyUri->data == nullptr || keyUri->size == 0 ||
        keyUri->size > MAX_LEN_URI || clientCallback == nullptr) {
        CM_LOG_E("invalid open dialog arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    /* scene / customData 复核（客户端已有校验，纵深防御，spec D13/D19） */
    if (!CmUkeySceneIsValid(scene)) {
        CM_LOG_E("invalid scene: %u", scene);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    if (customData != nullptr && customData->size > CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE) {
        CM_LOG_E("custom data too large: %u", customData->size);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t effectiveTimeoutMs = NormalizeTimeoutMsLocked(timeoutMs);
    if (session_ != nullptr) {
        CM_LOG_E("another ukey auth dialog session is in progress");
        return CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS;
    }

    /* 路由（spec §4.1）：查询失败=未注册→默认弹框；成功按 abilityType 分流。
     * SA 自行查询，不信任客户端声明的 ability 信息（D20）。 */
    std::string bundleName;
    std::string abilityName;
    uint32_t abilityType = CM_UKEY_ABILITY_TYPE_UIABILITY;
    int32_t queryRet = (querier_ == nullptr) ? CM_FAILURE : querier_(keyUri, bundleName, abilityName, abilityType);
    UkeyAuthSession::DialogKind kind;
    if (queryRet != CM_SUCCESS) {
        if (scene == CM_UKEY_AUTH_SCENE_CUSTOM) {
            /* rule 3：需默认弹框但调用方声明仅自定义（spec D10，29700005） */
            CM_LOG_E("no custom dialog registered but scene is Custom");
            return CMR_DIALOG_ERROR_NOT_REGISTERED;
        }
        kind = UkeyAuthSession::DEFAULT_DIALOG;
        bundleName = CM_UKEY_DEFAULT_DIALOG_BUNDLE;
        abilityName = CM_UKEY_DEFAULT_DIALOG_ABILITY;
    } else if (abilityType == CM_UKEY_ABILITY_TYPE_UIABILITY) {
        CM_LOG_E("ukey driver ability type is UIAbility, not supported by sa path");
        return CMR_DIALOG_ERROR_UIABILITY_NOT_SUPPORTED;
    } else if (abilityType == CM_UKEY_ABILITY_TYPE_UIEXTENSION) {
        /* rule 6：UIExtension 弹框仅 PC / PC 模式设备（spec D10/D15，29700005）；
         * checker 缺省按非 PC 处理（fail-closed） */
        if (pcChecker_ == nullptr || !pcChecker_()) {
            CM_LOG_E("ukey uiextension dialog requires pc device or pc mode");
            return CMR_DIALOG_ERROR_NOT_PC_DEVICE;
        }
        kind = UkeyAuthSession::UIEXTENSION_DIALOG;
    } else {
        CM_LOG_E("unknown ukey ability type: %u", abilityType);
        return CMR_DIALOG_ERROR_INTERNAL;
    }

    if (kind == UkeyAuthSession::UIEXTENSION_DIALOG) {
        return LaunchUiExtensionSessionLocked(bundleName, abilityName, keyUri, callerUid,
            effectiveTimeoutMs, customData, clientCallback);
    }

    /* DEFAULT_DIALOG 分支：保持既有内联拉起路径（不迁移，Task 6 移除） */
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
    session->kind = kind;
    session->scene = scene;
    session->ownerBundleName = bundleName; /* 默认弹框 kind 已指向 com.ohos.certmanager */
    session->callerUid = callerUid;
    session->clientCallback = clientCallback;
    session->state = UkeyAuthSession::LAUNCHING;

    {
        std::string paramsJson;
        bool paramsOk = BuildDefaultDialogParams(session->requestId, keyUri, callerUid, scene,
            paramsJson);
        if (!paramsOk) {
            CM_LOG_E("build dialog params json failed");
            return CMR_DIALOG_ERROR_INTERNAL;
        }
        if (customData != nullptr && customData->size > 0) {
            /* D18：回退默认弹框时 customData 静默丢弃（仅记录长度，spec R10） */
            CM_LOG_I("custom data dropped for default dialog, size: %u", customData->size);
        }
        sptr<CmSystemDialogConnection> connection = new (std::nothrow) CmSystemDialogConnection(
            session->requestId, bundleName, abilityName, paramsJson);
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
     * （会话不入表 -> 单飞不被占用），避免产生无超时保护的挂起会话（F8）。 */
    if (!StartTimerLocked(TotalTimeoutTaskName(requestId), effectiveTimeoutMs,
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
    CM_LOG_I("open ukey auth dialog success, kind: %d, request id: %s",
        static_cast<int32_t>(kind), requestId.c_str());
    return CM_SUCCESS;
}

int32_t CmUkeyAuthDialogManager::OpenDriverDialog(const struct CmBlob *abilityName,
    uint32_t abilityType, const struct CmBlob *keyUri, uint32_t callerUid,
    const std::string &callerBundleName, uint32_t timeoutMs,
    const struct CmBlob *customData, const sptr<IRemoteObject> &clientCallback)
{
    if (abilityName == nullptr || abilityName->data == nullptr || abilityName->size == 0 ||
        abilityName->size > HAP_INFO_MAX_LENGTH || keyUri == nullptr || keyUri->data == nullptr ||
        keyUri->size == 0 || keyUri->size > MAX_LEN_URI || clientCallback == nullptr ||
        callerBundleName.empty()) {
        CM_LOG_E("invalid open driver dialog arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (customData != nullptr && customData->size > CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE) {
        CM_LOG_E("custom data too large: %u", customData->size);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t effectiveTimeoutMs = NormalizeTimeoutMsLocked(timeoutMs);
    if (session_ != nullptr) {
        CM_LOG_E("another ukey auth dialog session is in progress");
        return CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS;
    }
    if (abilityType != CM_UKEY_ABILITY_TYPE_UIEXTENSION) {
        CM_LOG_E("driver dialog only supports uiextension type, got: %u", abilityType);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    std::string ability(reinterpret_cast<char *>(abilityName->data), abilityName->size);
    if (ability.back() == '\0') { /* blob 可能带结尾 NUL */
        ability.pop_back();
    }
    if (driverAbilityChecker_ == nullptr || !driverAbilityChecker_(callerBundleName, ability)) {
        CM_LOG_E("driver ability check failed, bundle: %s, ability: %s",
            callerBundleName.c_str(), ability.c_str());
        return CMR_DIALOG_ERROR_NOT_REGISTERED;
    }
    if (pcChecker_ == nullptr || !pcChecker_()) {
        CM_LOG_E("ukey uiextension dialog requires pc device or pc mode");
        return CMR_DIALOG_ERROR_NOT_PC_DEVICE;
    }
    return LaunchUiExtensionSessionLocked(callerBundleName, ability, keyUri, callerUid,
        effectiveTimeoutMs, customData, clientCallback);
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
        pcChecker_ = CmUkeyIsPcOrPcMode; /* spec D15 */
    }
    if (driverAbilityChecker_ == nullptr) {
        driverAbilityChecker_ = QueryDriverUkeyExtensionAbility; /* spec v4 D23 */
    }
    CM_LOG_I("real dialog dependencies initialized");
}
} // namespace OHOS::Security::CertManager
