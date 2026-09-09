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

#include <cstdio>
#include <ctime>

#include "cJSON.h"
#include "hks_api.h"
#include "message_option.h"
#include "message_parcel.h"

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

std::string GenerateRequestId() // 16 random bytes -> 32 hex chars
{
    uint8_t buf[16] = {0};
    bool randomOk = false;
    FILE *f = fopen("/dev/urandom", "r");
    if (f != nullptr) {
        randomOk = (fread(buf, 1, sizeof(buf), f) == sizeof(buf));
        fclose(f);
    }
    if (!randomOk) {
        /* fallback: loop counter + time（仅当 /dev/urandom 不可读时） */
        static uint32_t fallbackCounter = 0;
        uint64_t seed = static_cast<uint64_t>(time(nullptr)) |
            (static_cast<uint64_t>(fallbackCounter++) << 32);
        for (size_t i = 0; i < sizeof(buf); i++) {
            buf[i] = static_cast<uint8_t>((seed >> ((i % sizeof(uint64_t)) * 8)) & 0xFF);
        }
    }
    static const char hex[] = "0123456789abcdef";
    std::string id;
    id.reserve(sizeof(buf) * 2);
    for (size_t i = 0; i < sizeof(buf); i++) {
        id += hex[buf[i] >> 4];
        id += hex[buf[i] & 0xF];
    }
    return id;
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

/* 组装驱动弹框 parameters JSON（spec §6.2）：
 * {"keyUri":"<uri>","appUid":<callerUid>,"requestId":"<id>","action":"UkeyPINAuth"} */
bool BuildUkeyDialogParams(const std::string &requestId, const struct CmBlob *keyUri,
    uint32_t callerUid, std::string &paramsJson)
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
    };
    const char *names[] = { "keyUri", "appUid", "requestId", "action" };
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

/* HUKS ability 查询适配（生产装配，模式对齐 kits 层 cm_dialog_api_common.cpp:98-127）：
 * 查询失败即视为"未注册自定义弹框"（D3）。 */
int32_t QueryUkeyDriverAbility(const struct CmBlob *keyUri,
    std::string &bundleName, std::string &abilityName)
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
        return CMR_DIALOG_ERROR_UKEY_ABILITY_NOT_SUPPORTED;
    }
    abilityName.assign(reinterpret_cast<char *>(abilityInfo.abilityName.data), abilityInfo.abilityName.size);
    bundleName.assign(reinterpret_cast<char *>(abilityInfo.bundleName.data), abilityInfo.bundleName.size);
    CM_FREE_PTR(abilityInfo.abilityName.data);
    CM_FREE_PTR(abilityInfo.bundleName.data);
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

void CmUkeyAuthDialogManager::SetTimeoutForTest(uint32_t totalMs, uint32_t graceMs)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AbortActiveSessionLocked();
    totalTimeoutMs_ = totalMs;
    graceTimeoutMs_ = graceMs;
}

int32_t CmUkeyAuthDialogManager::OpenDialog(const struct CmBlob *keyUri, uint32_t callerUid,
    const sptr<IRemoteObject> &clientCallback)
{
    if (keyUri == nullptr || keyUri->data == nullptr || keyUri->size == 0 ||
        keyUri->size > MAX_LEN_URI || clientCallback == nullptr) {
        CM_LOG_E("invalid open dialog arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ != nullptr) {
        CM_LOG_E("another ukey auth dialog session is in progress");
        return CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS;
    }

    std::string bundleName;
    std::string abilityName;
    if (querier_ == nullptr || querier_(keyUri, bundleName, abilityName) != CM_SUCCESS) {
        CM_LOG_E("query ukey driver ability failed, custom pin dialog not registered");
        return CMR_DIALOG_ERROR_UKEY_ABILITY_NOT_SUPPORTED; // query empty == not registered (D3)
    }

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
    session->requestId = GenerateRequestId();
    session->driverBundleName = bundleName;
    session->callerUid = callerUid;
    session->clientCallback = clientCallback;
    session->state = UkeyAuthSession::LAUNCHING;

    std::string paramsJson;
    if (!BuildUkeyDialogParams(session->requestId, keyUri, callerUid, paramsJson)) {
        CM_LOG_E("build ukey dialog params json failed");
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
        return CMR_DIALOG_ERROR_INTERNAL; // session not stored -> single-flight not occupied
    }
    session->connection = connection;

    session->state = UkeyAuthSession::WAITING_REPORT;
    session_ = session;
    std::string requestId = session->requestId;
    StartTimerLocked(TotalTimeoutTaskName(requestId), totalTimeoutMs_,
        [this, requestId] { HandleTotalTimeout(requestId); });
    CM_LOG_I("open ukey auth dialog success, request id: %s", requestId.c_str());
    return CM_SUCCESS;
}

int32_t CmUkeyAuthDialogManager::OnReport(const std::string &requestId,
    const std::string &callerBundleName, int32_t resultCode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ == nullptr || session_->requestId != requestId) {
        CM_LOG_E("report rejected, session not found, request id: %s", requestId.c_str());
        return CMR_DIALOG_ERROR_INTERNAL;
    }
    if (session_->driverBundleName != callerBundleName) {
        CM_LOG_E("report rejected, bundle name mismatch, expect: %s, got: %s",
            session_->driverBundleName.c_str(), callerBundleName.c_str());
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
    StartTimerLocked(GraceTimeoutTaskName(requestId), graceTimeoutMs_,
        [this, requestId] { HandleGraceTimeout(requestId); });
    CM_LOG_I("dialog disconnected, enter grace waiting, request id: %s", requestId.c_str());
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

void CmUkeyAuthDialogManager::StartTimerLocked(const std::string &taskName, uint32_t delayMs,
    const std::function<void()> &callback)
{
    if (!EnsureTimerHandlerLocked()) {
        return;
    }
    if (!timerHandler_->PostTask(callback, taskName, static_cast<int64_t>(delayMs))) {
        CM_LOG_E("post timer task failed, task: %s", taskName.c_str());
    }
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
    }
    sptr<CmSystemDialogConnection> connection = session_->connection;
    if (connection != nullptr) {
        connection->ReleaseWindow(nullptr); // 仅在仍持有弹窗服务代理时发送销毁命令
    }
    if (launcher_ != nullptr) {
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
    }
    sptr<CmSystemDialogConnection> connection = session_->connection;
    if (connection != nullptr) {
        connection->ReleaseWindow(nullptr);
    }
    if (launcher_ != nullptr) {
        launcher_->Disconnect(connection);
    }
    session_ = nullptr;
    CM_LOG_W("active session aborted by reconfiguration, request id: %s", requestId.c_str());
}

void CmUkeyAuthDialogManager::InitRealDependencies()
{
    /* 幂等懒初始化：生产装配 RealSystemDialogLauncher + HUKS ability 查询。
     * 仅在未初始化时执行；测试注入（SetLauncher/SetAbilityQuerier）不受影响。 */
    std::lock_guard<std::mutex> lock(mutex_);
    if (realDepsInited_) {
        return;
    }
    realDepsInited_ = true;
    launcher_ = std::make_shared<RealSystemDialogLauncher>();
    querier_ = QueryUkeyDriverAbility;
    CM_LOG_I("real dialog dependencies initialized");
}
} // namespace OHOS::Security::CertManager
