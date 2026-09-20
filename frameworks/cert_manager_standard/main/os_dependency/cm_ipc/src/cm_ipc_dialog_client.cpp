/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cm_ipc_client.h"
#include "cm_request_dialog.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "event_handler.h"
#include "event_runner.h"
#include "iremote_broker.h"
#include "iremote_stub.h"
#include "iservice_registry.h"
#include "message_option.h"
#include "message_parcel.h"
#include "nocopyable.h"

#include "cm_ipc_client_serialization.h"
#include "cm_log.h"
#include "cm_param.h"
#include "cm_ukey_ability_type.h"

namespace OHOS {
namespace Security {
namespace CertManager {
namespace {
/* client-side fallback timer (> SA 5min total timeout): guards against SA death
 * leaving the caller's callback pending forever */
constexpr uint32_t CM_UKEY_DIALOG_CLIENT_FALLBACK_MS = 660000; /* 11 min, > server 10min max */
/* IRemoteStub<T> requires T::GetDescriptor(); IRemoteBroker has none, so a
 * local broker descriptor is declared (same fix as the SA-side test fake) */
class CmDialogCallbackBroker : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"cm.security.ukey.dialog.callback");
};

/* Dedicated fallback-timer thread, name distinct from the SA-side "cm_ukey_dialog".
 * Creation failure is not cached: the next call retries. */
std::shared_ptr<AppExecFwk::EventHandler> GetTimerHandler()
{
    static std::mutex mutex;
    static std::shared_ptr<AppExecFwk::EventHandler> handler;
    std::lock_guard<std::mutex> lock(mutex);
    if (handler == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create("cm_ukey_dialog_client");
        if (runner != nullptr) {
            handler = std::make_shared<AppExecFwk::EventHandler>(runner);
        }
    }
    return handler;
}

uint32_t NextTaskSeq()
{
    static std::atomic<uint32_t> seq { 1 };
    return seq.fetch_add(1);
}
} // namespace

/* Client-side callback stub: the SA delivers the dialog result via
 * SendRequest(CM_UKEY_DIALOG_CALLBACK_CMD, parcel[int32 resultCode], TF_ASYNC).
 * Delivery is exactly-once (atomic flag) across the IPC path and the fallback
 * timer; after a successful OPEN the stub owns itself until first Deliver. */
class CmDialogCallbackStub : public IRemoteStub<CmDialogCallbackBroker> {
public:
    CmDialogCallbackStub(CmUkeyAuthDialogResultCallback callback, void *userData);
    ~CmDialogCallbackStub() override;

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override;

    bool StartFallbackTimer();
    void HoldSelf();
    /* mark delivered without invoking the callback (sync-failure path) */
    void Cancel();
    void Deliver(int32_t result);

private:
    const std::string taskName_;
    CmUkeyAuthDialogResultCallback callback_;
    void *userData_;
    std::atomic<bool> delivered_;
    sptr<CmDialogCallbackStub> selfHold_;

    DISALLOW_COPY_AND_MOVE(CmDialogCallbackStub);
};

CmDialogCallbackStub::CmDialogCallbackStub(CmUkeyAuthDialogResultCallback callback, void *userData)
    : taskName_("cm_ukey_dialog_client_fallback_" + std::to_string(NextTaskSeq())),
      callback_(callback), userData_(userData), delivered_(false)
{
}

CmDialogCallbackStub::~CmDialogCallbackStub()
{
    auto handler = GetTimerHandler();
    if (handler != nullptr) {
        handler->RemoveTask(taskName_);
    }
}

int CmDialogCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    if (code != CM_UKEY_DIALOG_CALLBACK_CMD) {
        CM_LOG_W("unexpected ukey dialog callback code: %u", code);
        return 0;
    }
    int32_t result = data.ReadInt32();
    Deliver(result);
    return 0;
}

bool CmDialogCallbackStub::StartFallbackTimer()
{
    auto handler = GetTimerHandler();
    if (handler == nullptr) {
        CM_LOG_E("create ukey dialog client timer handler failed");
        return false;
    }
    wptr<CmDialogCallbackStub> weak(this);
    auto task = [weak]() {
        sptr<CmDialogCallbackStub> stub = weak.promote();
        if (stub == nullptr) {
            return;
        }
        CM_LOG_E("ukey dialog client fallback timer fired");
        stub->Deliver(CMR_DIALOG_ERROR_INTERNAL);
    };
    if (!handler->PostTask(task, taskName_, static_cast<int64_t>(CM_UKEY_DIALOG_CLIENT_FALLBACK_MS))) {
        CM_LOG_E("post ukey dialog fallback task failed");
        return false;
    }
    return true;
}

void CmDialogCallbackStub::HoldSelf()
{
    selfHold_ = this;
}

void CmDialogCallbackStub::Cancel()
{
    bool expected = false;
    delivered_.compare_exchange_strong(expected, true);
}

void CmDialogCallbackStub::Deliver(int32_t result)
{
    bool expected = false;
    if (!delivered_.compare_exchange_strong(expected, true)) {
        return; /* already delivered exactly once */
    }

    auto handler = GetTimerHandler();
    if (handler != nullptr) {
        handler->RemoveTask(taskName_);
    }
    CM_LOG_I("deliver ukey auth dialog result, code = %d", result);
    if (callback_ != nullptr) {
        callback_(result, userData_);
    }
    selfHold_ = nullptr; /* release self-ownership */
}
} // namespace CertManager
} // namespace Security
} // namespace OHOS

using namespace OHOS;
using namespace OHOS::Security::CertManager;

/* Common send sequence for OPEN requests (shared by both entries): arm the
 * client fallback timer -> send -> on sync failure Cancel destroys the stub
 * (no callback) / on success HoldSelf keeps it alive until Deliver; returns
 * the sync code */
static int32_t SendOpenDialogRequest(enum CertManagerInterfaceCode type,
    const sptr<CmDialogCallbackStub> &stub, const struct CmParamSet *sendParamSet)
{
    int32_t ret = CM_SUCCESS;
    int32_t replyCode = CM_FAILURE;
    do {
        if (!stub->StartFallbackTimer()) {
            /* reject rather than leave a callback that can hang forever */
            CM_LOG_E("arm ukey dialog fallback timer failed");
            ret = CMR_DIALOG_ERROR_INTERNAL;
            break;
        }
        struct CmBlob parcelBlob = { sendParamSet->paramSetSize,
            reinterpret_cast<uint8_t *>(const_cast<struct CmParamSet *>(sendParamSet)) };
        ret = OHOS::SendRequestWithRemote(type, &parcelBlob, stub, &replyCode);
        if (ret != CM_SUCCESS || replyCode != CM_SUCCESS) {
            /* sync error: destroy the stub without invoking the callback (spec 4) */
            CM_LOG_E("ukey dialog request failed, ret = %d, reply = %d", ret, replyCode);
            stub->Cancel();
            ret = (ret != CM_SUCCESS) ? ret : replyCode;
            break;
        }
        stub->HoldSelf(); /* stub manages its own lifetime until Deliver */
        CM_LOG_I("ukey dialog request accepted");
    } while (0);
    return ret;
}

int32_t CmClientOpenUkeyAuthDialog(const struct UkeyAuthRequest *ukeyAuthRequest,
    CmUkeyAuthDialogResultCallback callback, void *userData)
{
    if (ukeyAuthRequest == nullptr || callback == nullptr ||
        CmCheckBlob(&ukeyAuthRequest->keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid open ukey auth dialog arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    /* Defense in depth: intercept inner API callers that bypass NAPI validation (spec §8.3) */
    if (ukeyAuthRequest->customData.size > CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE) {
        CM_LOG_E("custom data too large: %u", ukeyAuthRequest->customData.size);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }

    sptr<CmDialogCallbackStub> stub = new (std::nothrow) CmDialogCallbackStub(callback, userData);
    if (stub == nullptr) {
        CM_LOG_E("create ukey dialog callback stub failed");
        return CMR_ERROR_MALLOC_FAIL;
    }

    /* Serialize all params in one pass: the FreshParamSet inside
     * CmParamsToParamSet writes blob data to the tail of the paramSet; a
     * later CmAddParams append would overwrite the already-serialized data
     * and the new param's blob would never enter the list (the SA side then
     * reads uninitialized heap). An omitted customData (size 0) is handled by
     * CmParamsToParamSet's NULL-blob marker conversion, and the SA side
     * parses it as a missing PARAM2. */
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = ukeyAuthRequest->keyUri },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = ukeyAuthRequest->timeoutDuration }, /* seconds; 0 = default */
        { .tag = CM_TAG_PARAM2_BUFFER, .blob = ukeyAuthRequest->customData },
    };

    struct CmParamSet *sendParamSet = nullptr;
    int32_t ret = CmParamsToParamSet(params, CM_ARRAY_SIZE(params), &sendParamSet);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("open ukey dialog pack params failed, ret = %d", ret);
        CmFreeParamSet(&sendParamSet);
        return ret;
    }

    ret = SendOpenDialogRequest(CM_MSG_OPEN_UKEY_AUTH_DIALOG, stub, sendParamSet);
    CmFreeParamSet(&sendParamSet);
    return ret;
}

int32_t CmClientOpenUkeyAuthDialogForDriver(const struct UkeyAuthDialogInfo *dialogInfo,
    const struct UkeyAuthRequest *ukeyAuthRequest, CmUkeyAuthDialogResultCallback callback,
    void *userData)
{
    if (dialogInfo == nullptr || ukeyAuthRequest == nullptr || callback == nullptr ||
        CmCheckBlob(&dialogInfo->abilityName) != CM_SUCCESS ||
        CmCheckBlob(&ukeyAuthRequest->keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid open auth dialog for ukey driver arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (dialogInfo->abilityType != CM_UKEY_ABILITY_TYPE_UIEXTENSION) {
        CM_LOG_E("invalid driver dialog ability type: %u", dialogInfo->abilityType);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    if (ukeyAuthRequest->customData.size > CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE) {
        CM_LOG_E("custom data too large: %u", ukeyAuthRequest->customData.size);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }

    sptr<CmDialogCallbackStub> stub = new (std::nothrow) CmDialogCallbackStub(callback, userData);
    if (stub == nullptr) {
        CM_LOG_E("create ukey dialog callback stub failed");
        return CMR_ERROR_MALLOC_FAIL;
    }

    /* Five params serialized in one pass (spec v4 §8.2): no later CmAddParams append */
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = dialogInfo->abilityName },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = dialogInfo->abilityType },
        { .tag = CM_TAG_PARAM2_BUFFER, .blob = ukeyAuthRequest->keyUri },
        { .tag = CM_TAG_PARAM3_UINT32, .uint32Param = ukeyAuthRequest->timeoutDuration }, /* seconds; 0 = default */
        { .tag = CM_TAG_PARAM4_BUFFER, .blob = ukeyAuthRequest->customData },
    };

    struct CmParamSet *sendParamSet = nullptr;
    int32_t ret = CmParamsToParamSet(params, CM_ARRAY_SIZE(params), &sendParamSet);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("open driver dialog pack params failed, ret = %d", ret);
        CmFreeParamSet(&sendParamSet);
        return ret;
    }

    ret = SendOpenDialogRequest(CM_MSG_OPEN_UKEY_AUTH_DIALOG_FOR_DRIVER, stub, sendParamSet);
    CmFreeParamSet(&sendParamSet);
    return ret;
}

int32_t CmClientReportUkeyAuthResult(const struct CmBlob *requestId, int32_t resultCode)
{
    if (CmCheckBlob(requestId) != CM_SUCCESS) {
        CM_LOG_E("invalid report ukey auth result arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParamSet *sendParamSet = nullptr;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *requestId },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = static_cast<uint32_t>(resultCode) },
    };

    int32_t ret = CmParamsToParamSet(params, CM_ARRAY_SIZE(params), &sendParamSet);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("report ukey result pack params failed, ret = %d", ret);
        return ret;
    }
    struct CmBlob parcelBlob = { sendParamSet->paramSetSize, reinterpret_cast<uint8_t *>(sendParamSet) };

    int32_t replyCode = CM_FAILURE;
    ret = OHOS::SendRequestWithRemote(CM_MSG_REPORT_UKEY_AUTH_RESULT, &parcelBlob, nullptr, &replyCode);
    CmFreeParamSet(&sendParamSet);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("report ukey auth result request failed, ret = %d", ret);
        return ret;
    }
    return replyCode; /* raw CMR_DIALOG_* code, SA routing passes it through */
}
