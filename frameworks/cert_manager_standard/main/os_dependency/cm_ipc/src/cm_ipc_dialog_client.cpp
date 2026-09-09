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

#include <atomic>
#include <memory>
#include <mutex>
#include <string>

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

namespace OHOS {
namespace Security {
namespace CertManager {
namespace {
constexpr int SA_ID_KEYSTORE_SERVICE = 3512;
constexpr int32_t LOAD_ABILITY_TIME_OUT_SECONDS = 3;
const std::u16string SA_KEYSTORE_SERVICE_DESCRIPTOR = u"ohos.security.cm.service";

/* SA -> client result dispatch command; must equal CM_UKEY_DIALOG_CALLBACK_CMD
 * in the SA-side dialog manager (cm_ukey_auth_dialog_manager.h) */
constexpr uint32_t CM_UKEY_DIALOG_CALLBACK_CMD = 1;

/* client-side fallback timer (> SA 5min total timeout): guards against SA death
 * leaving the caller's callback pending forever */
constexpr uint32_t CM_UKEY_DIALOG_CLIENT_FALLBACK_MS = 360000; /* 6 min */

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

static sptr<IRemoteObject> CmLoadSystemAbility(void)
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        CM_LOG_E("GetCmProxy registry is null");
        return {};
    }

    auto object = saManager->CheckSystemAbility(SA_ID_KEYSTORE_SERVICE);
    if (object != nullptr) {
        return object;
    }

    return saManager->LoadSystemAbility(SA_ID_KEYSTORE_SERVICE, LOAD_ABILITY_TIME_OUT_SECONDS);
}

/* Wire format (must match cm_sa.cpp OnRemoteRequest byte-for-byte):
 * [interfaceToken][uint32 size][paramSet blob][remote object (OPEN only)];
 * sync reply is a bare [int32 ret]. Dialog codes skip the outSize word. */
static int32_t SendDialogRequest(enum CertManagerInterfaceCode type, const struct CmBlob *parcelBlob,
    const sptr<IRemoteObject> &remoteObject, int32_t *replyCode)
{
    sptr<IRemoteObject> cmProxy = CmLoadSystemAbility();
    if (cmProxy == nullptr) {
        cmProxy = CmLoadSystemAbility();
    }

    if (cmProxy == nullptr) {
        CM_LOG_E("Certificate manager Proxy is null.");
        return CMR_ERROR_NULL_POINTER;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option = MessageOption::TF_SYNC;

    data.WriteInterfaceToken(SA_KEYSTORE_SERVICE_DESCRIPTOR);
    data.WriteUint32(parcelBlob->size);
    bool isWriteSuccess = data.WriteBuffer(parcelBlob->data, static_cast<size_t>(parcelBlob->size));
    if (!isWriteSuccess) {
        CM_LOG_E("WriteBuffer failed, size: %u", parcelBlob->size);
        isWriteSuccess = data.WriteRawData(parcelBlob->data, static_cast<size_t>(parcelBlob->size));
    }
    if (!isWriteSuccess) {
        CM_LOG_E("WriteBuffer and WriteRawData both failed, size: %u", parcelBlob->size);
        return CMR_ERROR_IPC_WRITE_FAIL;
    }
    if (remoteObject != nullptr && !data.WriteRemoteObject(remoteObject)) {
        CM_LOG_E("WriteRemoteObject failed");
        return CMR_ERROR_IPC_WRITE_FAIL;
    }

    int32_t error = cmProxy->SendRequest(static_cast<uint32_t>(type), data, reply, option);
    if (error != 0) {
        CM_LOG_E("SendRequest error:%d", error);
        return error;
    }
    *replyCode = reply.ReadInt32();
    return CM_SUCCESS;
}

int32_t CmClientOpenUkeyAuthDialog(const struct CmBlob *keyUri,
    CmUkeyAuthDialogResultCallback callback, void *userData)
{
    if (CmCheckBlob(keyUri) != CM_SUCCESS || callback == nullptr) {
        CM_LOG_E("invalid open ukey auth dialog arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    sptr<CmDialogCallbackStub> stub = new (std::nothrow) CmDialogCallbackStub(callback, userData);
    if (stub == nullptr) {
        CM_LOG_E("create ukey dialog callback stub failed");
        return CMR_ERROR_MALLOC_FAIL;
    }

    struct CmParamSet *sendParamSet = nullptr;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *keyUri },
    };

    int32_t ret = CmParamsToParamSet(params, CM_ARRAY_SIZE(params), &sendParamSet);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("open ukey dialog pack params failed, ret = %d", ret);
        return ret;
    }
    struct CmBlob parcelBlob = { sendParamSet->paramSetSize, reinterpret_cast<uint8_t *>(sendParamSet) };

    do {
        if (!stub->StartFallbackTimer()) {
            /* reject rather than leave a callback that can hang forever */
            CM_LOG_E("arm ukey dialog fallback timer failed");
            ret = CMR_DIALOG_ERROR_INTERNAL;
            break;
        }

        int32_t replyCode = CM_FAILURE;
        ret = SendDialogRequest(CM_MSG_OPEN_UKEY_AUTH_DIALOG, &parcelBlob, stub, &replyCode);
        if (ret != CM_SUCCESS || replyCode != CM_SUCCESS) {
            /* sync error: destroy the stub without invoking the callback (spec 4) */
            CM_LOG_E("open ukey auth dialog request failed, ret = %d, reply = %d", ret, replyCode);
            stub->Cancel();
            ret = (ret != CM_SUCCESS) ? ret : replyCode;
            break;
        }

        stub->HoldSelf(); /* stub manages its own lifetime until Deliver */
        CM_LOG_I("open ukey auth dialog request accepted");
    } while (0);

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
    ret = SendDialogRequest(CM_MSG_REPORT_UKEY_AUTH_RESULT, &parcelBlob, nullptr, &replyCode);
    CmFreeParamSet(&sendParamSet);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("report ukey auth result request failed, ret = %d", ret);
        return ret;
    }
    return replyCode; /* raw CMR_DIALOG_* code, SA routing passes it through */
}
