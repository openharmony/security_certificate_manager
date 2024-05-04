/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "cm_sa.h"

#include <pthread.h>
#include <unistd.h>

#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"

#include "cert_manager.h"
#include "cm_event_observer.h"
#include "cm_event_process.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_ipc_service.h"
#include "ipc_skeleton.h"
#include "cert_manager_updateflag.h"

namespace OHOS {
namespace Security {
namespace CertManager {
const bool REGISTER_RESULT = SystemAbility::MakeAndRegisterAbility(&CertManagerService::GetInstance());

const uint32_t MAX_MALLOC_LEN = 1 * 1024 * 1024; /* max malloc size 1 MB */
const uint32_t MAX_DELAY_TIMES = 100;
const uint32_t DELAY_INTERVAL = 200000; /* delay 200ms waiting for system event */

const std::string TASK_ID = "unload";
const uint32_t DELAY_TIME = 180000; /* delay 180000ms to unload SA */
const std::string USER_REMOVED_EVENT = "usual.event.USER_REMOVED";

constexpr int CM_IPC_THREAD_NUM = 32;

using CmIpcHandlerFuncProc = void (*)(const struct CmBlob *msg, const CmContext *context);

using CmIpcAppHandlerFuncProc = void (*)(const struct CmBlob *msg, struct CmBlob *outData,
    const CmContext *context);

struct CmIpcPoint {
    CertManagerInterfaceCode msgId;
    CmIpcAppHandlerFuncProc handler;
};

static struct CmIpcPoint g_cmIpcHandler[] = {
    { CM_MSG_INSTALL_APP_CERTIFICATE, CmIpcServiceInstallAppCert },
    { CM_MSG_UNINSTALL_APP_CERTIFICATE, CmIpcServiceUninstallAppCert },
    { CM_MSG_UNINSTALL_ALL_APP_CERTIFICATE, CmIpcServiceUninstallAllAppCert },
    { CM_MSG_GET_APP_CERTIFICATE_LIST, CmIpcServiceGetAppCertList },
    { CM_MSG_GET_APP_CERTIFICATE, CmIpcServiceGetAppCert },

    { CM_MSG_GRANT_APP_CERT, CmIpcServiceGrantAppCertificate },
    { CM_MSG_GET_AUTHED_LIST, CmIpcServiceGetAuthorizedAppList },
    { CM_MSG_CHECK_IS_AUTHED_APP, CmIpcServiceIsAuthorizedApp },
    { CM_MSG_REMOVE_GRANT_APP, CmIpcServiceRemoveGrantedApp },
    { CM_MSG_INIT, CmIpcServiceInit },
    { CM_MSG_UPDATE, CmIpcServiceUpdate },
    { CM_MSG_FINISH, CmIpcServiceFinish },
    { CM_MSG_ABORT, CmIpcServiceAbort },

    { CM_MSG_GET_USER_CERTIFICATE_LIST, CmIpcServiceGetUserCertList },
    { CM_MSG_GET_USER_CERTIFICATE_INFO, CmIpcServiceGetUserCertInfo },
    { CM_MSG_SET_USER_CERTIFICATE_STATUS, CmIpcServiceSetUserCertStatus },
    { CM_MSG_INSTALL_USER_CERTIFICATE, CmIpcServiceInstallUserCert },
    { CM_MSG_UNINSTALL_USER_CERTIFICATE, CmIpcServiceUninstallUserCert },
    { CM_MSG_UNINSTALL_ALL_USER_CERTIFICATE, CmIpcServiceUninstallAllUserCert },

    { CM_MSG_GET_CERTIFICATE_LIST, CmIpcServiceGetCertificateList },
    { CM_MSG_GET_CERTIFICATE_INFO, CmIpcServiceGetCertificateInfo },
    { CM_MSG_SET_CERTIFICATE_STATUS, CmIpcServiceSetCertStatus },
};

static void SubscribEvent()
{
    for (uint32_t i = 0; i < MAX_DELAY_TIMES; ++i) {
        if (SystemEventObserver::SubscribeSystemEvent()) {
            CM_LOG_D("subscribe system event success, i = %u", i);
            return;
        } else {
            CM_LOG_E("subscribe system event failed %u times", i);
            usleep(DELAY_INTERVAL);
        }
    }
    CM_LOG_E("subscribe system event failed");
    return;
}

static void CmSubscribeSystemEvent()
{
    pthread_t subscribeThread;
    if ((pthread_create(&subscribeThread, nullptr, (void *(*)(void *))SubscribEvent, nullptr)) == -1) {
        CM_LOG_E("create thread failed");
        return;
    }

    CM_LOG_D("create thread success");
}

static inline bool IsInvalidLength(uint32_t length)
{
    return (length == 0) || (length > MAX_MALLOC_LEN);
}

static int32_t ProcessMessage(uint32_t code, uint32_t outSize, const struct CmBlob &srcData, MessageParcel &reply)
{
    uint32_t size = sizeof(g_cmIpcHandler) / sizeof(g_cmIpcHandler[0]);
    for (uint32_t i = 0; i < size; ++i) {
        if (code != static_cast<uint32_t>(g_cmIpcHandler[i].msgId)) {
            continue;
        }
        struct CmBlob outData = { 0, nullptr };
        if (outSize != 0) {
            outData.size = outSize;
            if (outData.size > MAX_MALLOC_LEN) {
                CM_LOG_E("outData size is invalid, size:%u", outData.size);
                return CM_SYSTEM_ERROR;
            }
            outData.data = static_cast<uint8_t *>(CmMalloc(outData.size));
            if (outData.data == nullptr) {
                CM_LOG_E("Malloc outData failed.");
                return CM_SYSTEM_ERROR;
            }
            (void)memset_s(outData.data, outData.size, 0, outData.size);
        }
        g_cmIpcHandler[i].handler(static_cast<const struct CmBlob *>(&srcData), &outData,
            reinterpret_cast<const struct CmContext *>(&reply));
        CM_FREE_BLOB(outData);
        break;
    }

    return NO_ERROR;
}

CertManagerService::CertManagerService()
    : SystemAbility(SA_ID_KEYSTORE_SERVICE, true), registerToService_(false), runningState_(STATE_NOT_START)
{
    CM_LOG_D("CertManagerService");
}

CertManagerService::~CertManagerService()
{
    CM_LOG_D("~CertManagerService");
}

bool CertManagerService::Init()
{
    CM_LOG_D("CertManagerService::Init Ready to init");

    if (!registerToService_) {
        if (unloadHandler == nullptr) {
            auto runner = AppExecFwk::EventRunner::Create("unload");
            unloadHandler = std::make_shared<AppExecFwk::EventHandler>(runner);
        }

        DelayUnload();
        if (!Publish(this)) {
            CM_LOG_E("CertManagerService::Init Publish Failed");
            return false;
        }
        CM_LOG_D("CertManagerService::Init Publish service success");
        registerToService_ = true;
    }

    CM_LOG_D("CertManagerService::Init success.");
    return true;
}

int CertManagerService::OnRemoteRequest(uint32_t code, MessageParcel &data,
    MessageParcel &reply, MessageOption &option)
{
    // this is the temporary version which comments the descriptor check
    std::u16string descriptor = CertManagerService::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        CM_LOG_E("descriptor is diff");
        return CM_SYSTEM_ERROR;
    }

    // check the code is valid
    if (code < static_cast<uint32_t>(CM_MSG_BASE) || code >= static_cast<uint32_t>(CM_MSG_MAX)) {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    DelayUnload();
    uint32_t outSize = static_cast<uint32_t>(data.ReadUint32());
    struct CmBlob srcData = { 0, nullptr };
    srcData.size = static_cast<uint32_t>(data.ReadUint32());
    if (IsInvalidLength(srcData.size)) {
        CM_LOG_E("srcData size is invalid, size:%u", srcData.size);
        return CM_SYSTEM_ERROR;
    }

    srcData.data = static_cast<uint8_t *>(CmMalloc(srcData.size));
    if (srcData.data == nullptr) {
        CM_LOG_E("Malloc srcData failed.");
        return CM_SYSTEM_ERROR;
    }
    const uint8_t *pdata = data.ReadBuffer(static_cast<size_t>(srcData.size));
    if (pdata == nullptr) {
        CM_FREE_BLOB(srcData);
        CM_LOG_E("CMR_ERROR_NULL_POINTER");
        return CMR_ERROR_NULL_POINTER;
    }
    if (memcpy_s(srcData.data, srcData.size, pdata, srcData.size) != EOK) {
        CM_LOG_E("copy remote data failed!");
        CM_FREE_BLOB(srcData);
        return CMR_ERROR_INVALID_OPERATION;
    }
    if (ProcessMessage(code, outSize, srcData, reply) != NO_ERROR) {
        CM_LOG_E("process message!");
        CM_FREE_BLOB(srcData);
        CM_LOG_E("copy remote data failed!");
        return CMR_ERROR_INVALID_OPERATION;
    }
    CM_FREE_BLOB(srcData);
    return NO_ERROR;
}

void CertManagerService::OnStart(const SystemAbilityOnDemandReason& startReason)
{
    CM_LOG_D("CertManagerService OnStart startReason");

    if (runningState_ == STATE_RUNNING) {
        CM_LOG_D("CertManagerService has already Started");
        return;
    }

    if (CertManagerInitialize() != CMR_OK) {
        CM_LOG_E("Failed to init CertManagerService");
        return;
    }
    CM_LOG_D("CertManager init success");

    if (!Init()) {
        CM_LOG_E("Failed to init CertManagerService");
        return;
    }

    CM_LOG_D("certmanager start reason %s", startReason.GetName().c_str());
    if (startReason.GetId() == OnDemandReasonId::COMMON_EVENT &&
        startReason.GetName() == USER_REMOVED_EVENT) {
        struct CmContext context = { 0, INVALID_VALUE, {0} };
        context.userId = (uint32_t)startReason.GetExtraData().GetCode();
        CM_LOG_D("user remove event, userId = %u", context.userId);
        CmDeleteProcessInfo(&context);
    }

    IPCSkeleton::SetMaxWorkThreadNum(CM_IPC_THREAD_NUM);
    (void)AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);

    runningState_ = STATE_RUNNING;
    CM_LOG_D("CertManagerService start success.");

    (void)CmBackupAllSaUserCerts();
}

void CertManagerService::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    CM_LOG_D("systemAbilityId is %d!", systemAbilityId);
    CmSubscribeSystemEvent();
}

void CertManagerService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    CM_LOG_D("systemAbilityId is %d!", systemAbilityId);
}

void CertManagerService::OnStop()
{
    CM_LOG_D("CertManagerService Service OnStop");
    runningState_ = STATE_NOT_START;
    registerToService_ = false;
}

void CertManagerService::DelayUnload()
{
    auto unloadTask = []() {
        CM_LOG_D("do unload task");
        auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (saManager == nullptr) {
            CM_LOG_E("Failed to get saManager");
            return;
        }

        int32_t ret = saManager->UnloadSystemAbility(SA_ID_KEYSTORE_SERVICE);
        if (ret != ERR_OK) {
            CM_LOG_E("Failed to remove system ability");
            return;
        }
    };

    unloadHandler->RemoveTask(TASK_ID);
    unloadHandler->PostTask(unloadTask, TASK_ID, DELAY_TIME);
}

CertManagerService& CertManagerService::GetInstance()
{
    static auto instance = new CertManagerService();
    return *instance;
}
} // namespace CertManager
} // namespace Security
} // namespace OHOS
