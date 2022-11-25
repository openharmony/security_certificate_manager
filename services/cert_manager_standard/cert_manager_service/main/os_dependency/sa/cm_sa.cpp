/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_ipc_service.h"

namespace OHOS {
namespace Security {
namespace CertManager {
REGISTER_SYSTEM_ABILITY_BY_ID(CertManagerService, SA_ID_KEYSTORE_SERVICE, true);

std::mutex CertManagerService::instanceLock;
sptr<CertManagerService> CertManagerService::instance;
const uint32_t MAX_MALLOC_LEN = 1 * 1024 * 1024; /* max malloc size 1 MB */
const uint32_t MAX_DELAY_TIMES = 100;
const uint32_t DELAY_INTERVAL = 200000; /* delay 200ms waiting for system event */

using CmIpcHandlerFuncProc = void (*)(const struct CmBlob *msg, const CmContext *context);

using CmIpcAppHandlerFuncProc = void (*)(const struct CmBlob *msg, struct CmBlob *outData,
    const CmContext *context);

struct CmIpcPoint {
    enum CmMessage msgId;
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
            CM_LOG_I("subscribe system event success, i = %u", i);
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

    CM_LOG_I("create thread success");
}

static inline bool IsInvalidLength(uint32_t length)
{
    return (length == 0) || (length > MAX_MALLOC_LEN);
}

static int32_t ProcessMessage(uint32_t code, uint32_t outSize, const struct CmBlob &srcData, MessageParcel &reply)
{
    uint32_t size = sizeof(g_cmIpcHandler) / sizeof(g_cmIpcHandler[0]);
    for (uint32_t i = 0; i < size; ++i) {
        if (code != g_cmIpcHandler[i].msgId) {
            continue;
        }
        struct CmBlob outData = { 0, nullptr };
        if (outSize != 0) {
            outData.size = outSize;
            if (outData.size > MAX_MALLOC_LEN) {
                CM_LOG_E("outData size is invalid, size:%u", outData.size);
                return HW_SYSTEM_ERROR;
            }
            outData.data = static_cast<uint8_t *>(CmMalloc(outData.size));
            if (outData.data == nullptr) {
                CM_LOG_E("Malloc outData failed.");
                return HW_SYSTEM_ERROR;
            }
        }
        g_cmIpcHandler[i].handler(static_cast<const struct CmBlob *>(&srcData), &outData,
            reinterpret_cast<const struct CmContext *>(&reply));
        CM_FREE_BLOB(outData);
        break;
    }

    return NO_ERROR;
}

CertManagerService::CertManagerService(int saId, bool runOnCreate = true)
    : SystemAbility(saId, runOnCreate), registerToService_(false), runningState_(STATE_NOT_START)
{
    CM_LOG_D("CertManagerService");
}

CertManagerService::~CertManagerService()
{
    CM_LOG_D("~CertManagerService");
}

sptr<CertManagerService> CertManagerService::GetInstance()
{
    std::lock_guard<std::mutex> autoLock(instanceLock);
    if (instance == nullptr) {
        instance = new (std::nothrow) CertManagerService(SA_ID_KEYSTORE_SERVICE, true);
    }

    return instance;
}

bool CertManagerService::Init()
{
    CM_LOG_I("CertManagerService::Init Ready to init");

    if (!registerToService_) {
        sptr<CertManagerService> ptrInstance = CertManagerService::GetInstance();
        if (ptrInstance == nullptr) {
            CM_LOG_E("CertManagerService::Init GetInstance Failed");
            return false;
        }
        if (!Publish(ptrInstance)) {
            CM_LOG_E("CertManagerService::Init Publish Failed");
            return false;
        }
        CM_LOG_I("CertManagerService::Init Publish service success");
        registerToService_ = true;
    }

    CM_LOG_I("CertManagerService::Init success.");
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
        return HW_SYSTEM_ERROR;
    }

    CM_LOG_I("OnRemoteRequest code:%u", code);
    // check the code is valid
    if (code < MSG_CODE_BASE || code >= MSG_CODE_MAX) {
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    uint32_t outSize = static_cast<uint32_t>(data.ReadUint32());
    struct CmBlob srcData = { 0, nullptr };
    srcData.size = static_cast<uint32_t>(data.ReadUint32());
    if (IsInvalidLength(srcData.size)) {
        CM_LOG_E("srcData size is invalid, size:%u", srcData.size);
        return HW_SYSTEM_ERROR;
    }

    srcData.data = static_cast<uint8_t *>(CmMalloc(srcData.size));
    if (srcData.data == nullptr) {
        CM_LOG_E("Malloc srcData failed.");
        return HW_SYSTEM_ERROR;
    }
    const uint8_t *pdata = data.ReadBuffer(static_cast<size_t>(srcData.size));
    if (pdata == nullptr) {
        CM_FREE_BLOB(srcData);
        CM_LOG_I("CMR_ERROR_NULL_POINTER");
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
    CM_LOG_I("OnRemoteRequest: %d", NO_ERROR);
    CM_FREE_BLOB(srcData);
    return NO_ERROR;
}

void CertManagerService::OnStart()
{
    CM_LOG_I("CertManagerService OnStart");

    if (runningState_ == STATE_RUNNING) {
        CM_LOG_I("CertManagerService has already Started");
        return;
    }

    if (!Init()) {
        CM_LOG_E("Failed to init CertManagerService");
        return;
    }

    if (CertManagerInitialize() != CMR_OK) {
        CM_LOG_E("Failed to init CertManagerService");
        return;
    }

    (void)AddSystemAbilityListener(COMMON_EVENT_SERVICE_ID);

    runningState_ = STATE_RUNNING;
    CM_LOG_I("CertManagerService start success.");
}

void CertManagerService::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    CM_LOG_I("systemAbilityId is %d!", systemAbilityId);
    CmSubscribeSystemEvent();
}

void CertManagerService::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    CM_LOG_I("systemAbilityId is %d!", systemAbilityId);
}

void CertManagerService::OnStop()
{
    CM_LOG_I("CertManagerService Service OnStop");
    runningState_ = STATE_NOT_START;
    registerToService_ = false;
}
} // namespace CertManager
} // namespace Security
} // namespace OHOS
