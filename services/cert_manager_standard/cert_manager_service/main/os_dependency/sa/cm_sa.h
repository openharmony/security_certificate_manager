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

#ifndef CM_SA_H
#define CM_SA_H

#include "event_handler.h"
#include "event_runner.h"
#include "iremote_broker.h"
#include "iremote_stub.h"
#include "nocopyable.h"
#include "system_ability.h"

#include "cert_manager_service_ipc_interface_code.h"

namespace OHOS {
namespace Security {
namespace CertManager {
enum ServiceRunningState {
    STATE_NOT_START,
    STATE_RUNNING
};
enum ResponseCode {
    CM_SYSTEM_ERROR = -1,
};

constexpr int SA_ID_KEYSTORE_SERVICE = 3512;

class ICertManagerService : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.security.cm.service");
};

class CertManagerService : public SystemAbility, public IRemoteStub<ICertManagerService> {
    DECLEAR_SYSTEM_ABILITY(CertManagerService)

public:
    DISALLOW_COPY_AND_MOVE(CertManagerService);
    CertManagerService();
    virtual ~CertManagerService();

    void OnStart(const SystemAbilityOnDemandReason& startReason) override;
    void OnStop() override;
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    void DelayUnload();
    static CertManagerService& GetInstance();

protected:
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

private:
    bool Init();

    bool registerToService_;
    ServiceRunningState runningState_;
    std::shared_ptr<AppExecFwk::EventHandler> unloadHandler;
};
} // namespace CertManager
} // namespace Security
} // namespace OHOS

#endif // CM_SA_H
