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

#include "cm_event_observer.h"

#include "bundle_constants.h"
#include "common_event_support.h"
#include "os_account_manager.h"
#include "cm_event_process.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace CertManager {
std::shared_ptr<SystemEventSubscriber> SystemEventObserver::systemEventSubscriber_ = nullptr;

SystemEventSubscriber::SystemEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &subscriberInfo)
    : OHOS::EventFwk::CommonEventSubscriber(subscriberInfo)
{
}

void SystemEventSubscriber::OnReceiveEvent(const OHOS::EventFwk::CommonEventData &data)
{
    CM_LOG_I("SystemEventSubscriber::OnReceiveEvent");

    struct CmContext context;
    context.uid = INVALID_VALUE;
    auto want = data.GetWant();
    std::string action = want.GetAction();
    if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED ||
        action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED) {
        context.uid = static_cast<uint32_t>(want.GetIntParam(AppExecFwk::Constants::UID, -1));
        int userId = 0;
        OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(context.uid, userId);
        context.userId = static_cast<uint32_t>(userId);
        CM_LOG_I("CmService package removed: uid is %u userId is %u", context.uid, context.userId);
        CmDeleteProcessInfo(&context);
    } else if (action == OHOS::EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        context.userId = static_cast<uint32_t>(data.GetCode());
        CM_LOG_I("CmService user removed: userId is %d", context.userId);
        CmDeleteProcessInfo(&context);
    }
}

SystemEventObserver::~SystemEventObserver()
{
    if (systemEventSubscriber_ != nullptr) {
        UnSubscribeSystemEvent();
    }
}

bool SystemEventObserver::SubscribeSystemEvent()
{
    OHOS::EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    OHOS::EventFwk::CommonEventSubscribeInfo subscriberInfo(matchingSkills);
    systemEventSubscriber_ = std::make_shared<SystemEventSubscriber>(subscriberInfo);

    return OHOS::EventFwk::CommonEventManager::SubscribeCommonEvent(systemEventSubscriber_);
}

bool SystemEventObserver::UnSubscribeSystemEvent()
{
    if (systemEventSubscriber_ == nullptr) {
        CM_LOG_E("Cm system subscriber nullptr");
        return false;
    }
    return OHOS::EventFwk::CommonEventManager::UnSubscribeCommonEvent(systemEventSubscriber_);
}
} // namespace Cm
} // namespace Security
} // namespace OHOS
