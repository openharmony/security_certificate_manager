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


#include "hisysevent_wrapper.h"
#include "hisysevent.h"

#include "cm_log.h"

using namespace OHOS::HiviewDFX;

static constexpr char domain[] = "CERT_MANAGER";
static constexpr char g_eventName[] = "CERT_FAULT";
static constexpr char g_tagFunction[] = "FUNCTION";
static constexpr char g_tagUserId[] = "USER_ID";
static constexpr char g_tagUID[] = "UID";
static constexpr char g_tagCertName[] = "CERT_NAME";
static constexpr char g_tagErrorCode[] = "ERROR_CODE";

int WriteEvent(const char *functionName, const struct EventValues *eventValues)
{
    int32_t ret = HiSysEventWrite(domain, g_eventName, HiSysEvent::EventType::FAULT,
        g_tagFunction, functionName,
        g_tagUserId, eventValues->userId,
        g_tagUID, eventValues->uid,
        g_tagCertName, eventValues->certName,
        g_tagErrorCode, eventValues->errorCode);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("WriteEvent failed!");
        return ret;
    }
    return ret;
}