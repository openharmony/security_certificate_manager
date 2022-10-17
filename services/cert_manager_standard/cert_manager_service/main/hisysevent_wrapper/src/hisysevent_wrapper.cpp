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

static constexpr char CM_DOMAIN[] = "CERT_MANAGER";
static constexpr char CM_EVENT_NAME[] = "CERT_FAULT";
static constexpr char CM_TAG_FUNCTION[] = "FUNCTION";
static constexpr char CM_TAG_USER_ID[] = "USER_ID";
static constexpr char CM_TAG_UID[] = "UID";
static constexpr char CM_TAG_CERT_NAME[] = "CERT_NAME";
static constexpr char CM_TAG_ERROR_CODE[] = "ERROR_CODE";

int WriteEvent(const char *functionName, const struct EventValues *eventValues)
{
    int32_t ret = HiSysEventWrite(CM_DOMAIN, CM_EVENT_NAME, HiSysEvent::EventType::FAULT,
        CM_TAG_FUNCTION, functionName,
        CM_TAG_USER_ID, eventValues->userId,
        CM_TAG_UID, eventValues->uid,
        CM_TAG_CERT_NAME, eventValues->certName,
        CM_TAG_ERROR_CODE, eventValues->errorCode);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("WriteEvent failed!");
        return ret;
    }
    return ret;
}