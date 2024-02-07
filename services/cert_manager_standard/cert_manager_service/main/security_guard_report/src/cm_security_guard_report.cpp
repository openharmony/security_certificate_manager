/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "cm_security_guard_report.h"

#include "cm_log.h"
#include "cm_mem.h"

#include "ipc_skeleton.h"

#ifdef SUPPORT_SECURITY_GUARD

#include "event_info.h"
#include "sg_collect_client.h"

#define CM_INFO_JSON_MAX_LEN 512
#define SG_JSON_MAX_LEN 1024
#define CERT_EVENTID 1011015014
#define CERT_VERSION "1.0"

using namespace OHOS::Security::SecurityGuard;

uint32_t CmGetCallingUid(void)
{
    return OHOS::IPCSkeleton::GetCallingUid();
}

void InfoToJson(const struct CmReportSGInfo *info, char *json, int32_t jsonLen)
{
    int32_t ret = snprintf_s(json, jsonLen, jsonLen - 1, "{\\\"action\\\":\\\"%s\\\", \\\"uid\\\":%u, "
        "\\\"result\\\":%d, \\\"name\\\":\\\"%s\\\", \\\"isSetGrantUid\\\":%d, \\\"grantUid\\\":%u,"
        "\\\"isSetStatus\\\":%d, \\\"status\\\":%d}", info->action, info->uid, info->result, info->name,
        info->isSetGrantUid ? 1 : 0, info->grantUid, info->isSetStatus ? 1 : 0, info->status ? 1 : 0);
    if (ret < 0) {
        CM_LOG_E("info to json error");
    }
}

void CmFillSGRecord(char *objectInfoJson, char *recordJson, int32_t recordJsonLen)
{
    struct SGEventContent content;
    (void)memset_s(&content, sizeof(content), 0, sizeof(content));
    char constant[] = "";
    content.type = 0;
    content.subType = 0;
    content.caller = constant;
    content.objectInfo = objectInfoJson;
    content.bootTime = constant;
    content.wallTime = constant;
    content.outcome = constant;
    content.sourceInfo = constant;
    content.targetInfo = constant;
    content.extra = constant;
    int32_t ret = snprintf_s(recordJson, recordJsonLen, recordJsonLen - 1, "{\"type\":%d, \"subType\":%d,"
        "\"caller\":\"%s\", \"objectInfo\":\"%s\", \"bootTime\":\"%s\", \"wallTime\":\"%s\", \"outcome\":\"%s\", "
        "\"sourceInfo\":\"%s\", \"targetInfo\":\"%s\", \"extra\":\"%s\"}", content.type, content.subType,
        content.caller, content.objectInfo, content.bootTime, content.wallTime, content.outcome, content.sourceInfo,
        content.targetInfo, content.extra);
    if (ret < 0) {
        CM_LOG_E("fill SG record error");
    }
}

void CmReportSGRecord(const struct CmReportSGInfo *info)
{
    char *objectJson = static_cast<char *>(CmMalloc(CM_INFO_JSON_MAX_LEN));
    if (objectJson == NULL) {
        CM_LOG_E("objectJson malloc error");
        return;
    }
    (void)memset_s(objectJson, CM_INFO_JSON_MAX_LEN, 0, CM_INFO_JSON_MAX_LEN);
    InfoToJson(info, objectJson, CM_INFO_JSON_MAX_LEN);

    char *recordJson = static_cast<char *>(CmMalloc(SG_JSON_MAX_LEN));
    if (recordJson == NULL) {
        CM_FREE_PTR(objectJson);
        CM_LOG_E("recordJson malloc error");
        return;
    }
    (void)memset_s(recordJson, SG_JSON_MAX_LEN, 0, SG_JSON_MAX_LEN);
    CmFillSGRecord(objectJson, recordJson, SG_JSON_MAX_LEN);
    CM_FREE_PTR(objectJson);
    std::shared_ptr<EventInfo> eventInfo = std::make_shared<EventInfo>(CERT_EVENTID, CERT_VERSION, recordJson);
    int32_t ret = NativeDataCollectKit::ReportSecurityInfo(eventInfo);
    if (ret != 0) {
        CM_LOG_E("report security info error");
    }
    CM_FREE_PTR(recordJson);
    return;
}
#endif