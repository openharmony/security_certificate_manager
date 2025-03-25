/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "accesstoken_kit.h"
#include "hap_token_info.h"

#define CM_INFO_JSON_MAX_LEN 512
#define SG_JSON_MAX_LEN 1024
#define CERT_EVENTID 1011015014
#define CERT_VERSION "1.0"
#define CALLER_NAME_MAX_SIZE 128

using namespace OHOS::Security::SecurityGuard;
using namespace OHOS;
using namespace OHOS::Security::AccessToken;

const std::string CALLER_UID_NAME = "ipc_calling_uid: ";

uint32_t CmGetCallingUid(void)
{
    return OHOS::IPCSkeleton::GetCallingUid();
}

void InfoToJson(const struct CmReportSGInfo *info, char *json, int32_t jsonLen)
{
    char subjectName[MAX_LEN_SUBJECT_NAME] = {0};
    if (info->subjectName == nullptr) {
        subjectName[0] = '\0';
    } else {
        if (strncpy_s(subjectName, MAX_LEN_SUBJECT_NAME, info->subjectName, strlen(info->subjectName)) != EOK) {
            CM_LOG_E("Failed to copy subject name");
            return;
        }
    }

    int32_t ret = snprintf_s(
        json, jsonLen, jsonLen - 1,
        "{\\\"action\\\":\\\"%s\\\", \\\"uid\\\":%u, \\\"result\\\":%d, \\\"name\\\":\\\"%s\\\", "
        "\\\"subjectName\\\":\\\"%s\\\", \\\"isSetGrantUid\\\":%d, \\\"grantUid\\\":%u, "
        "\\\"isSetStatus\\\":%d, \\\"status\\\":%d}",
        info->action, info->uid, info->result, info->name, subjectName,
        info->isSetGrantUid ? 1 : 0, info->grantUid, info->isSetStatus ? 1 : 0, info->status ? 1 : 0);
    if (ret < 0) {
        CM_LOG_E("info to json error");
    }
}

static int32_t GetCallerBundleName(char *callerName, uint32_t callerNameSize)
{
    std::string caller = "";
    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (AccessTokenKit::GetTokenType(callingTokenId) != ATokenTypeEnum::TOKEN_HAP) {
        int32_t uid = IPCSkeleton::GetCallingUid();
        caller += CALLER_UID_NAME;
        caller += std::to_string(uid);
    } else {
        HapTokenInfo hapTokenInfo;
        int32_t ret = AccessTokenKit::GetHapTokenInfo(callingTokenId, hapTokenInfo);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get hap info from access token kit.");
            return CM_FAILURE;
        }
        caller += hapTokenInfo.bundleName;
    }

    if (strncpy_s(callerName, callerNameSize, caller.c_str(), caller.size() + 1) != EOK) {
        CM_LOG_E("Failed to copy caller");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    return CM_SUCCESS;
}

void CmFillSGRecord(char *objectInfoJson, char *recordJson, int32_t recordJsonLen)
{
    struct SGEventContent content;
    (void)memset_s(&content, sizeof(content), 0, sizeof(content));
    char callerName[CALLER_NAME_MAX_SIZE] = { 0 };
    int32_t ret = GetCallerBundleName(callerName, CALLER_NAME_MAX_SIZE);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get caller bundle name");
        return;
    }

    char constant[] = "";
    content.type = 0;
    content.subType = 0;
    content.caller = callerName;
    content.objectInfo = objectInfoJson;
    content.bootTime = constant;
    content.wallTime = constant;
    content.outcome = constant;
    content.sourceInfo = constant;
    content.targetInfo = constant;
    content.extra = constant;
    ret = snprintf_s(recordJson, recordJsonLen, recordJsonLen - 1, "{\"type\":%d, \"subType\":%d,"
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
    int32_t jsonLen = CM_INFO_JSON_MAX_LEN;
    if (info->subjectName != NULL) {
        jsonLen += strlen(info->subjectName);
    }

    char *objectJson = static_cast<char *>(CmMalloc(jsonLen));
    if (objectJson == NULL) {
        CM_LOG_E("objectJson malloc error");
        return;
    }
    (void)memset_s(objectJson, jsonLen, 0, jsonLen);
    InfoToJson(info, objectJson, jsonLen);

    int32_t recordJsonLen = jsonLen > SG_JSON_MAX_LEN ? jsonLen : SG_JSON_MAX_LEN;
    char *recordJson = static_cast<char *>(CmMalloc(recordJsonLen));
    if (recordJson == NULL) {
        CM_FREE_PTR(objectJson);
        CM_LOG_E("recordJson malloc error");
        return;
    }

    (void)memset_s(recordJson, recordJsonLen, 0, recordJsonLen);
    CmFillSGRecord(objectJson, recordJson, recordJsonLen);
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