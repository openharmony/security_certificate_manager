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

#ifndef CM_SECURITY_GUARD_REPORT_H
#define CM_SECURITY_GUARD_REPORT_H

#include "cm_type_inner.h"

#define CM_MAX_ACTION_LEN 100

struct CmReportSGInfo {
    char action[CM_MAX_ACTION_LEN];
    uint32_t uid;
    int32_t result;
    char *name;
    bool isSetGrantUid;
    uint32_t grantUid;
    bool isSetStatus;
    bool status;
};

struct SGEventContent {
    int32_t type;
    int32_t subType;
    char *caller;
    char *objectInfo;
    char *bootTime;
    char *wallTime;
    char *outcome;
    char *sourceInfo;
    char *targetInfo;
    char *extra;
};

#ifdef __cplusplus
extern "C" {
#endif

uint32_t CmGetCallingUid(void);

void CmReportSGRecord(const struct CmReportSGInfo *info);

#ifdef __cplusplus
}
#endif

#endif
