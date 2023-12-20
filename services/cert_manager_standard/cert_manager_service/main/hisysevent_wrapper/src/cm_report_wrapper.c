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

#include "cm_report_wrapper.h"

#include "cm_log.h"
#include "cm_type.h"

static int32_t ReportFaultEvent(const char *funcName, const struct CmContext *cmContext,
    const char *name, int32_t errorCode)
{
    struct EventValues eventValues = { cmContext->userId, cmContext->uid, name, errorCode };
    int32_t ret = WriteEvent(funcName, &eventValues);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("ReportFaultEvent failed, ret = %d", ret);
    }
    return ret;
}

static bool CheckCertName(const char *certName, uint32_t len)
{
    if ((len == 0) || (len > MAX_LEN_URI)) {
        return false;
    }

    for (uint32_t i = 1; i < len; ++i) { /* from index 1 has '\0' */
        if (certName[i] == 0) {
            return true;
        }
    }
    return false;
}

void CmReport(const char *funcName, const struct CmContext *cmContext,
    const struct CmBlob *certName, int32_t errorCode)
{
    if (errorCode == CM_SUCCESS) {
        return;
    }

    if ((certName == NULL) || (certName->data == NULL)) {
        (void)ReportFaultEvent(funcName, cmContext, "NULL", errorCode);
        return;
    }

    if (!CheckCertName((char *)certName->data, certName->size)) {
        CM_LOG_E("certName is invalid");
        return;
    }

    (void)ReportFaultEvent(funcName, cmContext, (char *)certName->data, errorCode);
}