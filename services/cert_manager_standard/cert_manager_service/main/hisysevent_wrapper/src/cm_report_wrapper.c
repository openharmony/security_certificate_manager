/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "cm_type.h"
#include "hisysevent_wrapper.h"

static int32_t ReportFaultEvent(const char *funcName, const struct CmContext *cmContext,
    const char *name, int32_t errorCode)
{
    struct EventValues eventValues = { cmContext->userId, cmContext->uid, name, errorCode };
    return WriteEvent(funcName, &eventValues);
}

static bool CheckCertName(const struct CmBlob *certName)
{
    if (CmCheckBlob(certName) != CM_SUCCESS) {
        return false;
    }
    if (certName->size > MAX_LEN_URI) {
        return false;
    }

    for (uint32_t i = 1; i < certName->size; ++i) { /* from index 1 has '\0' */
        if (certName->data[i] == 0) {
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

    if (!CheckCertName(certName)) {
        (void)ReportFaultEvent(funcName, cmContext, "NULL", errorCode);
        return;
    }

    (void)ReportFaultEvent(funcName, cmContext, (char *)certName->data, errorCode);
}