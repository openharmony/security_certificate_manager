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

#include "cm_security_guard_info.h"

#include "cm_log.h"
#include "cm_mem.h"
#include "cm_security_guard_report.h"

#ifdef SUPPORT_SECURITY_GUARD
#define CM_INVALID_NAME "nameInvalid"
#define CM_DELETE_ALL_NAME "deleteAll"
#define CM_REPORT_MAX_NAME_LEN 256

static bool IsNameValid(const struct CmBlob *name)
{
    if ((CmCheckBlob(name) != CM_SUCCESS) || (name->size >= CM_REPORT_MAX_NAME_LEN)) {
        return false;
    }

    for (uint32_t i = 1; i < name->size; ++i) { /* from index 1 has '\0' */
        if (name->data[i] == 0) {
            return true;
        }
    }
    return false;
}

#define ANONYMOUS_LEN 4

static void AnonymousName(char *name, uint32_t nameLen)
{
    char p = '*';
    uint32_t offset = strlen("o=");
    char *substr = strstr(name, "o=");
    if (substr == NULL || strlen(substr) == offset) {
        if (nameLen <= ANONYMOUS_LEN) {
            (void)memset_s(name, nameLen, p, nameLen);
        } else {
            (void)memset_s(name + nameLen - ANONYMOUS_LEN, ANONYMOUS_LEN, p, ANONYMOUS_LEN);
        }
        return;
    }

    uint32_t substrLen = strlen(substr);
    if (substrLen <= ANONYMOUS_LEN + offset) {
        (void)memset_s(substr + offset, substrLen - offset, p, substrLen - offset);
    } else {
        (void)memset_s(substr + offset, ANONYMOUS_LEN, p, ANONYMOUS_LEN);
    }
}

static int32_t ConstructInfoName(const struct CmBlob *input, char **name)
{
    bool isNameValid = IsNameValid(input);
    uint32_t nameLen = isNameValid ? input->size : strlen(CM_INVALID_NAME) + 1;
    *name = (char *)CmMalloc(nameLen);
    if (*name == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(*name, nameLen, 0, nameLen); /* initialized to 0 to avoid that input does not end with '\0' */
    (void)strcpy_s(*name, nameLen, isNameValid ? (char *)input->data : CM_INVALID_NAME);

    if (isNameValid) {
        AnonymousName(*name, nameLen - 1); /* nameLen is bigger than 1 and exclude end '\0' */
    }
    return CM_SUCCESS;
}

static void ConstructInfoAndReport(const struct CmBlob *input, const char *action, struct CmReportSGInfo *info)
{
    if (strcpy_s(info->action, sizeof(info->action), action) != EOK) {
        return;
    }
    if (ConstructInfoName(input, &info->name) != CM_SUCCESS) {
        return;
    }
    CmReportSGRecord(info);
    CM_FREE_PTR(info->name);
}
#endif

void CmReportSGSetCertStatus(const struct CmBlob *certUri, uint32_t store, uint32_t status, int32_t result)
{
#ifdef SUPPORT_SECURITY_GUARD
    struct CmReportSGInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));

    info.result = result;
    info.uid = CmGetCallingUid();
    info.isSetGrantUid = false;
    info.isSetStatus = true;
    info.status = (status == 0) ? true : false; /* 0 indicates the certificate enabled status */

    char *action = (store == CM_SYSTEM_TRUSTED_STORE) ? "CmSetSystemCertStatus" : "CmSetUserCertStatus";
    ConstructInfoAndReport(certUri, action, &info);
#else
    (void)certUri;
    (void)store;
    (void)status;
    (void)result;
#endif
}

void CmReportSGInstallUserCert(const struct CmBlob *certAlias, int32_t result)
{
#ifdef SUPPORT_SECURITY_GUARD
    struct CmReportSGInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));

    info.result = result;
    info.uid = CmGetCallingUid();
    info.isSetGrantUid = false;
    info.isSetStatus = false;

    char *action = "CmInstallUserCert";
    ConstructInfoAndReport(certAlias, action, &info);
#else
    (void)certAlias;
    (void)result;
#endif
}

void CmReportSGUninstallUserCert(const struct CmBlob *certUri, bool isUninstallAll, int32_t result)
{
#ifdef SUPPORT_SECURITY_GUARD
    struct CmReportSGInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));

    info.result = result;
    info.uid = CmGetCallingUid();
    info.isSetGrantUid = false;
    info.isSetStatus = false;

    if (isUninstallAll) {
        if (strcpy_s(info.action, sizeof(info.action), "CmUninstallAllUserCert") != EOK) {
            return;
        }
        info.name = CM_DELETE_ALL_NAME;
        return CmReportSGRecord(&info);
    }

    char *action = "CmUninstallUserCert";
    ConstructInfoAndReport(certUri, action, &info);
#else
    (void)certUri;
    (void)isUninstallAll;
    (void)result;
#endif
}

void CmReportSGInstallAppCert(const struct CmBlob *certAlias, uint32_t store, int32_t result)
{
#ifdef SUPPORT_SECURITY_GUARD
    struct CmReportSGInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));

    info.result = result;
    info.uid = CmGetCallingUid();
    info.isSetGrantUid = false;
    info.isSetStatus = false;

    char *action = (store == CM_CREDENTIAL_STORE) ? "CmInstallAppCert" : "CmInstallPriAppCert";
    ConstructInfoAndReport(certAlias, action, &info);
#else
    (void)certAlias;
    (void)store;
    (void)result;
#endif
}

void CmReportSGUninstallAppCert(const struct CmBlob *keyUri, uint32_t store, bool isUninstallAll, int32_t result)
{
#ifdef SUPPORT_SECURITY_GUARD
    struct CmReportSGInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));

    info.result = result;
    info.uid = CmGetCallingUid();
    info.isSetGrantUid = false;
    info.isSetStatus = false;

    if (isUninstallAll) {
        if (strcpy_s(info.action, sizeof(info.action), "CmUninstallAllAppCert") != EOK) {
            return;
        }
        info.name = CM_DELETE_ALL_NAME;
        return CmReportSGRecord(&info);
    }

    char *action = (store == CM_CREDENTIAL_STORE) ? "CmUninstallAppCert" : "CmUninstallPriAppCert";
    ConstructInfoAndReport(keyUri, action, &info);
#else
    (void)keyUri;
    (void)store;
    (void)isUninstallAll;
    (void)result;
#endif
}

void CmReportSGGrantAppCert(const struct CmBlob *keyUri, uint32_t appUid, bool isRemove, int32_t result)
{
#ifdef SUPPORT_SECURITY_GUARD
    struct CmReportSGInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));

    info.result = result;
    info.uid = CmGetCallingUid();
    info.isSetStatus = false;
    info.isSetGrantUid = true;
    info.grantUid = appUid;

    char *action = isRemove ? "CmRemoveGrantedAppUid" : "CmGrantAppCert";
    ConstructInfoAndReport(keyUri, action, &info);
#else
    (void)keyUri;
    (void)appUid;
    (void)isRemove;
    (void)result;
#endif
}
