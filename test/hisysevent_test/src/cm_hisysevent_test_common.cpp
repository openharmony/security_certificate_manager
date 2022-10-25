/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cm_hisysevent_test_common.h"

#include <cstdio>
#include <sys/time.h>
#include <unistd.h>

#include "hisysevent_manager.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"

using namespace std;

static const int MAX_QUERY_EVENT_COUNT = 1000;
static const int TIME_S_TO_MS = 1000;
static const int TIME_MS_TO_US = 1000;
static const int SLEEP_TIME = 2; /* 2 second */

static long long int g_beginTime = 0;
static long long int g_endTime = 0;
static volatile  bool g_queryResult = false;
static string g_queryStr;

namespace OHOS {
namespace HiviewDFX {
class CmHiSysEventCallBack : public OHOS::HiviewDFX::HiSysEventQueryCallback {
public:
    CmHiSysEventCallBack() {}
    virtual ~CmHiSysEventCallBack() {}
    void OnQuery(std::shared_ptr<std::vector<HiSysEventRecord>> sysEvents);
    void OnComplete(int32_t reason, int32_t total);
};

void CmHiSysEventCallBack::OnQuery(std::shared_ptr<std::vector<HiSysEventRecord>> sysEvents)
{
    if (g_queryStr.size() == 0 || sysEvents == nullptr) {
        return;
    }
    for_each((*sysEvents).cbegin(), (*sysEvents).cend(), [](const HiSysEventRecord& tmp) {
        string::size_type idx = tmp.AsJson().find(g_queryStr);
        if (idx != string::npos) {
            g_queryResult = true;
        }
    });
    return;
}

void CmHiSysEventCallBack::OnComplete(int32_t reason, int32_t total)
{
    return;
}
} // namespace HiviewDFX
} // namespace OHOS

using namespace OHOS::HiviewDFX;

static long long int GetCurrentTime(void)
{
    struct timeval tv;
    (void)gettimeofday(&tv, nullptr);
    long long int timeStamp = tv.tv_sec * TIME_S_TO_MS + tv.tv_usec / TIME_MS_TO_US;
    return timeStamp;
}

void CmHiSysEventQueryStart(void)
{
    g_beginTime = GetCurrentTime();
    g_endTime = 0;
}

int32_t CmHiSysEventQueryResult(const string funStr)
{
    if (g_beginTime == 0) {
        return CM_HISYSEVENT_QUERY_FAILED;
    }

    g_queryResult = false;
    g_queryStr = funStr;

    sleep(SLEEP_TIME); // Waiting for hisysevent to upload

    // queryArg
    g_endTime = GetCurrentTime();
    struct QueryArg args(g_beginTime, g_endTime, MAX_QUERY_EVENT_COUNT);

    // queryRules
    string domain = "CERT_MANAGER";
    vector<string> eventList;
    eventList.push_back("CERT_FAULT");
    QueryRule rule(domain, eventList);
    vector<QueryRule> queryRules;
    queryRules.push_back(rule);

    // queryCallback
    auto queryCallBack = std::make_shared<CmHiSysEventCallBack>();
    if (HiSysEventManager::Query(args, queryRules, queryCallBack) == 0) {
        sleep(SLEEP_TIME); // Waiting for Query end
        if (g_queryResult) {
            return CM_HISYSEVENT_QUERY_SUCCESS;
        }
        return CM_HISYSEVENT_QUERY_FAILED;
    }

    return CM_HISYSEVENT_QUERY_FAILED;
}

void FreeCMBlobData(struct CmBlob *blob)
{
    if (blob == nullptr) {
        return;
    }

    if (blob->data != nullptr) {
        CmFree(blob->data);
        blob->data = nullptr;
    }
    blob->size = 0;
}

uint32_t InitUserCertInfo(struct CertInfo **cInfo)
{
    *cInfo = static_cast<struct CertInfo *>(CmMalloc(sizeof(struct CertInfo)));
    if (*cInfo == nullptr) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(*cInfo, sizeof(struct CertInfo), 0, sizeof(struct CertInfo));

    (*cInfo)->certInfo.data = static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE));
    if ((*cInfo)->certInfo.data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    (*cInfo)->certInfo.size = MAX_LEN_CERTIFICATE;

    return CM_SUCCESS;
}

uint32_t InitUserCertList(struct CertList **cList)
{
    *cList = static_cast<struct CertList *>(CmMalloc(sizeof(struct CertList)));
    if (*cList == nullptr) {
        return CMR_ERROR_MALLOC_FAIL;
    }

    uint32_t buffSize = MAX_COUNT_CERTIFICATE * sizeof(struct CertAbstract);
    (*cList)->certAbstract = static_cast<struct CertAbstract *>(CmMalloc(buffSize));
    if ((*cList)->certAbstract == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s((*cList)->certAbstract, buffSize, 0, buffSize);
    (*cList)->certsCount = MAX_COUNT_CERTIFICATE;

    return CM_SUCCESS;
}

void FreeCertList(struct CertList *certList)
{
    if (certList == nullptr || certList->certAbstract == nullptr) {
        return;
    }

    CmFree(certList->certAbstract);
    certList->certAbstract = nullptr;

    CmFree(certList);
}
