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

#ifndef CM_HISYSEVENT_TEST_COMMON_H
#define CM_HISYSEVENT_TEST_COMMON_H

#include <stdint.h>
#include <string>
#include "securec.h"
#include "cm_type.h"
#ifdef __cplusplus
extern "C" {
#endif

#define CM_HISYSEVENT_QUERY_SUCCESS 0
#define CM_HISYSEVENT_QUERY_FAILED (-1)

void CmHiSysEventQueryStart(void);

int32_t CmHiSysEventQueryResult(const std::string funStr);

void FreeCMBlobData(struct CmBlob *blob);

uint32_t InitUserCertList(struct CertList **cList);

uint32_t InitUserCertInfo(struct CertInfo **cInfo);

void FreeCertList(struct CertList *certList);

#ifdef __cplusplus
}
#endif

#endif // CM_HISYSEVENT_TEST_COMMON_H