/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef CERT_MANAGER_SESSION_MGR_H
#define CERT_MANAGER_SESSION_MGR_H

#include <stdbool.h>
#include <stdint.h>

#include "cert_manager_double_list.h"
#include "cm_type.h"

struct CmSessionNodeInfo {
    uint32_t userId;
    uint32_t uid;
    struct CmBlob uri; /* origin uri */
};

struct CmSessionNode {
    struct DoubleList listHead;
    struct CmSessionNodeInfo info;
    struct CmBlob handle;
    bool abortable;
};

enum CmSessionDeleteType {
    DELETE_SESSION_BY_USERID,
    DELETE_SESSION_BY_UID,
    DELETE_SESSION_BY_URI,
    DELETE_SESSION_BY_ALL,
};

#ifdef __cplusplus
extern "C" {
#endif

int32_t CmCreateSession(const struct CmSessionNodeInfo *info, const struct CmBlob *handle, bool abortable);

struct CmSessionNode *CmQuerySession(const struct CmSessionNodeInfo *info, const struct CmBlob *handle);

void CmDeleteSession(const struct CmBlob *handle);

void CmDeleteSessionByNodeInfo(enum CmSessionDeleteType deleteType, const struct CmSessionNodeInfo *info);

#ifdef __cplusplus
}
#endif

#endif /* CERT_MANAGER_SESSION_MGR_H */
