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

#ifndef CERT_MANAGER_AUTH_LIST_MGR_H
#define CERT_MANAGER_AUTH_LIST_MGR_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CmAddAuthUid(const struct CmContext *context, const struct CmBlob *uri, uint32_t uid);

int32_t CmRemoveAuthUid(const struct CmContext *context, const struct CmBlob *uri, uint32_t uid);

int32_t CmGetAuthList(const struct CmContext *context, const struct CmBlob *uri, struct CmAppUidList *appUidList);

int32_t CmDeleteAuthListFile(const struct CmContext *context, const struct CmBlob *uri);

int32_t CmCheckIsAuthUidExist(const struct CmContext *context, const struct CmBlob *uri,
    uint32_t targetUid, bool *isInAuthList);

int32_t CmRemoveAuthUidByUserId(uint32_t userId, uint32_t targetUid, const struct CmBlob *uri);

int32_t CmGetAuthListByUserId(uint32_t userId, const struct CmBlob *uri, struct CmAppUidList *appUidList);

int32_t CmDeleteAuthListFileByUserId(uint32_t userId, const struct CmBlob *uri);

int32_t CmCheckIsAuthUidExistByUserId(uint32_t userId, uint32_t targetUid,
    const struct CmBlob *uri, bool *isInAuthList);

int32_t CmCheckCredentialExist(const struct CmContext *context, const struct CmBlob *uri);

#ifdef __cplusplus
}
#endif

#endif /* CERT_MANAGER_AUTH_LIST_MGR_H */

