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

#ifndef CERT_MANAGER_AUTH_MGR_H
#define CERT_MANAGER_AUTH_MGR_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CmAuthGrantAppCertificate(const struct CmContext *context, const struct CmBlob *keyUri,
    uint32_t appUid, struct CmBlob *authUri);

int32_t CmAuthGetAuthorizedAppList(const struct CmContext *context, const struct CmBlob *keyUri,
    struct CmAppUidList *appUidList);

int32_t CmAuthIsAuthorizedApp(const struct CmContext *context, const struct CmBlob *authUri);

int32_t CmAuthRemoveGrantedApp(const struct CmContext *context, const struct CmBlob *keyUri, uint32_t appUid);

int32_t CmAuthDeleteAuthInfo(const struct CmContext *context, const struct CmBlob *uri);

int32_t CmAuthDeleteAuthInfoByUserId(uint32_t userId, const struct CmBlob *uri);

int32_t CmAuthDeleteAuthInfoByUid(uint32_t userId, uint32_t targetUid, const struct CmBlob *uri);

int32_t CmCheckAndGetCommonUri(const struct CmContext *context, const struct CmBlob *uri, struct CmBlob *commonUri);

int32_t CmCheckCallerIsProducer(const struct CmContext *context, const struct CmBlob *uri);

#ifdef __cplusplus
}
#endif

#endif /* CERT_MANAGER_AUTH_MGR_H */

