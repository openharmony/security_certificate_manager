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

#ifndef AUTH_MANAGER_IPC_H
#define AUTH_MANAGER_IPC_H

#include "cm_type_inner.h"

#ifdef __cplusplus
extern "C"
{
#endif

int32_t CmClientGrantAppCertificate(const struct CmBlob *keyUri, uint32_t appUid, struct CmBlob *authUri);

int32_t CmClientGetAuthorizedAppList(const struct CmBlob *keyUri, struct CmAppUidList *appUidList);

int32_t CmClientIsAuthorizedApp(const struct CmBlob *authUri);

int32_t CmClientRemoveGrantedApp(const struct CmBlob *keyUri, uint32_t appUid);

int32_t CmClientInit(const struct CmBlob *authUri, const struct CmSignatureSpec *spec, struct CmBlob *handle);

int32_t CmClientUpdate(const struct CmBlob *handle, const struct CmBlob *inData);

int32_t CmClientFinish(const struct CmBlob *handle, const struct CmBlob *inData, struct CmBlob *outData);

int32_t CmClientAbort(const struct CmBlob *handle);

int32_t TestGenerateAppCert(const struct CmBlob *alias, uint32_t alg, uint32_t store);

#ifdef __cplusplus
}
#endif

#endif /* AUTH_MANAGER_IPC_H */
