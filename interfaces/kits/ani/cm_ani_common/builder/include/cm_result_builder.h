/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef CM_RESULT_BUILDER_H
#define CM_RESULT_BUILDER_H

#include "ani.h"
#include "cm_type.h"

namespace OHOS::Security::CertManager::Ani {
class CMResultBuilder {
private:
    ani_env *env = nullptr;
    CmBlob *uri = nullptr;
    CredentialList *credentialList = nullptr;
    CredentialDetailList *certificateList = nullptr;
    Credential *credential = nullptr;
    CertList *certList = nullptr;
    CmBlob *outData = nullptr;
    CertInfo *certInfo = nullptr;

    int32_t buildUri();
    int32_t buildCredentialList();
    int32_t buildCredentialDetailList();
    int32_t buildCredential();
    int32_t buildCertList();
    int32_t buildCertInfo();
    int32_t credentialSetStringProperty(ani_object credentialObj);
    int32_t buildOutData();
public:
    ani_object cmResult = nullptr;
    CMResultBuilder(ani_env *env);

    CMResultBuilder *setUri(CmBlob *uri);
    CMResultBuilder *setCredentialList(CredentialList *credentialList);
    CMResultBuilder *setCredentialDetailList(CredentialDetailList *certificateList);
    CMResultBuilder *setCredential(Credential *credential);
    CMResultBuilder *setCertList(CertList *certList);
    CMResultBuilder *setCertInfo(CertInfo *certInfo);
    CMResultBuilder *setOutData(CmBlob *outData);
    int32_t build();
};
} // OHOS::Security::CertManager::Ani
#endif // CM_RESULT_BUILDER_H