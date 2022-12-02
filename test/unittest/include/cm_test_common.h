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

#ifndef CM_TEST_COMMON_H
#define CM_TEST_COMMON_H

#include "cm_type.h"
#include "securec.h"

#include  <string>

#define CERT_KEY_ALG_RSA 1
#define CERT_KEY_ALG_ECC 2

#define PERFORMACE_COUNT 1000

#define DELIMITER "$$$"
#define ENDOF  "\n"

namespace CertmanagerTest {
void FreeCMBlobData(struct CmBlob *blob);

void FreeCertList(struct CertList *certList);

int32_t InitUserContext(struct CmContext* userCtx, const uint32_t userid, const uint32_t uid, const char *pktname);

bool CompareCertInfo(const struct CertInfo *firstCert, const struct CertInfo *secondCert);

bool CompareCredential(const struct Credential *firstCredential, const struct Credential *secondCredential);

bool CompareCredentialList(const struct CredentialAbstract *firstCert, const struct CredentialAbstract *secondCert);

int32_t TestGenerateAppCert(const struct CmBlob *alias, uint32_t alg, uint32_t store);

std::string DumpCertAbstractInfo(const struct CertAbstract *certAbstract);
std::string DumpCertInfo(const struct CertInfo* certInfo);
std::string DumpCertList(struct CertList *certList);

void SetATPermission(void);

int32_t InitCertList(struct CertList **cList);

int32_t InitUserCertInfo(struct CertInfo **cInfo);

int32_t InitCertInfo(struct CertInfo *certInfo);

bool FindCertAbstract(const struct CertAbstract *abstract, const struct CertList *cList);

void FreeCertInfo(struct CertInfo *cInfo);
}
#endif /* CM_TEST_COMMON_H */
