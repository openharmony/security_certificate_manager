/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "cmx509_fuzzer.h"

#include "cert_manager_auth_list_mgr.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"
#include "cert_manager_service.h"
#include "cm_cert_data_p7b.h"
#include "cm_cert_data_user.h"
#include "cm_x509.h"

using namespace CmFuzzTest;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPIX509All(const uint8_t* data, size_t size)
    {
        struct CmBlob displayName = { 0, nullptr };
        CertmanagerTest::MockHapToken mockHap;
        char outBuf[1024];
        uint32_t outBufMaxSize = sizeof(outBuf);
        uint8_t certAliasBuf[] = "40dc992e";
        struct CmBlob CertAlias = { sizeof(certAliasBuf), certAliasBuf };
        struct CmBlob subjectName = { 0, nullptr};
        STACK_OF(X509) *certStack1 = InitCertStackContext(g_p7bUserCert.data, g_p7bUserCert.size);
        STACK_OF(X509) *certStack2 = InitCertStackContext(g_p7bUserCertTooLongSubj.data, g_p7bUserCertTooLongSubj.size);
        X509 *x509 = InitCertContext(g_certData01, sizeof(g_certData01));
        (void)GetX509SerialNumber(x509, outBuf, outBufMaxSize);
        (void)GetSubjectNameAndAlias(x509, &CertAlias, &subjectName, &displayName);
        (void)GetX509SubjectNameLongFormat(x509, outBuf, outBufMaxSize);
        (void)GetX509IssueNameLongFormat(x509, outBuf, outBufMaxSize);
        (void)GetX509NotBefore(x509, outBuf, outBufMaxSize);
        (void)GetX509NotAfter(x509, outBuf, outBufMaxSize);
        (void)GetX509Fingerprint(x509, outBuf, outBufMaxSize);
        (void)CmX509ToPEM(x509, &CertAlias);
        sk_X509_pop_free(certStack1, X509_free);
        sk_X509_pop_free(certStack2, X509_free);
        FreeCertContext(x509);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPIX509All(data, size);
    return 0;
}

