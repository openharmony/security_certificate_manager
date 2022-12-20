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

#include "cm_test_common.h"

#include "cert_manager_api.h"

#include "cm_cert_data_ecc.h"
#include "cm_cert_data_ed25519.h"
#include "cm_cert_data_part1_rsa.h"
#include "cm_cert_data_part2_rsa.h"
#include "cm_mem.h"
#include "cm_test_log.h"

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

namespace CertmanagerTest {
void SetATPermission(void)
{
    const char **perms = new const char *[2]; // 2 permissions
    perms[0] = "ohos.permission.ACCESS_CERT_MANAGER_INTERNAL"; // system_basic
    perms[1] = "ohos.permission.ACCESS_CERT_MANAGER"; // normal
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "TestCertManager",
        .aplStr = "system_basic",
    };

    auto tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}

int32_t InitCertInfo(struct CertInfo *certInfo)
{
    if (certInfo == nullptr) {
        return CMR_ERROR_MALLOC_FAIL;
    }

    certInfo->certInfo.data =  static_cast<uint8_t *>(CmMalloc(MAX_LEN_CERTIFICATE));
    if (certInfo->certInfo.data  == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    certInfo->certInfo.size = MAX_LEN_CERTIFICATE;

    return CM_SUCCESS;
}

int32_t InitCertList(struct CertList **cList)
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

int32_t InitUserCertInfo(struct CertInfo **cInfo)
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

void FreeCertList(struct CertList *certList)
{
    if (certList == nullptr || certList->certAbstract == nullptr) {
        return;
    }

    CmFree(certList->certAbstract);
    certList->certAbstract = nullptr;

    CmFree(certList);
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

void FreeCertInfo(struct CertInfo *cInfo)
{
    if (cInfo == nullptr || (cInfo->certInfo).data == nullptr) {
        return;
    }

    FreeCMBlobData(&(cInfo->certInfo));
    CmFree(cInfo);
}

static bool CompareCert(const struct CertAbstract *firstCert, const struct CertAbstract *secondCert)
{
    if (firstCert == nullptr || secondCert == nullptr) {
        CM_TEST_LOG_E("cert invalid parameter");
        return false;
    }
    return ((strcmp(firstCert->uri, secondCert->uri) == 0) &&
        (strcmp(firstCert->certAlias, secondCert->certAlias) == 0) &&
        (strcmp(firstCert->subjectName, secondCert->subjectName) == 0) &&
        (firstCert->status == secondCert->status));
}

bool CompareCredentialList(const struct CredentialAbstract *firstCert, const struct CredentialAbstract *secondCert)
{
    if (firstCert == nullptr || secondCert == nullptr) {
        CM_TEST_LOG_E("cert invalid parameter");
        return false;
    }
    return ((strcmp(firstCert->type, secondCert->type) == 0) &&
        (strcmp(firstCert->alias, secondCert->alias) == 0) &&
        (strcmp(firstCert->keyUri, secondCert->keyUri) == 0));
}

std::string  DumpCertAbstractInfo(const struct CertAbstract *certAbstract)
{
    if (certAbstract == nullptr) {
        return " ";
    }
    std::string str  = "";
    str += ENDOF;
    str +=  certAbstract->uri;
    str += DELIMITER;
    str += certAbstract->certAlias;
    str += DELIMITER;
    str += certAbstract->subjectName;
    str += DELIMITER;
    str += (certAbstract->status)? "true":"false";
    str += ENDOF;
    return str;
}

std::string DumpCertList(struct CertList *certList)
{
    if (certList == nullptr) {
        return " ";
    }

    std::string  str  = "";
    if (certList->certsCount > 0 && certList->certAbstract != nullptr) {
        for (uint32_t i = 0; i < certList->certsCount; i++) {
            str +=  DumpCertAbstractInfo(&(certList->certAbstract[i]));
        }
    }
    return str;
}

bool CompareCertInfo(const struct CertInfo *firstCert, const struct CertInfo *secondCert)
{
    if (firstCert == nullptr || secondCert == nullptr) {
        return false;
    }
    return ((strcmp(firstCert->uri, secondCert->uri) == 0) &&
            (strcmp(firstCert->certAlias, secondCert->certAlias) == 0) &&
            (firstCert->status == secondCert->status) &&
            (strcmp(firstCert->issuerName, secondCert->issuerName) == 0) &&
            (strcmp(firstCert->subjectName, secondCert->subjectName) == 0) &&
            (strcmp(firstCert->serial, secondCert->serial) == 0) &&
            (strcmp(firstCert->notBefore, secondCert->notBefore) == 0) &&
            (strcmp(firstCert->notAfter, secondCert->notAfter) == 0) &&
            (strcmp(firstCert->fingerprintSha256, secondCert->fingerprintSha256) == 0));
}

bool CompareCertData(const struct CmBlob *firstData, const struct CmBlob *secondData)
{
    if (firstData == nullptr || secondData == nullptr) {
        return false;
    }
    return ((firstData->size == secondData->size) &&
            (memcmp(firstData->data, secondData->data, static_cast<int32_t>(firstData->size)) == 0));
}

std::string DumpCertInfo(const struct CertInfo *certInfo)
{
    if (certInfo == nullptr) {
        return " ";
    }
    std::string str = "";
    str += ENDOF;
    str += certInfo->uri;
    str += DELIMITER;
    str += certInfo->certAlias;
    str += DELIMITER;
    str += certInfo->subjectName;
    str += DELIMITER;
    str += (certInfo->status)? "true":"false";
    str += ENDOF;
    return str;
}

bool CompareCredential(const struct Credential *firstCredential, const struct Credential *secondCredential)
{
    if (firstCredential == nullptr || secondCredential == nullptr) {
        return false;
    }
    return ((strcmp(firstCredential->type, secondCredential->type) == 0) &&
            (strcmp(firstCredential->alias, secondCredential->alias) == 0) &&
            (strcmp(firstCredential->keyUri, secondCredential->keyUri) == 0) &&
            (firstCredential->certNum == secondCredential->certNum) &&
            (firstCredential->keyNum == secondCredential->keyNum) &&
            (firstCredential->credData.size == secondCredential->credData.size));
}

int32_t TestGenerateAppCert(const struct CmBlob *alias, uint32_t alg, uint32_t store)
{
    struct CmBlob appCert = { 0, NULL };
    switch (alg) {
        case CERT_KEY_ALG_RSA:
            appCert.size = sizeof(g_rsa2048P12CertInfo);
            appCert.data = const_cast<uint8_t *>(g_rsa2048P12CertInfo);
            break;
        case CERT_KEY_ALG_ECC:
            appCert.size = sizeof(g_eccP256P12CertInfo);
            appCert.data = const_cast<uint8_t *>(g_eccP256P12CertInfo);
            break;
        case CERT_KEY_ALG_RSA_512:
            appCert.size = sizeof(g_rsa512P12CertInfo);
            appCert.data = const_cast<uint8_t *>(g_rsa512P12CertInfo);
            break;
        case CERT_KEY_ALG_RSA_1024:
            appCert.size = sizeof(g_rsa1024P12CertInfo);
            appCert.data = const_cast<uint8_t *>(g_rsa1024P12CertInfo);
            break;
        case CERT_KEY_ALG_RSA_3072:
            appCert.size = sizeof(g_rsa3072P12CertInfo);
            appCert.data = const_cast<uint8_t *>(g_rsa3072P12CertInfo);
            break;
        case CERT_KEY_ALG_RSA_4096:
            appCert.size = sizeof(g_rsa4096P12CertInfo);
            appCert.data = const_cast<uint8_t *>(g_rsa4096P12CertInfo);
            break;
        case CERT_KEY_ALG_ECC_P224:
            appCert.size = sizeof(g_eccP224P12CertInfo);
            appCert.data = const_cast<uint8_t *>(g_eccP224P12CertInfo);
            break;
        case CERT_KEY_ALG_ECC_P384:
            appCert.size = sizeof(g_eccP384P12CertInfo);
            appCert.data = const_cast<uint8_t *>(g_eccP384P12CertInfo);
            break;
        case CERT_KEY_ALG_ECC_P521:
            appCert.size = sizeof(g_eccP521P12CertInfo);
            appCert.data = const_cast<uint8_t *>(g_eccP521P12CertInfo);
            break;
        case CERT_KEY_ALG_ED25519:
            appCert.size = sizeof(g_ed25519P12CertInfo);
            appCert.data = const_cast<uint8_t *>(g_ed25519P12CertInfo);
            break;
        default:
            return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmBlob appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };
    uint8_t uriData[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    return CmInstallAppCert(&appCert, &appCertPwd, alias, store, &keyUri);
}

bool FindCertAbstract(const struct CertAbstract *abstract, const struct CertList *cList)
{
    if (abstract == NULL || cList == NULL || cList->certsCount == 0) {
        return false;
    }
    for (uint32_t i = 0; i < cList->certsCount; ++i) {
        if (CompareCert(abstract, &(cList->certAbstract[i]))) {
            return true;
        }
    }
    return false;
}
}
