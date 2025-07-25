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
#include <unistd.h>
#include <unordered_map>

namespace CertmanagerTest {
constexpr uint32_t SLEEP_TIME = 3;
constexpr int32_t PERMISSION_MAX = 4;
constexpr int32_t PERMISSION_INDEX0 = 0;
constexpr int32_t PERMISSION_INDEX1 = 1;
constexpr int32_t PERMISSION_INDEX2 = 2;
constexpr int32_t PERMISSION_INDEX3 = 3;

static const std::unordered_map<uint32_t, const uint8_t*> ALG_CODE_TO_CERT_DATA = {
    { CERT_KEY_ALG_RSA, g_rsa2048P12CertInfo },
    { CERT_KEY_ALG_ECC, g_eccP256P12CertInfo },
    { CERT_KEY_ALG_RSA_512, g_rsa512P12CertInfo },
    { CERT_KEY_ALG_RSA_1024, g_rsa1024P12CertInfo },
    { CERT_KEY_ALG_RSA_3072, g_rsa3072P12CertInfo },
    { CERT_KEY_ALG_RSA_4096, g_rsa4096P12CertInfo },
    { CERT_KEY_ALG_ECC_P224, g_eccP224P12CertInfo },
    { CERT_KEY_ALG_ECC_P384, g_eccP384P12CertInfo },
    { CERT_KEY_ALG_ECC_P521, g_eccP521P12CertInfo },
    { CERT_KEY_ALG_ED25519, g_ed25519P12CertInfo },
    { CERT_KEY_ALG_SM2_1, g_sm2PfxCertInfo },
    { CERT_KEY_ALG_SM2_2, g_sm2PfxCertInfo2 },
};

static const std::unordered_map<uint32_t, uint32_t> ALG_CODE_TO_CERT_SIZE = {
    { CERT_KEY_ALG_RSA, sizeof(g_rsa2048P12CertInfo) },
    { CERT_KEY_ALG_ECC, sizeof(g_eccP256P12CertInfo) },
    { CERT_KEY_ALG_RSA_512, sizeof(g_rsa512P12CertInfo) },
    { CERT_KEY_ALG_RSA_1024, sizeof(g_rsa1024P12CertInfo) },
    { CERT_KEY_ALG_RSA_3072, sizeof(g_rsa3072P12CertInfo) },
    { CERT_KEY_ALG_RSA_4096, sizeof(g_rsa4096P12CertInfo) },
    { CERT_KEY_ALG_ECC_P224, sizeof(g_eccP224P12CertInfo) },
    { CERT_KEY_ALG_ECC_P384, sizeof(g_eccP384P12CertInfo) },
    { CERT_KEY_ALG_ECC_P521, sizeof(g_eccP521P12CertInfo) },
    { CERT_KEY_ALG_ED25519, sizeof(g_ed25519P12CertInfo) },
    { CERT_KEY_ALG_SM2_1, sizeof(g_sm2PfxCertInfo) },
    { CERT_KEY_ALG_SM2_2, sizeof(g_sm2PfxCertInfo2) },
};

void SetATPermission(void)
{
    static bool firstRun = true;
    const char **perms = new const char *[PERMISSION_MAX]; // 4 permissions
    perms[PERMISSION_INDEX0] = "ohos.permission.ACCESS_CERT_MANAGER_INTERNAL"; // system_core
    perms[PERMISSION_INDEX1] = "ohos.permission.ACCESS_CERT_MANAGER"; // normal
    perms[PERMISSION_INDEX2] = "ohos.permission.ACCESS_USER_TRUSTED_CERT"; // system_core
    perms[PERMISSION_INDEX3] = "ohos.permission.ACCESS_SYSTEM_APP_CERT"; // system_core
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = PERMISSION_MAX,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "TestCertManager",
        .aplStr = "system_core",
    };

    auto tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
    if (firstRun) {
        system("pidof accesstoken_service | xargs kill -9");
        sleep(SLEEP_TIME);
        firstRun = false;
    }
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

    uint32_t buffSize = MAX_COUNT_CERTIFICATE_ALL * sizeof(struct CertAbstract);
    (*cList)->certAbstract = static_cast<struct CertAbstract *>(CmMalloc(buffSize));
    if ((*cList)->certAbstract == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s((*cList)->certAbstract, buffSize, 0, buffSize);
    (*cList)->certsCount = MAX_COUNT_CERTIFICATE_ALL;

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
    str += (certAbstract->status) ? "true" : "false";
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
    str += (certInfo->status) ? "true" : "false";
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

static int32_t ConstructAppCertData(uint32_t alg, struct CmBlob *appCert)
{
    auto iterSize = ALG_CODE_TO_CERT_SIZE.find(alg);
    if (iterSize == ALG_CODE_TO_CERT_SIZE.end()) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    appCert->size = iterSize->second;

    auto iterData = ALG_CODE_TO_CERT_DATA.find(alg);
    if (iterData == ALG_CODE_TO_CERT_DATA.end()) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    appCert->data = const_cast<uint8_t *>(iterData->second);
    return CM_SUCCESS;
}

int32_t TestGenerateAppCert(const struct CmBlob *alias, uint32_t alg, uint32_t store)
{
    struct CmBlob appCert = { 0, NULL };
    int32_t ret = ConstructAppCertData(alg, &appCert);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    struct CmBlob appCertPwd = { sizeof(g_certPwd), const_cast<uint8_t *>(g_certPwd) };
    if (alg == CERT_KEY_ALG_SM2_1 || alg == CERT_KEY_ALG_SM2_2) {
        appCertPwd.size = sizeof(g_sm2certPwd);
        appCertPwd.data = const_cast<uint8_t *>(g_sm2certPwd);
    }
    uint8_t uriData[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriData), uriData };

    if (store == CM_SYS_CREDENTIAL_STORE) {
        struct CmAppCertParam appCertParam = { &appCert, &appCertPwd,
            (struct CmBlob *)alias, CM_SYS_CREDENTIAL_STORE, TEST_USERID };
        return CmInstallSystemAppCert(&appCertParam, &keyUri);
    }
    return CmInstallAppCert(&appCert, &appCertPwd, alias, store, &keyUri);
}

bool FindCertAbstract(const struct CertAbstract *abstract, const struct CertList *cList)
{
    if (abstract == nullptr || cList == nullptr || cList->certsCount == 0) {
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
