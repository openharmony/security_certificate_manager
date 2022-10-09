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

#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "cert_manager_api.h"

#include "cm_mem.h"
#include "cm_test_common.h"
#include "cm_test_log.h"

#include "cm_cert_data.h"

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

#define EOK  (0)

using namespace testing::ext;
namespace CertmanagerTest {
#ifndef errno_t
typedef int errno_t;
#endif

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
}

uint32_t InitCertList(struct CertList **certlist)
{
    *certlist = (struct CertList *)CmMalloc(sizeof(struct CertList));
    if (*certlist == nullptr) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    (*certlist)->certAbstract = nullptr;
    (*certlist)->certsCount = 0;

    return CM_SUCCESS;
}

uint32_t InitUserContext(struct CmContext* userCtx, const uint32_t userid, const uint32_t uid, const char *pktname)
{
    if (pktname == nullptr || userCtx  == nullptr) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    userCtx->userId = userid;
    userCtx->uid = uid;
    errno_t ret = strcpy_s(userCtx->packageName, MAX_LEN_PACKGE_NAME, pktname);
    if (ret != EOK) {
        return CM_FAILURE;
    }
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
    certList = nullptr;
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

bool CompareCert(const struct CertAbstract *firstCert, const struct CertAbstract *secondCert)
{
    if (firstCert == nullptr || secondCert == nullptr) {
        CM_TEST_LOG_E("cert invalid parameter");
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
            (firstCredential->keyNum == secondCredential->keyNum));
}

int32_t IsFileExist(const char *fileName)
{
    if (access(fileName, F_OK) != 0) {
        CM_TEST_LOG_E("file not exist, fileName %s", fileName);
        return -1;
    }

    return 0;
}

uint32_t FileRead(const char *fileName, uint32_t offset, uint8_t *buf, uint32_t len)
{
    (void)offset;
    if (IsFileExist(fileName) != 0) {
        return 0;
    }

    char filePath[PATH_MAX + 1] = {0};
    (void)realpath(fileName, filePath);
    if (strstr(filePath, "../") != nullptr) {
        CM_TEST_LOG_E("invalid filePath, path %s", filePath);
        return 0;
    }

    FILE *fp = fopen(filePath, "rb");
    if (fp == nullptr) {
        CM_TEST_LOG_E("failed to open file");
        return 0;
    }

    uint32_t size = fread(buf, 1, len, fp);
    if (fclose(fp) < 0) {
        CM_TEST_LOG_E("failed to close file");
        return 0;
    }

    return size;
}

uint32_t FileSize(const char *fileName)
{
    if (IsFileExist(fileName) != 0) {
        return 0;
    }

    struct stat fileStat;
    (void)memset_s(&fileStat, sizeof(fileStat), 0, sizeof(fileStat));
    if (stat(fileName, &fileStat) != 0) {
        CM_TEST_LOG_E("file stat fail.");
        return 0;
    }

    return fileStat.st_size;
}

int32_t TestGenerateAppCert(const struct CmBlob *alias, uint32_t alg, uint32_t store)
{
    struct CmBlob appCert = { 0, NULL };
    if (alg == CERT_KEY_ALG_RSA) {
        appCert.size = sizeof(g_rsaP12Certinfo);
        appCert.data = (uint8_t *)g_rsaP12Certinfo;
    } else if (alg == CERT_KEY_ALG_ECC) {
        appCert.size = sizeof(g_eccP12Certinfo);
        appCert.data = (uint8_t *)g_eccP12Certinfo;
    } else {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmBlob appCertPwd = { sizeof(g_certPwd), (uint8_t *)g_certPwd };
    uint8_t uriData[100] = {0};
    struct CmBlob keyUri = { sizeof(uriData), uriData };
    return CmInstallAppCert(&appCert, &appCertPwd, alias, store, &keyUri);
}
}

