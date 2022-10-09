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

#include "cm_ipc_service.h"

#include <dlfcn.h>
#include <stdbool.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include "cm_ipc_serialization.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type.h"
#include "cm_response.h"
#include "cert_manager_status.h"
#include "cert_manager.h"
#include "cm_pfx.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_uri.h"
#include "cm_ipc_check.h"
#include "cm_param.h"
#include <openssl/x509.h>
#include <openssl/err.h>
#include "cert_manager_type.h"
#include "hks_type.h"
#include "cm_openssl_ecc.h"
#include "cm_openssl_rsa.h"
#include "cm_openssl_curve25519.h"

#include "cert_manager_service.h"

#include "cert_manager_query.h"
#include "cert_manager_permission_check.h"
#include "cm_report_wrapper.h"

#define MAX_PACKAGENAME_LEN     32
#define MAX_LEN_CERTIFICATE     8196
#define MAX_LEN_PRIVATE_KEY     1024
#define INSTALL_PARAMSET_SZIE   4

static int32_t CmTrustCertificateListPack(struct CmBlob *tempCertificateList, const struct CmBlob *certificateList,
    const struct CertBlob *certBlob, const uint32_t *status)
{
    int32_t ret;
    uint32_t offset = 0;
    uint32_t buffSize;

    /* buff struct: cert count + (cert subjectname + cert status +  cert uri +  cert alias) * MAX_CERT_COUNT */
    buffSize = sizeof(uint32_t) + (sizeof(uint32_t) + MAX_LEN_SUBJECT_NAME + sizeof(uint32_t) + sizeof(uint32_t) +
        MAX_LEN_URI + MAX_LEN_CERT_ALIAS) * MAX_COUNT_CERTIFICATE;

    tempCertificateList->data = (uint8_t *)CmMalloc(buffSize);
    if (tempCertificateList->data == NULL) {
        ret = CMR_ERROR_MALLOC_FAIL;
        return ret;
    }
    tempCertificateList->size = buffSize;
    ret = CopyUint32ToBuffer(certificateList->size, tempCertificateList, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy certificate count failed");
        return ret;
    }

    for (uint32_t i = 0; i < certificateList->size; i++) {
        ret = CopyBlobToBuffer(&(certBlob->subjectName[i]), tempCertificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate subject failed");
            return ret;
        }
        ret = CopyUint32ToBuffer(status[i], tempCertificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate status failed");
            return ret;
        }
        ret = CopyBlobToBuffer(&(certBlob->uri[i]), tempCertificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate uri failed");
            return ret;
        }
        ret = CopyBlobToBuffer(&(certBlob->certAlias[i]), tempCertificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate certAlias failed");
            return ret;
        }
    }
    return ret;
}

static int32_t CmMallocCertInfo(struct CertBlob *certBlob)
{
    uint32_t i;

    if (certBlob == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    for (i = 0; i < MAX_COUNT_CERTIFICATE; i++) {
        certBlob->subjectName[i].size = MAX_LEN_CERTIFICATE;
        certBlob->subjectName[i].data = (uint8_t *)CmMalloc(MAX_LEN_SUBJECT_NAME);
        if (certBlob->subjectName[i].data == NULL) {
            return CMR_ERROR_MALLOC_FAIL;
        }
        ASSERT_FUNC(memset_s(certBlob->subjectName[i].data, MAX_LEN_SUBJECT_NAME, 0, MAX_LEN_SUBJECT_NAME));

        certBlob->certAlias[i].size = MAX_LEN_CERTIFICATE;
        certBlob->certAlias[i].data = (uint8_t *)CmMalloc(MAX_LEN_CERT_ALIAS);
        if (certBlob->certAlias[i].data == NULL) {
            return CMR_ERROR_MALLOC_FAIL;
        }
        ASSERT_FUNC(memset_s(certBlob->certAlias[i].data, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS));
    }
    return CM_SUCCESS;
}

static void CmFreeCertInfo(struct CertBlob *certBlob)
{
    uint32_t i;

    if (certBlob == NULL) {
        CM_LOG_E("CmFreeCertInfo certBlob null");
        return;
    }

    for (i = 0; i < MAX_COUNT_CERTIFICATE; i++) {
        CMMUTABLE_FREE_BLOB(certBlob->subjectName[i]);
        CMMUTABLE_FREE_BLOB(certBlob->certAlias[i]);
        CMMUTABLE_FREE_BLOB(certBlob->uri[i]);
    }
}

void CmIpcServiceGetCertificateList(const struct CmBlob *srcData, const struct CmContext *context)
{
    int32_t ret;
    uint32_t store;
    struct CmContext cmContext = {0};
    struct CmBlob certificateList = { 0, NULL };
    struct CmBlob tempCertificateList = { 0, NULL };
    uint32_t status[MAX_COUNT_CERTIFICATE] = {0};
    struct CertBlob certBlob;

    (void)memset_s(&certBlob, sizeof(struct CertBlob), 0, sizeof(struct CertBlob));
    do {
        ret = CmMallocCertInfo(&certBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmMallocCertInfo fail");
            break;
        }

        ret = CmTrustCertificateListUnpack(srcData, &cmContext, &store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmTrustCertificateListUnpack Ipc fail");
            break;
        }

        ret = CertManagerListTrustedCertificates(&cmContext, &certificateList, store, &certBlob, status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerListTrustedCertificates fail, ret = %d", ret);
            break;
        }
        ret = CmTrustCertificateListPack(&tempCertificateList, &certificateList, &certBlob, status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmIpcServiceGetCertificateList pack fail, ret = %d", ret);
            break;
        }

        CmSendResponse(context, ret, &tempCertificateList);
    } while (0);

    if (ret != CM_SUCCESS) {
        CmSendResponse(context, ret, NULL);
    }
    CmCertificateListFree((struct CmMutableBlob *)certificateList.data, certificateList.size);
    CM_FREE_BLOB(tempCertificateList);
    CmFreeCertInfo(&certBlob);
}

static int32_t CmTrustCertificateInfoPack(struct CmBlob *certificateInfo,
    const struct CmBlob *certificateList, uint32_t status)
{
    int32_t ret;
    uint32_t buffSize;
    uint32_t offset = 0;

    if (certificateList->data == NULL || certificateList->size == 0) {
        CM_LOG_E("certificateList data is null");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    const struct CmBlob *blob = &(((const struct CmBlob *)certificateList->data)[0]);

    /* buff struct: cert len + cert data + cert staus */
    buffSize = sizeof(uint32_t) + MAX_LEN_CERTIFICATE + sizeof(uint32_t);
    certificateInfo->data = (uint8_t *)CmMalloc(buffSize);
    if (certificateInfo->data == NULL) {
        ret = CMR_ERROR_MALLOC_FAIL;
        return ret;
    }
    certificateInfo->size = buffSize;

    ret = CopyBlobToBuffer(blob, certificateInfo, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy certificateInfo failed");
        return ret;
    }

    ret = CopyUint32ToBuffer(status, certificateInfo, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy certificate count failed");
        return ret;
    }

    return ret;
}

void CmIpcServiceGetCertificateInfo(const struct CmBlob *srcData, const struct CmContext *context)
{
    struct CmContext cmContext = {0};
    uint32_t store;
    struct CmBlob certificateList = { 0, NULL };
    struct CmBlob certificateInfo = { 0, NULL };
    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob uriBlob = { 0, uriBuf };
    int32_t ret;
    uint32_t status = 0;

    do {
        ret = CmTrustCertificateInfoUnpack(srcData, &cmContext, &uriBlob, &store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmTrustCertificateInfoUnpack Ipc fail");
            break;
        }

        ret = CmGetCertificatesByUri(context, &certificateList, store, &uriBlob, &status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmGetCertificatesByUri fail, ret = %d", ret);
            break;
        }

        ret =  CmTrustCertificateInfoPack(&certificateInfo, &certificateList, status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmIpcServiceGetCertificateInfo pack fail, ret = %d", ret);
            break;
        }
        CmSendResponse(context, ret, &certificateInfo);
    } while (0);

    if (ret != CM_SUCCESS) {
        CmSendResponse(context, ret, NULL);
    }
    CmCertificateListFree((struct CmMutableBlob *)certificateList.data, certificateList.size);
    CM_FREE_BLOB(certificateInfo);
}

void CmIpcServiceSetCertStatus(const struct CmBlob *srcData, const struct CmContext *context)
{
    struct CmContext cmContext = {0};
    uint32_t store;
    uint8_t uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob uriBlob = { 0, uriBuf };
    uint32_t status = 0;
    int32_t ret;

    do {
        ret = CmCertificateStatusUnpack(srcData, &cmContext, &uriBlob, &store, &status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmIpcServiceSetCertStatus Ipc fail");
            break;
        }

        ret = CertManagerSetCertificatesStatus(&cmContext, &uriBlob, store, status);

        CmSendResponse(context, ret, NULL);

        CM_LOG_I("CmIpcServiceSetCertStatus end:%d", ret);
    } while (0);

    if (ret != CM_SUCCESS) {
        CmSendResponse(context, ret, NULL);
    }
}

static int32_t CmWriteAppCert(const struct CmContext *context, const struct CmBlob *certDer,
    const uint32_t store, const struct CmBlob *certAlias, const struct CMApp *caller)
{
    int32_t ret = CMR_OK;
    char *objUri = NULL;
    uint8_t pathBuf[CERT_MAX_PATH_LEN] = {0};
    struct CmMutableBlob pathBlob = { sizeof(pathBuf), pathBuf };

    ret = CmGetFilePath(context, store, &pathBlob);
    if (ret != CMR_OK) {
        CM_LOG_E("Failed obtain path for store:%u path:%s", store, pathBuf);
        return CMR_ERROR;
    }

    CM_LOG_I("CmWriteAppCert path:%s", pathBuf);

    do {
        ret = BuildObjUri(&objUri, (char *)certAlias->data, CM_URI_TYPE_APP_KEY, caller);
        if (ret != CMR_OK || objUri == NULL) {
            CM_LOG_E("BuildObjUri failed");
            break;
        }

        if (CmFileWrite((char *)pathBuf, objUri, 0, certDer->data, certDer->size) != CMR_OK) {
            CM_LOG_E("Failed to write certificate path:%s", pathBuf);
            ret = CMR_ERROR_WRITE_FILE_FAIL;
            break;
        }
    } while (0);

    if (objUri != NULL) {
        CmFree(objUri);
    }
    return ret;
}

static int32_t CertManagerImportRsaKey(const struct CMApp *caller, EVP_PKEY *priKey,
    const struct CmBlob *certAlias)
{
    RSA *rsa = NULL;
    int32_t ret = CMR_OK;
    struct CmBlob keyPair = { 0, NULL };

    rsa = EVP_PKEY_get0_RSA(priKey);
    if (rsa == NULL) {
        CM_LOG_E("EVP_PKEY_get1_RSA error %s", ERR_reason_error_string(ERR_get_error()));
        goto err;
    }
    uint32_t keySize = ((uint32_t)RSA_size(rsa)) * CM_BITS_PER_BYTE;

    const struct CmKeySpec spec = {
        .algType = CM_ALG_RSA,
        .keyLen = keySize,
        .algParam = NULL
    };

    ret = RsaSaveKeyMaterial(rsa, spec.keyLen, &keyPair);
    if (ret != CMR_OK) {
        CM_LOG_E("save rsa key material failed ret=0x%x", ret);
        goto err;
    }

    struct CMKeyProperties props = {
        .type = CM_URI_TYPE_APP_KEY,
        .alg = CM_ALG_RSA,
        .size = keySize,
        .purpose = CM_KEY_PURPOSE_SIGN | CM_KEY_PURPOSE_VERIFY,
        .digest = CM_DIGEST_SHA256,
        .padding = HKS_PADDING_PSS
    };

    ret = CertManagerImportKeyPair(caller, &keyPair, &props, (char *)certAlias->data);
    if (ret != CMR_OK) {
        CM_LOG_E("rsa keypair import faild");
    }

err:
    CM_FREE_BLOB(keyPair);

    return ret;
}

static int32_t CertManagerImportEccKey(const struct CMApp *caller, EVP_PKEY *priKey,
    const struct CmBlob *certAlias)
{
    EC_KEY *eccKey = NULL;
    int32_t ret = CMR_OK;
    struct CmBlob keyPair = { 0, NULL };

    eccKey = EVP_PKEY_get0_EC_KEY(priKey);
    if (eccKey == NULL) {
        CM_LOG_E("EVP_PKEY_get0_EC_KEY faild");
        goto err;
    }

    uint32_t keyLen = (uint32_t)EC_GROUP_order_bits(EC_KEY_get0_group(eccKey));

    struct CmKeySpec spec = {
        .algType = CM_ALG_ECC,
        .keyLen = keyLen,
        .algParam = NULL
    };

    ret = EccSaveKeyMaterial(eccKey, &spec, &keyPair.data, &keyPair.size);
    if (ret != CMR_OK) {
        CM_LOG_E("save ec key material failed ret=0x%x", ret);
        goto err;
    }

    const struct CMKeyProperties props = {
        .type = CM_URI_TYPE_APP_KEY,
        .alg = CM_ALG_ECC,
        .size = keyLen,
        .purpose = CM_KEY_PURPOSE_SIGN | CM_KEY_PURPOSE_VERIFY,
        .digest = CM_DIGEST_SHA256
    };

    ret = CertManagerImportKeyPair(caller, &keyPair, &props, (char *)certAlias->data);
    if (ret != CMR_OK) {
        CM_LOG_E("ecc Key type import faild");
    }

err:
    CM_FREE_BLOB(keyPair);

    return ret;
}

static int32_t CertManagerImportEd25519Key(const struct CMApp *caller, const EVP_PKEY *priKey,
    const struct CmBlob *certAlias)
{
    int32_t ret = CMR_OK;
    struct CmBlob keyPair = { 0, NULL };

    struct CMKeyProperties props = {
        .type = CM_URI_TYPE_APP_KEY,
        .alg = HKS_ALG_ED25519,
        .size = HKS_CURVE25519_KEY_SIZE_256,
        .purpose = CM_KEY_PURPOSE_SIGN | CM_KEY_PURPOSE_VERIFY,
        .digest = CM_DIGEST_SHA256
    };

    const struct CmKeySpec spec = {
        .algType = HKS_ALG_ED25519,
        .keyLen = HKS_CURVE25519_KEY_SIZE_256,
        .algParam = NULL
    };

    ret = SaveCurve25519KeyMaterial(spec.algType, priKey, &keyPair);
    if (ret != CMR_OK) {
        CM_LOG_E("save curve25519 key material failed");
        goto err;
    }

    ret = CertManagerImportKeyPair(caller, &keyPair, &props, (char *)certAlias->data);
    if (ret != CMR_OK) {
        CM_LOG_E("Ed25519 key type import faild");
    }
err:
    CM_FREE_BLOB(keyPair);

    return ret;
}

static int32_t CmImportKeyPairInfo(EVP_PKEY *priKey, struct CMApp *caller,
    const struct CmBlob *certAlias)
{
    int32_t ret = CM_SUCCESS;

    int32_t keyType = EVP_PKEY_base_id(priKey);

    switch (keyType) {
        case EVP_PKEY_RSA:
            ret = CertManagerImportRsaKey(caller, priKey, certAlias);
            break;

        case EVP_PKEY_EC:
            ret = CertManagerImportEccKey(caller, priKey, certAlias);
            break;

        case EVP_PKEY_ED25519:
            ret = CertManagerImportEd25519Key(caller, priKey, certAlias);
            break;

        default:
            CM_LOG_E("Import key:%d type not suported", keyType);
    }
    return ret;
}

static int32_t CmInstallAppCert(const struct CmContext *context, const struct CmBlob *keystore,
    const struct CmBlob *keystorePwd, const struct CmBlob *certAlias, const uint32_t store)
{
    int32_t ret = CM_SUCCESS;
    EVP_PKEY *priKey = NULL;
    struct AppCert appCert;
    struct CmBlob certBlob = { 0, NULL };
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    struct CMApp caller = {
        .userId = context->userId,
        .uid = context->uid,
        .packageName = context->packageName,
    };

    do {
        ret = CmParsePkcs12Cert(keystore, (char *)keystorePwd->data, &priKey, &appCert);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmParsePkcs12Cert fail");
            ret = CM_FAILURE;
            break;
        }

        ret = CmImportKeyPairInfo(priKey, &caller, certAlias);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmImportKeyPairInfo fail");
            break;
        }

        appCert.keyCount = 1;
        certBlob.size = sizeof(struct AppCert) - MAX_LEN_CERTIFICATE_CHAIN + appCert.certSize;
        certBlob.data = (uint8_t *)(&appCert);

        ret = CmWriteAppCert(context, &certBlob, store, certAlias, &caller);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmWriteAppCert fail");
            ret = CM_FAILURE;
            break;
        }
    } while (0);

   CmReport(__func__, context, (char *)certAlias->data, ret);

    EVP_PKEY_free(priKey);
    return ret;
}

static bool AppCertCheckBlobValid(const struct CmBlob *data)
{
    bool validChar = true;

    for (uint32_t i = 0; i < data->size; i++) {
        if ((!isalnum(data->data[i])) && (data->data[i] != '_') && (data->data[i] != '\0')) {
            validChar = false;
            CM_LOG_E("data include invalid character");
            break;
        }
    }

    return validChar;
}

static bool CmCheckMaxInstalledCertCount(const uint32_t store, const struct CmContext *cmContext)
{
    bool isValid = true;
    uint32_t fileCount;
    struct CmBlob fileNames[MAX_COUNT_CERTIFICATE];
    uint32_t len = MAX_COUNT_CERTIFICATE * sizeof(struct CmBlob);
    (void)memset_s(fileNames, len, 0, len);

    if (CmServiceGetAppCertList(cmContext, store, fileNames,
        MAX_COUNT_CERTIFICATE, &fileCount) != CM_SUCCESS) {
        isValid = false;
        CM_LOG_E("Get App cert list fail");
    }

    if (fileCount >= MAX_COUNT_CERTIFICATE) {
        isValid = false;
        CM_LOG_E("The app cert installed has reached max count:%u", fileCount);
    }

    CmFreeFileNames(fileNames, fileCount);
    return isValid;
}

static int32_t CmInstallAppCertCheck(const struct CmBlob *appCert, const struct CmBlob *appCertPwd,
    const struct CmBlob *certAlias, uint32_t store, const struct CmContext *cmContext)
{
    if (appCert->data == NULL || appCertPwd->data == NULL || certAlias->data == NULL) {
        CM_LOG_E("CmInstallAppCertCheck paramSet check fail");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (appCert->size == 0 || appCertPwd->size == 0 || certAlias->size == 0 ||
        appCert->size > MAX_LEN_APP_CERT || appCertPwd->size > MAX_LEN_APP_CERT_PASSWD ||
        certAlias->size > MAX_LEN_CERT_ALIAS) {
        CM_LOG_E("CmInstallAppCertCheck paramSet check fail, appCert:%u, appCertPwd:%u, certAlias:%u",
            appCert->size, appCertPwd->size, certAlias->size);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (store != CM_CREDENTIAL_STORE && store != CM_PRI_CREDENTIAL_STORE) {
        CM_LOG_E("CmInstallAppCertCheck store check fail, store:%u", store);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!AppCertCheckBlobValid(appCertPwd) || !AppCertCheckBlobValid(certAlias)) {
        CM_LOG_E("CmInstallAppCertCheck blob data check fail");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (CmCheckMaxInstalledCertCount(store, cmContext) == false) {
        CM_LOG_E("CmCheckMaxInstalledCertCount check fail");
        return CM_FAILURE;
    }

    return CM_SUCCESS;
}

static int32_t CmServiceInstallAppCertPack(const struct CmContext *context,
    const struct CmBlob *certAlias, struct CmBlob *keyUri)
{
    int32_t ret;
    uint32_t offset = 0;
    char *objUri = NULL;
    struct CMApp caller = {
        .userId = context->userId,
        .uid = context->uid,
        .packageName = context->packageName,
    };

    /* buff struct: keyUriSize + keyUriData */
    uint32_t buffSize = sizeof(uint32_t) + MAX_LEN_URI;
    keyUri->data = (uint8_t *)CmMalloc(buffSize);
    if (keyUri->data == NULL) {
        keyUri->size = 0;
        return CMR_ERROR_MALLOC_FAIL;
    }
    keyUri->size = buffSize;
    do {
        ret = BuildObjUri(&objUri, (char *)certAlias->data, CM_URI_TYPE_APP_KEY, &caller);
        if (ret != CMR_OK || objUri == NULL) {
            CM_LOG_E("BuildObjUri failed");
            break;
        }
        struct CmBlob blob = { strlen(objUri) + 1, (uint8_t *)objUri };
        ret = CopyBlobToBuffer(&blob, keyUri, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("copy keyUri failed");
            break;
        }
    } while (0);

    if (objUri != NULL) {
        CmFree(objUri);
    }

    return ret;
}

static int32_t CmInstallAppCertGetParam(const struct CmBlob *paramSetBlob, struct CmParamSet **paramSet,
    struct CmParamOut *params, uint32_t paramsSize, struct CertParam *certParam)
{
    uint8_t *aliasBuff = certParam->aliasBuff;
    uint8_t *passWdBuff = certParam->passWdBuff;
    struct CmContext *cmContext = certParam->cmContext;
    int32_t ret = CmGetParamSet((struct CmParamSet *)paramSetBlob->data, paramSetBlob->size, paramSet);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("InstallAppCert CmGetParamSet fail, ret = %d", ret);
        return CM_FAILURE;
    }

    ret = CmParamSetToParams(*paramSet, params, paramsSize);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("InstallAppCert CmParamSetToParams fail, ret = %d", ret);
        return CM_FAILURE;
    }

    if (paramsSize > INSTALL_PARAMSET_SZIE) {
        CM_LOG_E("paramsSize check faild, paramsSize:%u", paramsSize);
        return CM_FAILURE;
    }

    struct CmBlob *appCert = params[0].blob, *appCertPwd = params[1].blob, *certAlias = params[2].blob;
    uint32_t store = *(params[3].uint32Param);
    ret = CmInstallAppCertCheck(appCert, appCertPwd, certAlias, store, cmContext);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmInstallAppCertCheck fail, ret = %d", ret);
        return CM_FAILURE;
    }

    if (appCertPwd->data[appCertPwd->size - 1] != '\0') {
        if (memcpy_s(passWdBuff, MAX_LEN_APP_CERT_PASSWD, appCertPwd->data, appCertPwd->size) != EOK) {
            CM_LOG_E("Copy passWdBuff failed");
            return CMR_ERROR_INVALID_OPERATION;
        }
        passWdBuff[appCertPwd->size] = '\0';
        appCertPwd->data = passWdBuff;
        appCertPwd->size++;
    }

    if (certAlias->data[certAlias->size - 1] != '\0') {
        if (memcpy_s(aliasBuff, MAX_LEN_CERT_ALIAS, certAlias->data, certAlias->size) != EOK) {
            CM_LOG_E("Copy aliasBuff failed");
            return CMR_ERROR_INVALID_OPERATION;
        }
        aliasBuff[certAlias->size] = '\0';
        certAlias->data = aliasBuff;
        certAlias->size++;
    }

    return CM_SUCCESS;
}

void CmIpcServiceInstallAppCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret;
    uint32_t store;
    (void)outData;
    struct CmContext cmContext = {0};
    uint8_t aliasBuff[MAX_LEN_CERT_ALIAS] = {0}, passWdBuff[MAX_LEN_APP_CERT_PASSWD] = {0};
    struct CertParam certParam = { aliasBuff, passWdBuff, &cmContext};
    struct CmBlob appCert = { 0, NULL }, appCertPwd = { 0, NULL };
    struct CmBlob certAlias = { 0, NULL }, keyUri = { 0, NULL };
    struct CmParamSet *paramSet = NULL;
    struct CmParamOut params[] = {
        {
            .tag = CM_TAG_PARAM0_BUFFER, .blob = &appCert
        }, {
            .tag = CM_TAG_PARAM1_BUFFER, .blob = &appCertPwd
        }, {
            .tag = CM_TAG_PARAM2_BUFFER, .blob = &certAlias
        }, {
            .tag = CM_TAG_PARAM0_UINT32, .uint32Param = &store
        },
    };

    do {
        ret = CmGetProcessInfoForIPC(&cmContext);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmGetProcessInfoForIPC fail, ret = %d", ret);
            break;
        }

        ret = CmInstallAppCertGetParam(paramSetBlob, &paramSet, params, CM_ARRAY_SIZE(params), &certParam);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmInstallAppCertGetParam fail, ret = %d", ret);
            break;
        }

        ret = CmInstallAppCert(&cmContext, &appCert, &appCertPwd, &certAlias, store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmInstallAppCert fail, ret = %d", ret);
            break;
        }

        ret = CmServiceInstallAppCertPack(&cmContext, &certAlias, &keyUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmServiceInstallAppCertPack fail, ret = %d", ret);
        }
    } while (0);

    CmSendResponse(context, ret, &keyUri);
    CmFreeParamSet(&paramSet);
    CM_FREE_BLOB(keyUri);
    CM_LOG_I("CmIpcServiceInstallAppCert end:%d", ret);
}

void CmIpcServiceUninstallAppCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret;
    (void)outData;
    uint32_t store;
    struct CmParamSet *paramSet = NULL;
    struct CmBlob keyUri = { 0, NULL };
    struct CmContext cmContext = {0};

    struct CmParamOut params[] = {
        {
            .tag = CM_TAG_PARAM0_BUFFER,
            .blob = &keyUri
        }, {
            .tag = CM_TAG_PARAM0_UINT32,
            .uint32Param = &store
        },
    };

    do {
        ret = CmGetParamSet((struct CmParamSet *)paramSetBlob->data, paramSetBlob->size, &paramSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UninstallAppCert CmGetParamSet fail, ret = %d", ret);
            break;
        }

        ret = CmParamSetToParams(paramSet, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UninstallAppCert CmParamSetToParams fail, ret = %d", ret);
            break;
        }

        ret = CmGetProcessInfoForIPC(&cmContext);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UninstallAppCert CmGetProcessInfoForIPC fail, ret = %d", ret);
            break;
        }

        ret = CmRemoveAppCert(&cmContext, &keyUri, store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmRemoveAppCert fail");
        }
    } while (0);

    CmSendResponse(context, ret, NULL);
    CmFreeParamSet(&paramSet);
    CM_LOG_I("CmIpcServiceUninstallAppCert end:%d", ret);
}

void CmIpcServiceUninstallAllAppCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    (void)outData;
    (void)paramSetBlob;
    int32_t ret = CM_SUCCESS;
    struct CmContext cmContext = {0};

    ret = CmGetProcessInfoForIPC(&cmContext);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmGetProcessInfoForIPC fail, ret = %d", ret);
    }

    ret = CmRemoveAllAppCert(&cmContext);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmRemoveAllAppCert fail");
    }

    CmSendResponse(context, ret, NULL);
    CM_LOG_I("CmIpcServiceUninstallAllAppCert end:%d", ret);
}

static int32_t GetAppCertInfo(const struct CmBlob *keyUri, struct CmBlob *certType,
    struct CmBlob *certUri, struct CmBlob *cerAlies)
{
    int32_t ret;
    char uriBuf[MAX_LEN_URI] = {0};
    struct CMUri uri;

    do {
        if ((keyUri->size >= MAX_LEN_URI) || memcpy_s(uriBuf, MAX_LEN_URI, keyUri->data, keyUri->size) != EOK) {
            CM_LOG_E("Failed to copy keyUri");
            ret = CMR_ERROR;
            break;
        }

        (void)memset_s(&uri, sizeof(struct CMUri), 0, sizeof(struct CMUri));
        ret = CertManagerUriDecode(&uri, (char *)keyUri->data);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerUriDecode failed");
            break;
        }

        if (memcpy_s(certType->data, MAX_LEN_SUBJECT_NAME, g_types[uri.type],
            strlen(g_types[uri.type])) != EOK) {
            CM_LOG_E("Failed to copy certType->data");
            ret = CMR_ERROR;
            break;
        }
        certType->size = strlen(g_types[uri.type]) + 1;

        if (memcpy_s(certUri->data, MAX_LEN_URI, uriBuf, strlen(uriBuf)) != EOK) {
            CM_LOG_E("Failed to copy certUri->data");
            ret = CMR_ERROR;
            break;
        }
        certUri->size = strlen(uriBuf) + 1;

        if (memcpy_s(cerAlies->data, MAX_LEN_CERT_ALIAS, uri.object, strlen(uri.object)) != EOK) {
            CM_LOG_E("Failed to copy cerAlies->data");
            ret = CMR_ERROR;
            break;
        }
        cerAlies->size = strlen(uri.object) + 1;
    } while (0);

    CertManagerFreeUri(&uri);
    return ret;
}

static int32_t CmCertListGetAppCertInfo(const struct CmBlob *fileName, struct CmBlob *certType,
     struct CmBlob *certUri,  struct CmBlob *certAlies)
{
    char uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), (uint8_t *)uriBuf };

    int32_t ret = CmGetUri((char *)fileName->data, &keyUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get uri failed");
        return ret;
    }

    ret = GetAppCertInfo(&keyUri, certType, certUri, certAlies);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("GetAppCertInfo failed");
        return ret;
    }

    return ret;
}

static int32_t CmServiceGetAppCertListPack(struct CmBlob *certificateList, const struct CmBlob *fileNames,
    const uint32_t fileCount)
{
    int32_t ret;
    uint32_t offset = 0, buffSize = 0;
    uint8_t typeBuf[MAX_LEN_SUBJECT_NAME] = {0}, certUriBuf[MAX_LEN_URI] = {0}, aliesBuf[MAX_LEN_CERT_ALIAS] = {0};
    struct CmBlob certType = { 0, typeBuf }, certUri = { 0, certUriBuf }, certAlies = { 0, aliesBuf };

    /* buff struct: cert count + (cert type +  cert uri +  cert alias) * MAX_CERT_COUNT */
    buffSize = sizeof(uint32_t) + (sizeof(uint32_t) + MAX_LEN_SUBJECT_NAME + sizeof(uint32_t) +
        MAX_LEN_URI + sizeof(uint32_t) + MAX_LEN_CERT_ALIAS) * MAX_COUNT_CERTIFICATE;

    certificateList->data = (uint8_t *)CmMalloc(buffSize);
    if (certificateList->data == NULL) {
        ret = CMR_ERROR_MALLOC_FAIL;
        return ret;
    }

    certificateList->size = buffSize;
    ret = CopyUint32ToBuffer(fileCount, certificateList, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy certificate count failed");
        return ret;
    }

    for (uint32_t i = 0; i < fileCount; i++) {
        (void)memset_s(typeBuf, MAX_LEN_SUBJECT_NAME, 0, MAX_LEN_SUBJECT_NAME);
        (void)memset_s(certUriBuf, MAX_LEN_URI, 0, MAX_LEN_URI);
        (void)memset_s(aliesBuf, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS);

        ret = CmCertListGetAppCertInfo(&fileNames[i], &certType, &certUri, &certAlies);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmCertListGetAppCertInfo failed");
            return ret;
        }

        CM_LOG_I("CmServiceGetAppCertListPack i:%u, Type:%s, certUri:%s, Alies:%s", i, typeBuf, certUriBuf, aliesBuf);

        ret = CopyBlobToBuffer(&certType, certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certType failed");
            return ret;
        }

        ret = CopyBlobToBuffer(&certUri, certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certUri failed");
            return ret;
        }

        ret = CopyBlobToBuffer(&certAlies, certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certAlies failed");
            return ret;
        }
    }

    return ret;
}

void CmIpcServiceGetAppCertList(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret;
    (void)outData;
    uint32_t store, fileCount = 0;
    struct CmContext cmContext = {0};
    struct CmBlob certificateList = { 0, NULL };
    struct CmBlob fileNames[MAX_COUNT_CERTIFICATE];
    struct CmParamSet *paramSet = NULL;
    struct CmParamOut params[] = {
        {
            .tag = CM_TAG_PARAM0_UINT32,
            .uint32Param = &store
        },
    };
    uint32_t len = MAX_COUNT_CERTIFICATE * sizeof(struct CmBlob);
    (void)memset_s(fileNames, len, 0, len);
    do {
        ret = CmGetParamSet((struct CmParamSet *)paramSetBlob->data, paramSetBlob->size, &paramSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetAppCertList CmGetParamSet fail, ret = %d", ret);
            break;
        }

        ret = CmParamSetToParams(paramSet, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetAppCertList CmParamSetToParams fail, ret = %d", ret);
            break;
        }

        ret = CmGetProcessInfoForIPC(&cmContext);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmGetProcessInfoForIPC fail, ret = %d", ret);
            break;
        }

        ret = CmServiceGetAppCertList(&cmContext, store, fileNames, MAX_COUNT_CERTIFICATE, &fileCount);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Get App cert list fail, ret = %d", ret);
            break;
        }

        ret = CmServiceGetAppCertListPack(&certificateList, fileNames, fileCount);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmServiceGetAppCertListPack pack fail, ret = %d", ret);
        }
    } while (0);

    CmSendResponse(context, ret, &certificateList);
    CmFreeParamSet(&paramSet);
    CmFreeFileNames(fileNames, fileCount);
    CM_FREE_BLOB(certificateList);
    CM_LOG_I("CmIpcServiceGetAppCertList end:%d", ret);
}

static int32_t CopyCertificateInfoToBuffer(const struct CmBlob *certBlob,
    const struct CmBlob *certificateInfo, uint32_t *offset)
{
    struct AppCert *appCert = (struct AppCert *)certBlob->data;

    int32_t ret = CopyUint32ToBuffer(appCert->certCount, certificateInfo, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy appcert->certCount failed");
        return ret;
    }

    ret = CopyUint32ToBuffer(appCert->keyCount, certificateInfo, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get appcert->keyCount failed");
        return ret;
    }

    struct CmBlob appCertBlob = { appCert->certSize, appCert->appCertdata };
    ret = CopyBlobToBuffer(&appCertBlob, certificateInfo, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy appCertBlob failed");
    }

    return ret;
}

static int32_t CopyCertSize(const struct CmBlob *certBlob, const struct CmBlob *certificateInfo,
    uint32_t *offset)
{
    uint32_t certCount = (((certBlob->size > 0) && (certBlob->data != NULL)) ? 1 : 0);

    int32_t ret = CopyUint32ToBuffer(certCount, certificateInfo, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy certificateList->size failed");
        return ret;
    }
    if (certCount == 0) {
        CM_LOG_E("app cert not exist");
        return CMR_ERROR_NOT_EXIST;
    }
    return ret;
}

static int32_t CmAppCertificateInfoPack(struct CmBlob *certificateInfo,
    const struct CmBlob *certBlob, const struct CmBlob *keyUri)
{
    int32_t ret;
    uint32_t buffSize = 0, offset = 0;
    uint8_t typeBuf[MAX_LEN_SUBJECT_NAME] = {0};
    uint8_t certUriBuf[MAX_LEN_URI] = {0};
    uint8_t aliesBuf[MAX_LEN_CERT_ALIAS] = {0};
    struct CmBlob certType = { 0, typeBuf };
    struct CmBlob certUri = { 0, certUriBuf };
    struct CmBlob cerAlies = { 0, aliesBuf };

    buffSize = sizeof(uint32_t) + sizeof(uint32_t) + MAX_LEN_SUBJECT_NAME + sizeof(uint32_t) + MAX_LEN_CERT_ALIAS +
        sizeof(uint32_t) + MAX_LEN_URI + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) +
        MAX_LEN_CERTIFICATE_CHAIN;
    certificateInfo->data = (uint8_t *)CmMalloc(buffSize);
    if (certificateInfo->data == NULL) {
        ret = CMR_ERROR_MALLOC_FAIL;
        return ret;
    }
    certificateInfo->size = buffSize;

    if (CopyCertSize(certBlob, certificateInfo, &offset) != CM_SUCCESS) {
        return CMR_ERROR_NOT_EXIST;
    }

    ret = GetAppCertInfo(keyUri, &certType, &certUri, &cerAlies);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("GetAppCertInfo failed");
        return ret;
    }

    if (CopyBlobToBuffer(&certType, certificateInfo, &offset) != CM_SUCCESS) {
        CM_LOG_E("Copy certType failed");
        return CMR_ERROR;
    }

    if (CopyBlobToBuffer(&certUri, certificateInfo, &offset) != CM_SUCCESS) {
        CM_LOG_E("Copy certUri failed");
        return CMR_ERROR;
    }

    if (CopyBlobToBuffer(&cerAlies, certificateInfo, &offset) != CM_SUCCESS) {
        CM_LOG_E("Copy cerAlies failed");
        return CMR_ERROR;
    }

    ret = CopyCertificateInfoToBuffer(certBlob, certificateInfo, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy CertificateInfo failed");
        return ret;
    }

    return ret;
}

void CmIpcServiceGetAppCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret;
    (void)outData;
    uint32_t store;
    struct CmBlob keyUri = { 0, NULL }, certificateInfo = { 0, NULL }, certBlob = { 0, NULL };
    struct CmContext cmContext = {0};
    struct CmParamSet *paramSet = NULL;
    struct CmParamOut params[] = {
        {
            .tag = CM_TAG_PARAM0_BUFFER,
            .blob = &keyUri
        },
        {
            .tag = CM_TAG_PARAM0_UINT32,
            .uint32Param = &store
        },
    };
    do {
        ret = CmGetParamSet((struct CmParamSet *)paramSetBlob->data, paramSetBlob->size, &paramSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetAppCert CmGetParamSet fail, ret = %d", ret);
            break;
        }

        ret = CmParamSetToParams(paramSet, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            break;
        }

        ret = CmGetProcessInfoForIPC(&cmContext);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmGetProcessInfoForIPC fail, ret = %d", ret);
            break;
        }

        ret = CmServiceGetAppCert(&cmContext, store, &keyUri, &certBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Get App cert list fail, ret = %d", ret);
            break;
        }

        ret = CmAppCertificateInfoPack(&certificateInfo, &certBlob, &keyUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmAppCertificateInfoPack fail, ret = %d", ret);
        }
    } while (0);

    CmSendResponse(context, ret, &certificateInfo);
    CmFreeParamSet(&paramSet);
    CM_FREE_BLOB(certBlob);
    CM_FREE_BLOB(certificateInfo);
    CM_LOG_I("CmIpcServiceGetAppCert end:%d", ret);
}

static int32_t GetInputParams(const struct CmBlob *paramSetBlob, struct CmParamSet **paramSet,
    struct CmContext *cmContext, struct CmParamOut *params, uint32_t paramsCount)
{
    int32_t ret = CmGetProcessInfoForIPC(cmContext);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get ipc info failed, ret = %d", ret);
        return ret;
    }

    /* The paramSet blob pointer needs to be refreshed across processes. */
    ret = CmGetParamSet((struct CmParamSet *)paramSetBlob->data, paramSetBlob->size, paramSet);
    if (ret != HKS_SUCCESS) {
        CM_LOG_E("get paramSet failed, ret = %d", ret);
        return ret;
    }

    ret = CmParamSetToParams(*paramSet, params, paramsCount);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get params from paramSet failed, ret = %d", ret);
        CmFreeParamSet(paramSet); /* if success no need free paramSet */
    }

    return ret;
}

static int32_t GetAuthedList(const struct CmContext *context, const struct CmBlob *keyUri, struct CmBlob *outData)
{
    if (outData->size < sizeof(uint32_t)) { /* appUidCount size */
        CM_LOG_E("invalid outData size[%u]", outData->size);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t count = (outData->size - sizeof(uint32_t)) / sizeof(uint32_t);
    struct CmAppUidList appUidList = { count, NULL };
    if (count != 0) {
        appUidList.appUid = (uint32_t *)(outData->data + sizeof(uint32_t));
    }

    int32_t ret = CmServiceGetAuthorizedAppList(context, keyUri, &appUidList);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("service get authed list failed, ret = %d", ret);
        return ret;
    }

    /* refresh outData:  1.refresh appUidCount; 2.appUidCount is no bigger than count */
    (void)memcpy_s(outData->data, sizeof(uint32_t), &appUidList.appUidCount, sizeof(uint32_t));
    outData->size = sizeof(uint32_t) + sizeof(uint32_t) * appUidList.appUidCount;

    return CM_SUCCESS;
}

void CmIpcServiceGrantAppCertificate(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    struct CmContext cmContext = { 0, 0, {0} };
    struct CmParamSet *paramSet = NULL;
    struct CmBlob keyUri = { 0, NULL };
    int32_t ret;
    do {
        uint32_t appUid = 0;
        struct CmParamOut params[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = &keyUri },
            { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = &appUid },
        };
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get input params failed, ret = %d", ret);
            break;
        }

        ret = CmServiceGrantAppCertificate(&cmContext, &keyUri, appUid, outData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("service grant app failed, ret = %d", ret);
            break;
        }
    } while (0);

    CmReport(__func__, context, (char *)keyUri.data, ret);

    CM_LOG_I("CmIpcServiceGrantAppCertificate end:%d", ret);
    CmSendResponse(context, ret, outData);
    CmFreeParamSet(&paramSet);
}

void CmIpcServiceGetAuthorizedAppList(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    struct CmContext cmContext = { 0, 0, {0} };
    struct CmParamSet *paramSet = NULL;
    struct CmBlob keyUri = { 0, NULL };

    int32_t ret;
    do {
        struct CmParamOut params[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = &keyUri },
        };
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get input params failed, ret = %d", ret);
            break;
        }

        ret = GetAuthedList(&cmContext, &keyUri, outData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get authed app list failed, ret = %d", ret);
            break;
        }
    } while (0);
    CmReport(__func__, context, (char *)keyUri.data, ret);

    CM_LOG_I("CmIpcServiceGetAuthorizedAppList end:%d", ret);
    CmSendResponse(context, ret, outData);
    CmFreeParamSet(&paramSet);
}

void CmIpcServiceIsAuthorizedApp(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    (void)outData;
    struct CmContext cmContext = { 0, 0, {0} };
    struct CmParamSet *paramSet = NULL;
    struct CmBlob authUri = { 0, NULL };

    int32_t ret;
    do {
        struct CmParamOut params[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = &authUri },
        };
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get input params failed, ret = %d", ret);
            break;
        }

        ret = CmServiceIsAuthorizedApp(&cmContext, &authUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("service check is authed app failed, ret = %d", ret);
            break;
        }
    } while (0);

    CmReport(__func__, context, (char *)authUri.data, ret);
    CM_LOG_I("CmIpcServiceIsAuthorizedApp end:%d", ret);
    CmSendResponse(context, ret, NULL);
    CmFreeParamSet(&paramSet);
}

void CmIpcServiceRemoveGrantedApp(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    struct CmContext cmContext = { 0, 0, {0} };
    struct CmParamSet *paramSet = NULL;
    (void)outData;
    struct CmBlob keyUri = { 0, NULL };

    int32_t ret;
    do {
        uint32_t appUid = 0;
        struct CmParamOut params[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = &keyUri },
            { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = &appUid },
        };
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get input params failed, ret = %d", ret);
            break;
        }

        ret = CmServiceRemoveGrantedApp(&cmContext, &keyUri, appUid);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("service remove grant app failed, ret = %d", ret);
            break;
        }
    } while (0);
    CmReport(__func__, context, (char *)keyUri.data, ret);

    CM_LOG_I("CmIpcServiceRemoveGrantedApp end:%d", ret);
    CmSendResponse(context, ret, NULL);
    CmFreeParamSet(&paramSet);
}

void CmIpcServiceInit(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    struct CmContext cmContext = { 0, 0, {0} };
    struct CmParamSet *paramSet = NULL;

    int32_t ret;
    do {
        struct CmBlob authUri = { 0, NULL };
        struct CmBlob specBlob = { 0, NULL };
        struct CmParamOut params[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = &authUri },
            { .tag = CM_TAG_PARAM1_BUFFER, .blob = &specBlob },
        };
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get input params failed, ret = %d", ret);
            break;
        }

        struct CmSignatureSpec spec = { 0 };
        if (specBlob.size < sizeof(struct CmSignatureSpec)) {
            CM_LOG_E("invalid input spec size");
            ret = CMR_ERROR_INVALID_ARGUMENT;
            break;
        }
        (void)memcpy_s(&spec, sizeof(struct CmSignatureSpec), specBlob.data, sizeof(struct CmSignatureSpec));

        ret = CmServiceInit(&cmContext, &authUri, &spec, outData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("service init failed, ret = %d", ret);
            break;
        }
    } while (0);

    CM_LOG_I("CmIpcServiceInit end:%d", ret);
    CmSendResponse(context, ret, outData);
    CmFreeParamSet(&paramSet);
}

void CmIpcServiceUpdate(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    (void)outData;
    struct CmContext cmContext = { 0, 0, {0} };
    struct CmParamSet *paramSet = NULL;

    int32_t ret;
    do {
        struct CmBlob handleUpdate = { 0, NULL };
        struct CmBlob inDataUpdate = { 0, NULL };
        struct CmParamOut params[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = &handleUpdate },
            { .tag = CM_TAG_PARAM1_BUFFER, .blob = &inDataUpdate },
        };
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get input params failed, ret = %d", ret);
            break;
        }

        ret = CmServiceUpdate(&cmContext, &handleUpdate, &inDataUpdate);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("service update failed, ret = %d", ret);
            break;
        }
    } while (0);

    CM_LOG_I("CmIpcServiceUpdate end:%d", ret);
    CmSendResponse(context, ret, NULL);
    CmFreeParamSet(&paramSet);
}

void CmIpcServiceFinish(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    struct CmContext cmContext = { 0, 0, {0} };
    struct CmParamSet *paramSet = NULL;

    int32_t ret;
    do {
        struct CmBlob handleFinish = { 0, NULL };
        struct CmBlob inDataFinish = { 0, NULL };
        struct CmParamOut params[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = &handleFinish },
            { .tag = CM_TAG_PARAM1_BUFFER, .blob = &inDataFinish },
        };
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get input params failed, ret = %d", ret);
            break;
        }

        ret = CmServiceFinish(&cmContext, &handleFinish, &inDataFinish, outData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("service finish failed, ret = %d", ret);
            break;
        }
    } while (0);

    CM_LOG_I("CmIpcServiceFinish end:%d", ret);
    CmSendResponse(context, ret, outData);
    CmFreeParamSet(&paramSet);
}

void CmIpcServiceAbort(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    (void)outData;
    struct CmContext cmContext = { 0, 0, {0} };
    struct CmParamSet *paramSet = NULL;

    int32_t ret;
    do {
        struct CmBlob handle = { 0, NULL };
        struct CmParamOut params[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = &handle },
        };
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get input params failed, ret = %d", ret);
            break;
        }

        ret = CmServiceAbort(&cmContext, &handle);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("service abort failed, ret = %d", ret);
            break;
        }
    } while (0);

    CM_LOG_I("CmIpcServiceAbort end:%d", ret);
    CmSendResponse(context, ret, NULL);
    CmFreeParamSet(&paramSet);
}

void CmIpcServiceGetUserCertList(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret = CM_SUCCESS;
    uint32_t store;
    struct CmContext cmContext = {0};
    struct CmParamSet *paramSet = NULL;
    struct CmMutableBlob certFileList = { 0, NULL };
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = &store },
    };

    do {
        if (!CmHasCommonPermission()) {
            CM_LOG_E("caller no permission");
            ret = CMR_ERROR_PERMISSION_DENIED;
            break;
        }

        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetUserCertList get input params failed, ret = %d", ret);
            break;
        }

        ret = CmServiceGetCertList(&cmContext, store, &certFileList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertList failed, ret = %d", ret);
            break;
        }

        ret = CmServiceGetCertListPack(&cmContext, store, &certFileList, outData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmServiceGetCertListPack pack fail, ret = %d", ret);
            break;
        }

        CmSendResponse(context, ret, outData);
    } while (0);

    CmReport(__func__, &cmContext, "NULL", ret);

    if (ret != CM_SUCCESS) {
        CmSendResponse(context, ret, NULL);
    }
    CmFreeCertFiles(&certFileList);
    CmFreeParamSet(&paramSet);
}

void CmIpcServiceGetUserCertInfo(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret = CM_SUCCESS;
    uint32_t store;
    uint32_t status = 0;
    struct CmBlob certUri = { 0, NULL };
    struct CmBlob certificateData = { 0, NULL };
    struct CmContext cmContext = {0};
    struct CmParamSet *paramSet = NULL;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &certUri},
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = &store},
    };

    do {
        if (!CmHasCommonPermission()) {
            CM_LOG_E("caller no permission");
            ret = CMR_ERROR_PERMISSION_DENIED;
            break;
        }

        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetUserCertInfo get input params failed, ret = %d", ret);
            break;
        }

        ret = CmGetServiceCertInfo(&cmContext, &certUri, store, &certificateData, &status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertInfo failed, ret = %d", ret);
            break;
        }

        ret = CmServiceGetCertInfoPack(&certificateData, status, outData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmServiceGetCertInfoPack pack failed, ret = %d", ret);
            break;
        }
        CmSendResponse(context, ret, outData);
    } while (0);
    CmReport(__func__, &cmContext, (char *)certUri.data, ret);
    if (ret != CM_SUCCESS) {
        CmSendResponse(context, ret, NULL);
    }
    CM_FREE_BLOB(certificateData);
    CmFreeParamSet(&paramSet);
}

void CmIpcServiceSetUserCertStatus(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret = CM_SUCCESS;
    uint32_t store;
    uint32_t status;
    struct CmBlob certUri = { 0, NULL };
    struct CmContext cmContext = {0};
    struct CmParamSet *paramSet = NULL;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &certUri},
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = &store},
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = &status},
    };

    do {
        if (!CmHasCommonPermission() || !CmHasPrivilegedPermission()) {
            CM_LOG_E("caller no permission");
            ret = CMR_ERROR_PERMISSION_DENIED;
            break;
        }

        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("SetUserCertStatus get input params failed, ret = %d", ret);
            break;
        }

        ret = CertManagerSetCertificatesStatus(&cmContext, &certUri, store, status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("set cert status failed, ret = %d", ret);
            break;
        }
    } while (0);
    CmSendResponse(context, ret, NULL);
    CmFreeParamSet(&paramSet);
}

void CmIpcServiceInstallUserCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret = CM_SUCCESS;
    struct CmBlob userCert = { 0, NULL };
    struct CmBlob certAlias = { 0, NULL };
    struct CmContext cmContext = {0};
    struct CmParamSet *paramSet = NULL;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &userCert },
        { .tag = CM_TAG_PARAM1_BUFFER, .blob = &certAlias },
    };

    do {
        if (!CmHasCommonPermission() || !CmHasPrivilegedPermission()) {
            CM_LOG_E("caller no permission");
            ret = CMR_ERROR_PERMISSION_DENIED;
            break;
        }

        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("InstallUserCert get input params failed, ret = %d", ret);
            break;
        }

        ret = CmInstallUserCert(&cmContext, &userCert, &certAlias, outData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerInstallUserCert fail, ret = %d", ret);
        }

        CmSendResponse(context, ret, outData);
    } while (0);

    CmReport(__func__, &cmContext, "NULL", ret);

    if (ret != CM_SUCCESS) {
        CmSendResponse(context, ret, NULL);
    }
    CmFreeParamSet(&paramSet);
}

void CmIpcServiceUninstallUserCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    (void)outData;
    int32_t ret = CM_SUCCESS;
    struct CmBlob certUri = { 0, NULL };
    struct CmContext cmContext = {0};
    struct CmParamSet *paramSet = NULL;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &certUri },
    };

    do {
        if (!CmHasCommonPermission() || !CmHasPrivilegedPermission()) {
            CM_LOG_E("caller no permission");
            ret = CMR_ERROR_PERMISSION_DENIED;
            break;
        }

        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UninstallUserCert get input params failed, ret = %d", ret);
            break;
        }

        ret = CmUninstallUserCert(&cmContext, &certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerUninstallUserCert fail, ret = %d", ret);
            break;
        }
    } while (0);
    CmReport(__func__, &cmContext, (char *)certUri.data, ret);
    CmSendResponse(context, ret, NULL);
    CmFreeParamSet(&paramSet);
}

void CmIpcServiceUninstallAllUserCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    (void)outData;
    int32_t ret = CM_SUCCESS;
    struct CmContext cmContext = {0};

    do {
        if (!CmHasCommonPermission() || !CmHasPrivilegedPermission()) {
            CM_LOG_E("caller no permission");
            ret = CMR_ERROR_PERMISSION_DENIED;
            break;
        }

        ret = CmGetProcessInfoForIPC(&cmContext);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmGetProcessInfoForIPC fail, ret = %d", ret);
            break;
        }

        ret = CmUninstallAllUserCert(&cmContext);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerUninstallAllUserCert fail, ret = %d", ret);
            break;
        }
    } while (0);

    CmSendResponse(context, ret, NULL);

}

