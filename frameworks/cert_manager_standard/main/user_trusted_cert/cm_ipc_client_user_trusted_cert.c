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

#include "cm_ipc_client_user_trusted_cert.h"
#include "cm_ipc_check.h"

#include "cm_ipc_serialization.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_x509.h"
#include "cm_param.h"

#include "cm_request_user_trusted_cert.h"

static int32_t GetCertListInitBlob(const struct CmBlob *outBlob, struct CertList *certificateList)
{
    uint32_t buffSize;
    int32_t ret = CM_SUCCESS;
    buffSize = sizeof(uint32_t) + (sizeof(uint32_t) + MAX_LEN_SUBJECT_NAME + sizeof(uint32_t) + sizeof(uint32_t) +
        MAX_LEN_URI + sizeof(uint32_t) +  MAX_LEN_CERT_ALIAS) * MAX_COUNT_CERTIFICATE;

    do {
        outBlob->data = (uint8_t *)CmMalloc(buffSize);
        if (outBlob->data == NULL) {
            ret = CMR_ERROR_MALLOC_FAIL;
            CM_FREE_BLOB(*outBlob);
            break;
        }
        outBlob->size = buffSize;

        buffSize = (MAX_COUNT_CERTIFICATE * sizeof(struct CertAbstract));
        certificateList->certAbstract = (struct CertAbstract *)CmMalloc(buffSize);
        if (certificateList->certAbstract == NULL) {
            ret = CMR_ERROR_MALLOC_FAIL;
            CM_FREE_BLOB(*outBlob);
            CmFree(certificateList->certAbstract);
            break;
        }
        certificateList->certsCount = MAX_COUNT_CERTIFICATE;

        if (memset_s(certificateList->certAbstract, buffSize, 0, buffSize) != EOK) {
            CM_LOG_E("init certAbstract failed");
            ret = CMR_ERROR_BAD_STATE;
            CM_FREE_BLOB(*outBlob);
            CmFree(certificateList->certAbstract);
            break;
        }
    } while (0);

    return ret;
}

static int32_t CmSendParcelInit(const struct CmParam *params, uint32_t cnt,
    struct CmParamSet *sendParamSet, struct CmBlob *parcelBlob)
{
    int32_t ret = CmParamsToParamSet(params, CM_ARRAY_SIZE(params), &sendParamSet);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("install CmParamSetPack fail");
        break;
    }

    parcelBlob->size = sendParamSet->paramSetSize;
    parcelBlob->data = (uint8_t *)sendParamSet;
    return ret;
}

static int32_t GetCertificateList01(enum CmMessage type, const uint32_t store,
    struct CertList *certificateList)
{
    struct CmBlob outBlob = {0, NULL};
    struct CmBlob parcelBlob = {0, NULL};
    const struct CmContext context = {0};
    struct CmParamSet *sendParamSet = NULL;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_UINT32,
          .uint32Param = store },
    };

    do {
        int32_t ret = CmSendParcelInit(params, CM_ARRAY_SIZE(params), &sendParamSet, &parcelBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("install CmParamSetPack fail");
            break;
        }

        ret = GetCertListInitBlob(&outBlob, certificateList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertListInitBlob fail");
            break;
        }

        ret = SendRequest(type, &parcelBlob, &outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertList request fail");
            break;
        }

        ret = CmCertificateListUnpackFromService(&outBlob, false, &context, certificateList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmCertificatetListUnpackFromService fail");
            break;
        }
    } while (0);

    CmFreeParamSet(&sendParamSet);
    CM_FREE_BLOB(outBlob);
    return ret;
}

int32_t CmClientGetCertList01(const uint32_t store, struct CertList *certificateList)
{
    return GetCertificateList01(CM_MSG_GET_CERTIFICATE_LIST, store, certificateList);
}

static int32_t GetCertInfoInitBlob(struct CmBlob *outBlob, struct CertInfo *certificateInfo)
{
    int32_t ret = CM_SUCCESS;
    uint32_t buffSize;
    buffSize = sizeof(uint32_t) + MAX_LEN_CERTIFICATE + sizeof(uint32_t);

    do {
        outBlob->data = (uint8_t *)CmMalloc(buffSize);
        if (outBlob->data == NULL) {
            ret = CMR_ERROR_MALLOC_FAIL;
            CM_FREE_BLOB(*outBlob);
            break;
        }
        outBlob->size = buffSize;

        certificateInfo->certInfo.data = (uint8_t *)CmMalloc(MAX_LEN_CERTIFICATE);
        if (certificateInfo->certInfo.data == NULL) {
            ret = CMR_ERROR_MALLOC_FAIL;
            CM_FREE_BLOB(*outBlob);
            break;
        }
        certificateInfo->certInfo.size = MAX_LEN_CERTIFICATE;
    } while (0);

    return ret;
}

static int32_t GetCertificateInfo01(enum CmMessage type, const struct CmBlob *certUri,
    const uint32_t store, struct CertInfo *certificateInfo)
{
    struct CmBlob outBlob = {0, NULL};
    struct CmBlob parcelBlob = {0, NULL};
    const struct CmContext context = {0};
    struct CmParamSet *sendParamSet = NULL;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER,
          .blob = *certUri },
        { .tag = CM_TAG_PARAM0_UINT32,
          .uint32Param = store },
    };

    do {
        int32_t ret = CmSendParcelInit(params, CM_ARRAY_SIZE(params), &sendParamSet, &parcelBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("install CmParamSetPack fail");
            break;
        }

        ret = GetCertInfoInitBlob(&outBlob, certificateInfo);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertListInitBlob fail");
            break;
        }

        ret = SendRequest(type, &parcelBlob, &outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertList request fail");
            break;
        }

        ret = CmCertificateInfoUnpackFromService(&outBlob, &context, certificateInfo, certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmCertificatetListUnpackFromService fail");
            break;
        }
    } while (0);

    CmFreeParamSet(&sendParamSet);
    CM_FREE_BLOB(outBlob);
    return ret;
}

int32_t CmClientGetCertInfo01(const struct CmBlob *certUri, const uint32_t store,
    struct CertInfo *certificateInfo)
{
    return GetCertificateInfo01(CM_MSG_GET_CERTIFICATE_INFO, certUri, store, certificateInfo);
}

static int32_t SetCertificateStatus01(enum CmMessage type, const struct CmBlob *certUri,
    const uint32_t store, const uint32_t status)
{
    struct CmBlob parcelBlob = {0, NULL};
    struct CmParamSet *sendParamSet = NULL;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER,
          .blob = *certUri },
        { .tag = CM_TAG_PARAM0_UINT32,
          .uint32Param = store },
        { .tag = CM_TAG_PARAM1_UINT32,
          .uint32Param = status },
    };

    do {
        int32_t ret = CmSendParcelInit(params, CM_ARRAY_SIZE(params), &sendParamSet, &parcelBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("install CmParamSetPack fail");
            break;
        }

        ret = SendRequest(type, &parcelBlob, NULL);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("SetCertStatus CmParamSet send fail");
            break;
        }
    } while (0);

    CmFreeParamSet(&sendParamSet);
    return ret;
}

int32_t CmClientSetCertStatus01(const struct CmBlob *certUri, const uint32_t store,
    const uint32_t status)
{
    return SetCertificateStatus01(CM_MSG_SET_CERTIFICATE_STATUS, certUri, store, status);
}

static int32_t InstallUserCertInitBlob(struct CmBlob *outBlob, struct CmBlob *certUri)
{
    int32_t ret = CM_SUCCESS;
    uint32_t buffSize;

    do {
        buffSize = sizeof(uint32_t) + MAX_LEN_URI;
        outBlob->data = (uint8_t *)CmMalloc(buffSize);
        if (outBlob->data == NULL) {
            CM_LOG_E("InstallUserCert malloc OutBlob fail");
            ret = CMR_ERROR_MALLOC_FAIL;
            break;
        }
        outBlob->size = buffsize;

        certUri->data = (uint8_t *)CMMalloc(MAX_LEN_URI);
        if (certUri->data == NULL) {
            ret = CMR_ERROR_MALLOC_FAIL;
            CM_LOG_E("InstallUserCert malloc certUri fail");
            break;
        }
        certUri->size = MAX_LEN_URI;
        if (memset_s(certUri->data, MAX_LEN_URI, 0, MAX_LEN_URI) != EOK) {
            CM_LOG_E("init certUri fail");
            ret = CMR_ERROR_BAD_STATE;
            break;
        }
    } while (0);
    if (certUri->data != NULL) {
        CM_FREE_BLOB(certUri);
    }
    return ret;
}

int32_t CmInstallUserCertUnpackFromService(const struct CmBlob *outData,
    struct CmBlob *certUri)
{
    uint32_t offset = 0;
    struct CmBlob blob;
    if ((outData == NULL) || (certUri == NULL) || (outData->data == NULL) ||
        (certUri->data == NULL)) {
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = CmGetBlobFromBuffer(&blob, outData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmInstallUserCert get certUri faild");
        return ret;
    }
    certUri->size = blob.size;
    if (memcpy_s(certUri->data, MAX_LEN_URI, blob.data, blob.size) != EOK) {
        CM_LOG_E("copy certuri failed");
        return CMR_ERROR_BAD_STATE;
    }

    return CM_SUCCESS;
}

static int32_t InstallUserCert(enum CmMessage type, const struct CmBlob *userCert, const struct CmBlob *certAlias,
    struct CmBlob *certUri)
{
    struct CmBlob parcelBlob = {0, NULL};
    struct CmParamSet *sendParamSet = NULL;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER,
          .blob = *userCert },
        { .tag = CM_TAG_PARAM1_BUFFER,
          .blob = *certAlias },
    };
    struct CmBlob outBlob = {0, NULL};

    do {
        int32_t ret = CmSendParcelInit(params, CM_ARRAY_SIZE(params), &sendParamSet, &parcelBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("install CmParamSetPack fail");
            break;
        }

        ret = InstallUserCertInitBlob(&outBlob, certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("init blob fail");
            break;
        }

        ret = SendRequest(type, &parcelBlob, &outBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("install CmParamSet send fail");
            break;
        }

        ret = CmInstallUserCertUnpackFromService(&outBlob, certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmInstallUserCertUnpackFromService fail");
            break;
        }
    } while (0);
    CmFreeParamSet(&sendParamSet);
    CM_FREE_BLOB(outBlob);
    return ret;
}

int32_t CmClientInstallUserTrustedCert(const struct CmBlob *userCert, const struct CmBlob *certAlias,
    struct CmBlob *certUri)
{
    return InstallUserCert(CM_MSG_INSTALL_USER_CERTIFICATE, userCert, certAlias, certUri);
}

static int32_t UninstallUserCert(enum CmMessage type, const struct CmBlob *certUri)
{
    struct CmParamSet *sendParamSet = NULL;
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER,
          .blob = *certUri },
    };
    struct CmBlob parcelBlob = {0, NULL};

    do {
        int32_t ret = CmSendParcelInit(params, CM_ARRAY_SIZE(params), &sendParamSet, &parcelBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("install CmParamSetPack fail");
            break;
        }

        ret = SendRequest(type, &parcelBlob, NULL);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("uninstall CmParamSet send fail");
            break;
        }
    } while (0);
    CmFreeParamSet(&sendParamSet);
    return ret;
}

int32_t CmClientUninstallUserTrustedCert(const struct CmBlob *certUri)
{
    return UninstallUserCert(CM_MSG_UNINSTALL_USER_CERTIFICATE, certUri);
}

static int32_t UninstallAllUserCert(enum CmMessage type)
{
    struct CmParamSet *sendParamSet = NULL;
    struct CmBlob parcelBlob = {
        .size = sendParamSet->paramSetSize,
        .data = (uint8_t *)sendParamSet
    };

    ret = SendRequest(type, &parcelBlob, NULL);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uninstall all CmParamSet send fail");
        break;
    }
    CmFreeParamSet(&sendParamSet);
    return ret;
}

int32_t CmClientUninstallAllUserTrustedCert(void)
{
    return UninstallAllUserCert(CM_MSG_UNINSTALL_ALL_USER_CERTIFICATE);
}
