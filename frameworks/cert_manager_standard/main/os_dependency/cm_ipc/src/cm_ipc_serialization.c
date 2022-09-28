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

#include "cm_ipc_serialization.h"

#include "cm_log.h"
#include "cm_mem.h"

#include "cm_param.h"
#include "cm_x509.h"

int32_t CopyUint32ToBuffer(uint32_t value, const struct CmBlob *destBlob, uint32_t *destOffset)
{
    if ((*destOffset > destBlob->size) || ((destBlob->size - *destOffset) < sizeof(value))) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    if (memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, &value, sizeof(value)) != EOK) {
        return CMR_ERROR_INVALID_OPERATION;
    }
    *destOffset += sizeof(value);
    return CM_SUCCESS;
}

int32_t CopyBlobToBuffer(const struct CmBlob *blob, const struct CmBlob *destBlob, uint32_t *destOffset)
{
    if ((*destOffset > destBlob->size) ||
        ((destBlob->size - *destOffset) < (sizeof(blob->size) + ALIGN_SIZE(blob->size)))) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    if (memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset,
                 &(blob->size), sizeof(blob->size)) != EOK) {
        return CMR_ERROR_INVALID_OPERATION;
    }
    *destOffset += sizeof(blob->size);

    if (memcpy_s(destBlob->data + *destOffset, destBlob->size - *destOffset, blob->data, blob->size) != EOK) {
        *destOffset -= sizeof(blob->size);
        return CMR_ERROR_INVALID_OPERATION;
    }
    *destOffset += ALIGN_SIZE(blob->size);
    return CM_SUCCESS;
}

int32_t GetUint32FromBuffer(uint32_t *value, const struct CmBlob *srcBlob, uint32_t *srcOffset)
{
    if ((*srcOffset > srcBlob->size) || (srcBlob->size - *srcOffset < sizeof(uint32_t))) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    if (memcpy_s(value, sizeof(uint32_t), srcBlob->data + *srcOffset, sizeof(uint32_t)) != EOK) {
        return CMR_ERROR_INVALID_OPERATION;
    }

    *srcOffset += sizeof(uint32_t);
    return CM_SUCCESS;
}

int32_t CmGetBlobFromBuffer(struct CmBlob *blob, const struct CmBlob *srcBlob, uint32_t *srcOffset)
{
    if ((*srcOffset > srcBlob->size) || ((srcBlob->size - *srcOffset) < sizeof(uint32_t))) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    uint32_t size = *((uint32_t *)(srcBlob->data + *srcOffset));
    if (ALIGN_SIZE(size) > srcBlob->size - *srcOffset - sizeof(uint32_t)) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    blob->size = size;
    *srcOffset += sizeof(blob->size);
    blob->data = (uint8_t *)(srcBlob->data + *srcOffset);
    *srcOffset += ALIGN_SIZE(blob->size);
    return CM_SUCCESS;
}

static int32_t CmCopyCmContextToBuffer(const struct CmContext *cmContext, struct CmBlob *inData, uint32_t *offset)
{
    int32_t ret;
    ret = CopyUint32ToBuffer(cmContext->userId, inData, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy cmContext->userId failed");
        return ret;
    }

    ret = CopyUint32ToBuffer(cmContext->uid, inData, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy cmContext->uid failed");
        return ret;
    }

    struct CmBlob packageName = {MAX_LEN_PACKGE_NAME, (uint8_t *)cmContext->packageName};
    ret = CopyBlobToBuffer(&packageName, inData, offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy cmContext->packageName failed");
        return ret;
    }
    return ret;
}

int32_t CmCertificateInfoPack(struct CmBlob *inData, const struct CmContext *cmContext,
    const struct CmBlob *certUri, const uint32_t store)
{
    int32_t ret;
    uint32_t offset = 0;

    ret = CmCopyCmContextToBuffer(cmContext, inData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy cmContext failed");
        return ret;
    }

    ret = CopyBlobToBuffer(certUri, inData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy certUri failed");
        return ret;
    }

    ret = CopyUint32ToBuffer(store, inData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy store failed");
        return ret;
    }
    return ret;
}

int32_t CmCertificateListPack(struct CmBlob *inData, const struct CmContext *cmContext, const uint32_t store)
{
    int32_t ret;
    uint32_t offset = 0;

    ret = CmCopyCmContextToBuffer(cmContext, inData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy cmContext failed");
        return ret;
    }

    ret = CopyUint32ToBuffer(store, inData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy store failed");
        return ret;
    }
    return ret;
}

int32_t CmCertificateListUnpackFromService(const struct CmBlob *outData, bool needEncode,
    const struct CmContext *context, struct CertList *certificateList)
{
    uint32_t offset = 0, status = 0;
    struct CmBlob blob = {0};
    if ((outData == NULL) || (context == NULL) || (certificateList == NULL) ||
        (outData->data == NULL) || (certificateList->certAbstract == NULL)) {
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = GetUint32FromBuffer(&(certificateList->certsCount), outData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get certificateList->certsCount failed");
        return ret;
    }
    for (uint32_t i = 0; i < certificateList->certsCount; i++) {
        ret = CmGetBlobFromBuffer(&blob, outData, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Get subjectNameBlob FromBuffer");
            return ret;
        }
        if (memcpy_s(certificateList->certAbstract[i].subjectName, MAX_LEN_SUBJECT_NAME, blob.data, blob.size) != EOK) {
            CM_LOG_E("copy subjectName failed");
            return CMR_ERROR_INVALID_OPERATION;
        }
        ret = GetUint32FromBuffer(&status, outData, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("copy status failed");
            return ret;
        }
        certificateList->certAbstract[i].status = (status >= 1) ? false : true;
        ret = CmGetBlobFromBuffer(&blob, outData, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("copy uri failed");
            return ret;
        }

        if (memcpy_s(certificateList->certAbstract[i].uri, MAX_LEN_URI, blob.data, blob.size) != EOK) {
            CM_LOG_E("copy uri failed");
            return CMR_ERROR_INVALID_OPERATION;
        }

        ret = CmGetBlobFromBuffer(&blob, outData, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("copy certAlias failed");
            return ret;
        }
        if (memcpy_s(certificateList->certAbstract[i].certAlias, MAX_LEN_CERT_ALIAS, blob.data, blob.size) != EOK) {
            CM_LOG_E("copy certAlias failed");
            return CMR_ERROR_INVALID_OPERATION;
        }
    }
    return CM_SUCCESS;
}

int32_t CmCertificateInfoUnpackFromService(const struct CmBlob *outData,
    const struct CmContext *context, struct CertInfo *certificateInfo, const struct CmBlob *certUri)
{
    struct CmBlob blob;
    uint32_t offset = 0, status = 0;

    if ((outData == NULL) || (context == NULL) || (certificateInfo == NULL) ||
        (outData->data == NULL) || (certificateInfo->certInfo.data == NULL)) {
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = CmGetBlobFromBuffer(&blob, outData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmCertificateInfo get certInfo faild");
        return ret;
    }
    certificateInfo->certInfo.size = blob.size;
    if (memcpy_s(certificateInfo->certInfo.data, MAX_LEN_CERTIFICATE, blob.data, blob.size) != EOK) {
        CM_LOG_E("copy cert data failed");
        return CMR_ERROR_INVALID_OPERATION;
    }

    ret = GetUint32FromBuffer(&(status), outData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("copy status failed");
        return ret;
    }
    certificateInfo->status = (status >= 1) ?  false : true;

    X509 *x509cert = InitCertContext(certificateInfo->certInfo.data, certificateInfo->certInfo.size);

    GetX509SubjectNameLongFormat(x509cert, certificateInfo->subjectName, MAX_LEN_SUBJECT_NAME);
    GetX509IssueNameLongFormat(x509cert, certificateInfo->issuerName, MAX_LEN_ISSUER_NAME);
    GetX509SerialNumber(x509cert, certificateInfo->serial, MAX_LEN_SERIAL);
    GetX509NotBefore(x509cert, certificateInfo->notBefore, MAX_LEN_NOT_BEFORE);
    GetX509NotAfter(x509cert, certificateInfo->notAfter, MAX_LEN_NOT_AFTER);
    GetX509Fingerprint(x509cert, certificateInfo->fingerprintSha256, MAX_LEN_FINGER_PRINT_SHA256);
    GetX509SubjectName(x509cert, CM_ORGANIZATION_NAME, certificateInfo->certAlias, MAX_LEN_CERT_ALIAS);

    FreeCertContext(x509cert);

    if (memset_s(certificateInfo->uri, MAX_LEN_URI, 0, MAX_LEN_URI) != EOK) {
        CM_LOG_E("init uri failed");
        return CMR_ERROR_INVALID_OPERATION;
    }
    if (memcpy_s(certificateInfo->uri, MAX_LEN_URI, certUri->data, certUri->size) != EOK) {
        CM_LOG_E("copy uri failed");
        return CMR_ERROR_INVALID_OPERATION;
    }
    return CM_SUCCESS;
}

int32_t CmCertificateStatusPack(struct CmBlob *inData, const struct CmContext *cmContext, const struct CmBlob *certUri,
    const uint32_t store, const uint32_t status)
{
    int32_t ret;
    uint32_t offset = 0;

    ret = CmCopyCmContextToBuffer(cmContext, inData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CertificateStatus copy cmContext failed");
        return ret;
    }

    ret = CopyBlobToBuffer(certUri, inData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CertificateStatus copy certUri failed");
        return ret;
    }

    ret = CopyUint32ToBuffer(store, inData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CertificateStatus copy store failed");
        return ret;
    }

    ret = CopyUint32ToBuffer(status, inData, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CertificateStatus copy store failed");
        return ret;
    }
    return ret;
}

int32_t CmParamsToParamSet(struct CmParam *params, uint32_t cnt, struct CmParamSet **outParamSet)
{
    struct CmParamSet *newParamSet = NULL;

    int32_t ret = CmInitParamSet(&newParamSet);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("init param set failed");
        return ret;
    }

    do {
        uint8_t tmpData = 0;
        struct CmBlob tmpBlob = { sizeof(tmpData), &tmpData };
        for (uint32_t i = 0; i < cnt; ++i) {
            if ((GetTagType(params[i].tag) == CM_TAG_TYPE_BYTES) &&
                (params[i].blob.size == 0 || params[i].blob.data == NULL)) {
                params[i].tag += CM_PARAM_BUFFER_NULL_INTERVAL;
                params[i].blob = tmpBlob;
            }
        }

        ret = CmAddParams(newParamSet, params, cnt);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("add in params failed");
            break;
        }

        ret = CmBuildParamSet(&newParamSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("build paramset failed!");
            break;
        }
    } while (0);
    if (ret != CM_SUCCESS) {
        CmFreeParamSet(&newParamSet);
        return ret;
    }

    *outParamSet = newParamSet;

    return ret;
}
