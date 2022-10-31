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

#include "cm_log.h"
#include "cm_mem.h"
#include "cm_ipc_service_serialization.h"

#include "cm_param.h"
#include "cm_pfx.h"
#include "cm_report_wrapper.h"
#include "cm_response.h"
#include "cm_type.h"

#include "cert_manager.h"
#include "cert_manager_check.h"
#include "cert_manager_key_operation.h"
#include "cert_manager_permission_check.h"
#include "cert_manager_query.h"
#include "cert_manager_service.h"
#include "cert_manager_status.h"
#include "cert_manager_uri.h"

#define MAX_LEN_CERTIFICATE     8196

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
    if (ret != CM_SUCCESS) {
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

void CmIpcServiceGetCertificateList(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret;
    uint32_t store;
    struct CmContext cmContext = {0};
    struct CmMutableBlob certFileList = { 0, NULL };
    struct CmParamSet *paramSet = NULL;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = &store },
    };

    do {
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCaCertList get input params failed, ret = %d", ret);
            break;
        }

        ret = CmServiceGetSystemCertListCheck(store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmIpcServiceGetSystemCertCheck fail, ret = %d", ret);
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

    if (ret != CM_SUCCESS) {
        CmSendResponse(context, ret, NULL);
    }
    CmFreeCertFiles(&certFileList);
    CmFreeParamSet(&paramSet);
}

void CmIpcServiceGetCertificateInfo(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret;
    uint32_t status = 0;
    uint32_t store;
    struct CmContext cmContext = {0};
    struct CmBlob certificateData = { 0, NULL };
    struct CmBlob certUri = { 0, NULL };
    struct CmParamSet *paramSet = NULL;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &certUri},
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = &store},
    };

    do {
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetUserCertInfo get input params failed, ret = %d", ret);
            break;
        }

        ret = CmServiceGetSystemCertCheck(store, &certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmServiceGetSystemCertCheck failed, ret = %d", ret);
            break;
        }

        ret = CmServiceGetCertInfo(&cmContext, &certUri, store, &certificateData, &status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertInfo failed, ret = %d", ret);
            break;
        }

        ret = CmServiceGetCertInfoPack(store, &certificateData, status, &certUri, outData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmServiceGetCertInfoPack pack failed, ret = %d", ret);
            break;
        }

        CmSendResponse(context, ret, outData);
    } while (0);

    if (ret != CM_SUCCESS) {
        CmSendResponse(context, ret, NULL);
    }
    CM_FREE_BLOB(certificateData);
    CmFreeParamSet(&paramSet);
}

void CmIpcServiceSetCertStatus(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret;
    uint32_t store;
    uint32_t status = 0;
    struct CmContext cmContext = {0};
    struct CmBlob certUri = { 0, NULL };
    struct CmParamSet *paramSet = NULL;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &certUri},
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = &store},
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = &status},
    };

    do {
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("SetUserCertStatus get input params failed, ret = %d", ret);
            break;
        }

        ret = CmServiceSetCertStatusCheck(store, &certUri, status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmServiceSetCertStatusCheck check failed, ret = %d", ret);
            break;
        }

        ret = CmServiceSetCertStatus(&cmContext, &certUri, store, status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("set cert status failed, ret = %d", ret);
            break;
        }
    } while (0);
    CmSendResponse(context, ret, NULL);
    CmFreeParamSet(&paramSet);
    CM_LOG_I("CmIpcServiceSetCertStatus end:%d", ret);
}

void CmIpcServiceInstallAppCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    struct CmContext cmContext = {0};
    struct CmParamSet *paramSet = NULL;
    int32_t ret;

    do {
        struct CmAppCertInfo appCertInfo = { { 0, NULL }, { 0, NULL } };
        struct CmBlob certAlias = { 0, NULL };
        uint32_t store;
        struct CmParamOut params[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = &appCertInfo.appCert },
            { .tag = CM_TAG_PARAM1_BUFFER, .blob = &appCertInfo.appCertPwd },
            { .tag = CM_TAG_PARAM2_BUFFER, .blob = &certAlias },
            { .tag = CM_TAG_PARAM3_UINT32, .uint32Param = &store },
        };
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("install app cert get input params failed, ret = %d", ret);
            break;
        }

        ret = CmServicInstallAppCert(&cmContext, &appCertInfo, &certAlias, store, outData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("service install app cert failed, ret = %d", ret);
            break;
        }
    } while (0);

    CmReport(__func__, context, "NULL", ret);
    CmSendResponse(context, ret, outData);
    CmFreeParamSet(&paramSet);
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
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UninstallAppCert get input params failed, ret = %d", ret);
            break;
        }

        ret = CmServiceUninstallAppCertCheck(store, &keyUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UninstallAppCert CmServiceGetSystemCertCheck failed, ret = %d", ret);
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
    (void)memset_s(&uri, sizeof(uri), 0, sizeof(uri));

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
    uint32_t len = MAX_COUNT_CERTIFICATE * sizeof(struct CmBlob);
    (void)memset_s(fileNames, len, 0, len);
    struct CmParamSet *paramSet = NULL;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = &store },
    };

    do {
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmIpcServiceGetAppCertList get input params failed, ret = %d", ret);
            break;
        }

        ret = CmServiceGetAppCertListCheck(store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmServiceGetAppCertListCheck fail, ret = %d", ret);
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
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmIpcServiceGetAppCert get input params failed, ret = %d", ret);
            break;
        }

        ret = CmServiceGetAppCertCheck(store, &keyUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GCmServiceGetAppCertCheck fail, ret = %d", ret);
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

        ret = CmServiceGetCertInfo(&cmContext, &certUri, store, &certificateData, &status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertInfo failed, ret = %d", ret);
            break;
        }

        ret = CmServiceGetCertInfoPack(store, &certificateData, status, &certUri, outData);
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

        ret = CmServiceSetCertStatus(&cmContext, &certUri, store, status);
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

