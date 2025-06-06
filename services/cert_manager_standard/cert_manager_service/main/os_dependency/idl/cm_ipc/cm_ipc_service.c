/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "cm_security_guard_info.h"
#include "cm_type.h"

#include "cert_manager.h"
#include "cert_manager_check.h"
#include "cert_manager_key_operation.h"
#include "cert_manager_permission_check.h"
#include "cert_manager_query.h"
#include "cert_manager_service.h"
#include "cert_manager_status.h"
#include "cert_manager_uri.h"
#include "cert_manager_updateflag.h"
#include "cert_manager_storage.h"
#include "cert_manager_file_operator.h"

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

        const struct UserCAProperty prop = { INIT_INVALID_VALUE, CM_ALL_USER };
        ret = CmServiceGetCertList(&cmContext, &prop, store, &certFileList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get cert list failed, ret = %d", ret);
            break;
        }

        ret = CmServiceGetCertListPack(&cmContext, store, &certFileList, outData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("cert list data pack fail, ret = %d", ret);
            break;
        }

        CmSendResponse(context, ret, outData);
    } while (0);
    CmReport(__func__, &cmContext, NULL, ret);

    if (ret != CM_SUCCESS) {
        CmSendResponse(context, ret, NULL);
    }

    if (certFileList.data != NULL) {
        CmFreeCertFiles((struct CertFileInfo *)certFileList.data, certFileList.size);
    }
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
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
            CM_LOG_E("get cert info failed, ret = %d", ret);
            break;
        }

        ret = CmServiceGetCertInfoPack(store, &certificateData, status, &certUri, outData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("cert info data pack failed, ret = %d", ret);
            break;
        }

        CmSendResponse(context, ret, outData);
    } while (0);
    CmReport(__func__, &cmContext, &certUri, ret);

    if (ret != CM_SUCCESS) {
        CmSendResponse(context, ret, NULL);
    }
    CM_FREE_BLOB(certificateData);
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
}

void CmIpcServiceSetCertStatus(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret;
    uint32_t store = CM_SYSTEM_TRUSTED_STORE;
    uint32_t status = INIT_INVALID_VALUE;
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
    } while (0);
    CmReport(__func__, &cmContext, &certUri, ret);

    CmSendResponse(context, ret, NULL);
    CmReportSGSetCertStatus(&certUri, store, status, ret);
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
}

void CmIpcServiceInstallAppCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    uint32_t store = CM_CREDENTIAL_STORE;
    uint32_t userId = 0;
    struct CmBlob appCert = { 0, NULL };
    struct CmBlob appCertPwd = { 0, NULL };
    struct CmBlob certAlias = { 0, NULL };
    enum CmAuthStorageLevel level;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &appCert },
        { .tag = CM_TAG_PARAM1_BUFFER, .blob = &appCertPwd },
        { .tag = CM_TAG_PARAM2_BUFFER, .blob = &certAlias },
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = &store },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = &userId },
        { .tag = CM_TAG_PARAM2_UINT32, .uint32Param = &level },
    };

    int32_t ret;
    struct CmContext cmContext = { 0 };
    struct CmContext oriContext = {0};
    struct CmParamSet *paramSet = NULL;
    do {
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("install app cert get input params failed, ret = %d", ret);
            break;
        }
        oriContext.userId = cmContext.userId;
        oriContext.uid = cmContext.uid;

        struct CmAppCertParam certParam = { &appCert, &appCertPwd, &certAlias, store, userId, level };
        ret = CmServicInstallAppCert(&cmContext, &certParam, outData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("service install app cert failed, ret = %d", ret);
            break;
        }
    } while (0);

    struct CmBlob tempBlob = { 0, NULL };
    CmReport(__func__, &oriContext, &tempBlob, ret);

    CmSendResponse(context, ret, outData);
    CmReportSGInstallAppCert(&certAlias, store, ret);
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
}

void CmIpcServiceUninstallAppCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret;
    (void)outData;
    uint32_t store = CM_CREDENTIAL_STORE;
    struct CmParamSet *paramSet = NULL;
    struct CmBlob keyUri = { 0, NULL };
    struct CmContext cmContext = {0};
    struct CmContext oriContext = {0};

    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &keyUri },
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = &store },
    };

    do {
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UninstallAppCert get input params failed, ret = %d", ret);
            break;
        }
        oriContext.userId = cmContext.userId;
        oriContext.uid = cmContext.uid;

        ret = CmServiceUninstallAppCertCheck(&cmContext, store, &keyUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UninstallAppCert CmServiceGetSystemCertCheck failed, ret = %d", ret);
            break;
        }

        ret = CmRemoveAppCert(&cmContext, &keyUri, store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmRemoveAppCert fail");
        }
    } while (0);

    CmReport(__func__, &oriContext, &keyUri, ret);
    CmSendResponse(context, ret, NULL);
    CmReportSGUninstallAppCert(&keyUri, store, false, ret);
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
}

void CmIpcServiceUninstallAllAppCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    (void)outData;
    (void)paramSetBlob;
    int32_t ret = CM_SUCCESS;
    struct CmContext cmContext = {0};

    do {
        ret = CmGetProcessInfoForIPC(&cmContext);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmGetProcessInfoForIPC fail, ret = %d", ret);
            break;
        }

        ret = CmRemoveAllAppCert(&cmContext);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmRemoveAllAppCert fail");
            break;
        }
    } while (0);

    CmReport(__func__, &cmContext, NULL, ret);
    CmSendResponse(context, ret, NULL);
    CmReportSGUninstallAppCert(NULL, INIT_INVALID_VALUE, true, ret);

    CM_LOG_I("leave: ret = %d", ret);
}

static int32_t GetAppCertInfo(const struct CmBlob *keyUri, struct CmBlob *certType,
    struct CmBlob *certUri, struct CmBlob *cerAlias)
{
    int32_t ret;
    struct CMUri uri;
    (void)memset_s(&uri, sizeof(struct CMUri), 0, sizeof(struct CMUri));

    do {
        ret = CertManagerUriDecode(&uri, (char *)keyUri->data);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerUriDecode failed");
            break;
        }
        if ((uri.type >= TYPE_COUNT) || (uri.object == NULL)) {
            CM_LOG_E("uri's type[%u] or object is invalid after decode", uri.type);
            ret = CMR_ERROR_INVALID_ARGUMENT_URI;
            break;
        }

        if (memcpy_s(certType->data, certType->size, g_types[uri.type], strlen(g_types[uri.type]) + 1) != EOK) {
            CM_LOG_E("Failed to copy certType->data");
            ret = CMR_ERROR_MEM_OPERATION_COPY;
            break;
        }
        certType->size = strlen(g_types[uri.type]) + 1;

        if (memcpy_s(certUri->data, certUri->size, keyUri->data, keyUri->size) != EOK) {
            CM_LOG_E("Failed to copy certUri->data");
            ret = CMR_ERROR_MEM_OPERATION_COPY;
            break;
        }
        certUri->size = keyUri->size;

        ret = CmGetDisplayNameByURI(keyUri, uri.object, cerAlias);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to CMGetDisplayNameByURI");
            break;
        }
    } while (0);

    CertManagerFreeUri(&uri);
    return ret;
}

static int32_t CmCertListGetAppCertInfo(const struct CmBlob *fileName, struct CmBlob *certType,
    struct CmBlob *certUri,  struct CmBlob *certAlias)
{
    char uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob keyUri = { sizeof(uriBuf), (uint8_t *)uriBuf };

    int32_t ret = CmGetUri((char *)fileName->data, &keyUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get uri failed");
        return ret;
    }

    ret = GetAppCertInfo(&keyUri, certType, certUri, certAlias);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("GetAppCertInfo failed");
        return ret;
    }

    return ret;
}

static int32_t CmServiceGetAppCertListPack(struct CmBlob *certificateList, const struct CmBlob *fileNames,
    const uint32_t fileCount)
{
    /* buff struct: cert count + (cert type +  cert uri +  cert alias) * MAX_CERT_COUNT */
    uint32_t buffSize = sizeof(uint32_t) + (sizeof(uint32_t) + MAX_LEN_SUBJECT_NAME + sizeof(uint32_t) +
        MAX_LEN_URI + sizeof(uint32_t) + MAX_LEN_CERT_ALIAS) * MAX_COUNT_CERTIFICATE;
    certificateList->data = (uint8_t *)CmMalloc(buffSize);
    if (certificateList->data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    certificateList->size = buffSize;

    uint32_t offset = 0;
    int32_t ret = CopyUint32ToBuffer(fileCount, certificateList, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy certificate count failed");
        return ret;
    }

    for (uint32_t i = 0; i < fileCount; i++) {
        uint8_t typeBuf[MAX_LEN_SUBJECT_NAME] = {0};
        struct CmBlob certType = { sizeof(typeBuf), typeBuf };
        uint8_t certUriBuf[MAX_LEN_URI] = {0};
        struct CmBlob certUri = { sizeof(certUriBuf), certUriBuf };
        uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = {0};
        struct CmBlob certAlias = { sizeof(aliasBuf), aliasBuf };

        ret = CmCertListGetAppCertInfo(&fileNames[i], &certType, &certUri, &certAlias);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmCertListGetAppCertInfo failed");
            return ret;
        }

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

        ret = CopyBlobToBuffer(&certAlias, certificateList, &offset);
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
    uint32_t store;
    uint32_t fileCount = 0;
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

        ret = CmServiceGetAppCertListCheck(&cmContext, store);
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

    CmReport(__func__, &cmContext, NULL, ret);
    CmSendResponse(context, ret, &certificateList);
    CmFreeParamSet(&paramSet);
    CmFreeFileNames(fileNames, fileCount);
    CM_FREE_BLOB(certificateList);

    CM_LOG_I("leave: ret = %d", ret);
}

void CmIpcServiceGetCallingAppCertList(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret;
    (void)outData;
    uint32_t store;
    uint32_t fileCount = 0;
    struct CmContext cmContext = {0};
    struct CmBlob certificateList = { 0, NULL };
    struct CmBlob fileNamesBlob[MAX_COUNT_CERTIFICATE];
    uint32_t len = MAX_COUNT_CERTIFICATE * sizeof(struct CmBlob);
    (void)memset_s(fileNamesBlob, len, 0, len);
    struct CmParamSet *paramSets = NULL;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = &store },
    };

    do {
        ret = GetInputParams(paramSetBlob, &paramSets, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmIpcServiceGetCallingAppCertList get input params failed, ret = %d", ret);
            break;
        }

        ret = CmServiceGetCallingAppCertListCheck(&cmContext, store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmServiceGetCallingAppCertListCheck fail, ret = %d", ret);
            break;
        }

        ret = CmServiceGetCallingAppCertList(&cmContext, store, fileNamesBlob, MAX_COUNT_CERTIFICATE, &fileCount);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Get calling App cert list fail, ret = %d", ret);
            break;
        }

        ret = CmServiceGetAppCertListPack(&certificateList, fileNamesBlob, fileCount);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmServiceGetAppCertListPack pack fail, ret = %d", ret);
        }
    } while (0);

    CmReport(__func__, &cmContext, NULL, ret);
    CmSendResponse(context, ret, &certificateList);
    CmFreeParamSet(&paramSets);
    CmFreeFileNames(fileNamesBlob, fileCount);
    CM_FREE_BLOB(certificateList);

    CM_LOG_I("leave: ret = %d", ret);
}

static int32_t CopyCertificateInfoToBuffer(const struct CmBlob *certBlob,
    const struct CmBlob *certificateInfo, uint32_t *offset)
{
    if (certBlob->size < (sizeof(struct AppCert) - MAX_LEN_CERTIFICATE_CHAIN)) {
        CM_LOG_E("certInfo size[%u] invalid", certBlob->size);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct AppCert *appCert = (struct AppCert *)certBlob->data;
    if ((certBlob->size - (sizeof(struct AppCert) - MAX_LEN_CERTIFICATE_CHAIN)) < appCert->certSize) {
        CM_LOG_E("certInfo data size[%u] invalid, certSize[%u]", certBlob->size, appCert->certSize);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

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
    /* buff struct: certCount + certType + certAlias + certUri + certNum + keyNum + credData */
    uint32_t buffSize = sizeof(uint32_t) + sizeof(uint32_t) + MAX_LEN_SUBJECT_NAME +
        sizeof(uint32_t) + MAX_LEN_CERT_ALIAS + sizeof(uint32_t) + MAX_LEN_URI +
        sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t) + MAX_LEN_CERTIFICATE_CHAIN;
    certificateInfo->data = (uint8_t *)CmMalloc(buffSize);
    if (certificateInfo->data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    certificateInfo->size = buffSize;

    uint32_t offset = 0;
    if (CopyCertSize(certBlob, certificateInfo, &offset) != CM_SUCCESS) {
        return CMR_ERROR_NOT_EXIST;
    }

    uint8_t typeBuf[MAX_LEN_SUBJECT_NAME] = {0};
    uint8_t certUriBuf[MAX_LEN_URI] = {0};
    uint8_t aliasBuf[MAX_LEN_CERT_ALIAS] = {0};
    struct CmBlob certType = { sizeof(typeBuf), typeBuf };
    struct CmBlob certUri = { sizeof(certUriBuf), certUriBuf };
    struct CmBlob cerAlias = { sizeof(aliasBuf), aliasBuf };
    int32_t ret = GetAppCertInfo(keyUri, &certType, &certUri, &cerAlias);
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

    if (CopyBlobToBuffer(&cerAlias, certificateInfo, &offset) != CM_SUCCESS) {
        CM_LOG_E("Copy cerAlias failed");
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
    struct CmBlob keyUri = { 0, NULL };
    struct CmBlob certificateInfo = { 0, NULL };
    struct CmBlob certBlob = { 0, NULL };
    struct CmContext cmContext = {0};
    struct CmContext oriContext = {0};
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
        oriContext.userId = cmContext.userId;
        oriContext.uid = cmContext.uid;

        ret = CmServiceGetAppCertCheck(&cmContext, store, &keyUri);
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

    CmReport(__func__, &oriContext, &keyUri, ret);
    CmSendResponse(context, ret, &certificateInfo);
    CmFreeParamSet(&paramSet);
    CM_FREE_BLOB(certBlob);
    CM_FREE_BLOB(certificateInfo);

    CM_LOG_I("leave: ret = %d", ret);
}

static int32_t GetAuthedList(const struct CmContext *context, const struct CmBlob *keyUri, struct CmBlob *outData)
{
    if (outData->size < sizeof(uint32_t)) { /* appUidCount size */
        CM_LOG_E("invalid outData size[%u]", outData->size);
        return CMR_ERROR_BUFFER_TOO_SMALL;
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
    uint32_t grantUid = INIT_INVALID_VALUE;
    int32_t ret;
    do {
        struct CmParamOut params[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = &keyUri },
            { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = &grantUid },
        };
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get input params failed, ret = %d", ret);
            break;
        }

        ret = CmServiceGrantAppCertificate(&cmContext, &keyUri, grantUid, outData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("service grant app failed, ret = %d", ret);
            break;
        }
    } while (0);

    CmReport(__func__, &cmContext, &keyUri, ret);

    CmSendResponse(context, ret, outData);
    CmReportSGGrantAppCert(&keyUri, grantUid, false, ret);
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
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
    CmReport(__func__, &cmContext, &keyUri, ret);
    CmSendResponse(context, ret, outData);
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
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

    CmReport(__func__, &cmContext, &authUri, ret);
    CmSendResponse(context, ret, NULL);
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
}

void CmIpcServiceRemoveGrantedApp(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    struct CmContext cmContext = { 0, 0, {0} };
    struct CmParamSet *paramSet = NULL;
    (void)outData;
    struct CmBlob keyUri = { 0, NULL };
    uint32_t appUid = INIT_INVALID_VALUE;
    int32_t ret;
    do {
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
    CmReport(__func__, &cmContext, &keyUri, ret);

    CmSendResponse(context, ret, NULL);
    CmReportSGGrantAppCert(&keyUri, appUid, true, ret);
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
}

void CmIpcServiceInit(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    struct CmContext cmContext = { 0, 0, {0} };
    struct CmParamSet *paramSet = NULL;
    struct CmBlob authUri = { 0, NULL };

    int32_t ret;
    do {
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
            ret = CMR_ERROR_INVALID_ARGUMENT_SIGN_SPEC;
            break;
        }
        (void)memcpy_s(&spec, sizeof(struct CmSignatureSpec), specBlob.data, sizeof(struct CmSignatureSpec));

        ret = CmServiceInit(&cmContext, &authUri, &spec, outData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("service init failed, ret = %d", ret);
            break;
        }
    } while (0);

    CmReport(__func__, &cmContext, &authUri, ret);
    CmSendResponse(context, ret, outData);
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
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

    CmReport(__func__, &cmContext, NULL, ret);
    CmSendResponse(context, ret, NULL);
    CmFreeParamSet(&paramSet);
    CM_LOG_I("leave: ret = %d", ret);
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

    CmReport(__func__, &cmContext, NULL, ret);
    CmSendResponse(context, ret, outData);
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
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

    CmReport(__func__, &cmContext, NULL, ret);
    CmSendResponse(context, ret, NULL);
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
}

void CmIpcServiceGetUserCertList(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret = CM_SUCCESS;
    uint32_t store;
    uint32_t userId;
    enum CmCertScope scope;
    struct CmContext cmContext = {0};
    struct CmParamSet *paramSet = NULL;
    struct CmMutableBlob certFileList = { 0, NULL };
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = &store },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = &userId },
        { .tag = CM_TAG_PARAM2_UINT32, .uint32Param = &scope },
    };

    do {
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetUserCertList get input params failed, ret = %d", ret);
            break;
        }

        if (!CmHasCommonPermission()) {
            CM_LOG_E("caller no permission");
            ret = CMR_ERROR_PERMISSION_DENIED;
            break;
        }

        struct UserCAProperty prop = { userId, scope };
        ret = CmServiceGetCertList(&cmContext, &prop, store, &certFileList);
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

    struct CmBlob tempBlob = { 0, NULL };
    CmReport(__func__, &cmContext, &tempBlob, ret);

    if (ret != CM_SUCCESS) {
        CmSendResponse(context, ret, NULL);
    }

    if (certFileList.data != NULL) {
        CmFreeCertFiles((struct CertFileInfo *)certFileList.data, certFileList.size);
    }
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
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
    struct CmContext oriContext = {0};
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
        oriContext.userId = cmContext.userId;
        oriContext.uid = cmContext.uid;

        if (!CmHasCommonPermission()) {
            CM_LOG_E("caller no permission");
            ret = CMR_ERROR_PERMISSION_DENIED;
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
    CmReport(__func__, &oriContext, &certUri, ret);
    if (ret != CM_SUCCESS) {
        CmSendResponse(context, ret, NULL);
    }
    CM_FREE_BLOB(certificateData);
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
}

void CmIpcServiceSetUserCertStatus(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret = CM_SUCCESS;
    uint32_t store = CM_USER_TRUSTED_STORE;
    uint32_t status = INIT_INVALID_VALUE;
    struct CmContext oriContext = {0};
    struct CmBlob certUri = { 0, NULL };
    struct CmContext cmContext = {0};
    struct CmParamSet *paramSet = NULL;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &certUri },
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = &store },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = &status },
    };

    do {
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("SetUserCertStatus get input params failed, ret = %d", ret);
            break;
        }
        oriContext.userId = cmContext.userId;
        oriContext.uid = cmContext.uid;

        ret = CmServiceSetUserCertStatusCheck(&cmContext, &certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmServiceSetUserCertStatusCheck fail, ret = %d", ret);
            break;
        }

        ret = CmSetStatusBackupCert(&cmContext, &certUri, store, status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmSetStatusBackupCert failed, ret = %d", ret);
            break;
        }
    } while (0);

    CmReport(__func__, &oriContext, &certUri, ret);
    CmSendResponse(context, ret, NULL);
    CmReportSGSetCertStatus(&certUri, store, status, ret);
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
}

static int32_t CmInstallUserCertExecute(const struct InstallUserCertParams *installCertParams,
    const enum CmCertFileFormat certFormat)
{
    if (installCertParams == NULL || CmCheckBlob(installCertParams->outData) != CM_SUCCESS) {
        CM_LOG_E("check out data invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    int32_t ret = CM_SUCCESS;
    if (certFormat == PEM_DER) {
        ret = CmInstallUserCert(installCertParams->cmContext, installCertParams->userCert,
            installCertParams->certAlias, installCertParams->status, installCertParams->outData);
    } else if (certFormat == P7B) {
        ret = CmInstallMultiUserCert(installCertParams->cmContext, installCertParams->userCert,
            installCertParams->certAlias, installCertParams->status, installCertParams->outData);
    } else {
        ret = CMR_ERROR_NOT_SUPPORTED;
    }
    if (ret != CM_SUCCESS) {
        CM_LOG_E("install user cert failed, certFormat = %u, ret = %d", certFormat, ret);
    }
    return ret;
}

void CmIpcServiceInstallUserCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    int32_t ret = CM_SUCCESS;
    struct CmBlob userCert = { 0, NULL };
    struct CmBlob certAlias = { 0, NULL };
    uint32_t userId = 0;
    uint32_t status = CERT_STATUS_ENANLED;
    uint32_t certFormat = PEM_DER;
    struct CmContext cmContext = {0};
    struct CmContext oriContext = {0};
    struct CmParamSet *paramSet = NULL;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &userCert },
        { .tag = CM_TAG_PARAM1_BUFFER, .blob = &certAlias },
        { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = &userId },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = &status },
        { .tag = CM_TAG_PARAM2_UINT32, .uint32Param = &certFormat },
    };

    do {
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("InstallUserCert get input params failed, ret = %d", ret);
            break;
        }
        oriContext.userId = cmContext.userId;
        oriContext.uid = cmContext.uid;

        ret = CmServiceInstallUserCertCheck(&cmContext, &userCert, &certAlias, userId, certFormat);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmServiceInstallUserCertCheck fail, ret = %d", ret);
            break;
        }

        struct InstallUserCertParams installUserCertParams = { &cmContext, &userCert, &certAlias, outData, status };
        ret = CmInstallUserCertExecute(&installUserCertParams, certFormat);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerInstallUserCert fail, ret = %d", ret);
            break;
        }

        CmSendResponse(context, ret, outData);
    } while (0);

    struct CmBlob tempBlob = { 0, NULL };
    CmReport(__func__, &oriContext, &tempBlob, ret);

    if (ret != CM_SUCCESS) {
        CmSendResponse(context, ret, NULL);
    }
    CmReportSGInstallUserCert(&certAlias, outData, ret);
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
}

void CmIpcServiceUninstallUserCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    (void)outData;
    int32_t ret = CM_SUCCESS;
    struct CmBlob certUri = { 0, NULL };
    struct CmContext cmContext = {0};
    struct CmContext oriContext = {0};
    struct CmParamSet *paramSet = NULL;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &certUri },
    };

    do {
        ret = GetInputParams(paramSetBlob, &paramSet, &cmContext, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UninstallUserCert get input params failed, ret = %d", ret);
            break;
        }
        oriContext.userId = cmContext.userId;
        oriContext.uid = cmContext.uid;

        ret = CmServiceUninstallUserCertCheck(&cmContext, &certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmServiceUninstallUserCertCheck fail, ret = %d", ret);
            break;
        }

        ret = CmUninstallUserCert(&cmContext, &certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerUninstallUserCert fail, ret = %d", ret);
            break;
        }
    } while (0);

    CmReport(__func__, &oriContext, &certUri, ret);
    CmSendResponse(context, ret, NULL);
    CmReportSGUninstallUserCert(&certUri, false, ret);
    CmFreeParamSet(&paramSet);

    CM_LOG_I("leave: ret = %d", ret);
}

void CmIpcServiceUninstallAllUserCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    (void)outData;
    int32_t ret = CM_SUCCESS;
    struct CmContext cmContext = {0};

    do {
        ret = CmGetProcessInfoForIPC(&cmContext);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmGetProcessInfoForIPC fail, ret = %d", ret);
            break;
        }

        if (!CmHasCommonPermission() || !CmHasUserTrustedPermission()) {
            CM_LOG_E("caller no permission");
            ret = CMR_ERROR_PERMISSION_DENIED;
            break;
        }
        if (!CmIsSystemApp()) {
            CM_LOG_E("uninstall all user cert: caller is not system app");
            ret = CMR_ERROR_NOT_SYSTEMP_APP;
            break;
        }
        ret = CmUninstallAllUserCert(&cmContext);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerUninstallAllUserCert fail, ret = %d", ret);
            break;
        }
    } while (0);
    CmReport(__func__, &cmContext, NULL, ret);
    CmSendResponse(context, ret, NULL);
    CmReportSGUninstallUserCert(NULL, true, ret);

    CM_LOG_I("leave: ret = %d", ret);
}

