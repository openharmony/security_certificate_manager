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

#include "cm_ipc_service_user_trusted_cert.h"

static int32_t CmMallocCertInfo01(struct CertBlob *certInfoBlob)
{
    uint32_t i;

    if (certInfoBlob == NULL) {
        return CMR_INVALID_ARGUMENT;
    }

    for (i = 0; i < MAX_COUNT_CERTIFICATE; i++) {
        certInfoBlob->uri[i].size = MAX_LEN_CERTIFICATE;
        certInfoBlob->uri[i].data = (uint8_t *)CmMalloc(MAX_LEN_URI);
        if (certInfoBlob->uri[i].data == NULL) {
            return CMR_ERROR_MALLOC_FAIL;
        }
        ASSERT_FUNC(memset_s(certInfoBlob->uri[i].data, MAX_LEN_URI, 0, MAX_LEN_URI));

        certInfoBlob->subjectName[i].size = MAX_LEN_CERTIFICATE;
        certInfoBlob->subjectName[i].data = (uint8_t *)CmMalloc(MAX_LEN_SUBJECT_NAME);
        if (certInfoBlob->subjectName[i].data == NULL) {
            return CMR_ERROR_MALLOC_FAIL;
        }
        ASSERT_FUNC(memset_s(certInfoBlob->subjectName[i].data, MAX_LEN_SUBJECT_NAME, 0, MAX_LEN_SUBJECT_NAME));

        certInfoBlob->certAlias[i].size = MAX_LEN_CERTIFICATE;
        certInfoBlob->certAlias[i].data = (uint8_t *)CmMalloc(MAX_LEN_CERT_ALIAS);
        if (certInfoBlob->certAlias[i].data == NULL) {
            return CMR_ERROR_MALLOC_FAIL;
        }
        ASSERT_FUNC(memset_s(certInfoBlob->certAlias[i].data, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS));
    }
    return CM_SUCCESS;
}

static int32_t CmServiceGetCertListPack01(const struct CmContext *context, uint32_t store,
    const struct CmMutableBlob *certFileList, struct CmBlob *certificateList)
{
    int32_t ret = CM_SUCCESS;
    uint32_t offset = 0;
    uint32_t buffSize;
    uint32_t status[MAX_COUNT_CERTIFICATE] = {0};
    struct CertBlob certBlob;

    ret = CmGetCertListInfo(context, store, certFileList, &certBlob, status);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmGetCertListInfo fail");
        return ret;
    }

    /* buff struct: cert count + (cert subjectname + cert status +  cert uri +  cert alias) * MAX_CERT_COUNT */
    buffSize = sizeof(uint32_t) + (sizeof(uint32_t) + MAX_LEN_SUBJECT_NAME + sizeof(uint32_t) + sizeof(uint32_t) +
        MAX_LEN_URI + sizeof(uint32_t) + MAX_LEN_CERT_ALIAS) * MAX_COUNT_CERTIFICATE;
    certificateList->data = (uint8_t *)CmMalloc(buffSize);
    if (certificateList->data == NULL) {
        ret = CMR_ERROR_MALLOC_FAIL;
        return ret;
    }
    certificateList->size = buffSize;

    ret = CopyUint32ToBuffer(certFileList->size, certificateList, &offset);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Copy cert count failed");
        return ret;
    }

    for (uint32_t i = 0; i < certFileList->size; i++) {
        ret = CopyBlobToBuffer(&(certBlob->subjectName[i]), certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate subject failed");
            return ret;
        }
        ret = CopyUint32ToBuffer(status[i], certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate status failed");
            return ret;
        }
        ret = CopyBlobToBuffer(&(certBlob->uri[i]), certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate uri failed");
            return ret;
        }
        ret = CopyBlobToBuffer(&(certBlob->certAlias[i]), certificateList, &offset);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Copy certificate certAlias failed");
            return ret;
        }
    }
    return ret;
}

static int32_t CmParsesInputParcel(const struct CmBlob *paramSetBlob, const struct CmParam *params,
    struct CmContext *cmContext)
{
    struct CmParamSet *paramSet = NULL;

    do {
        int ret = CmGetParamSet((struct CmParamSet *)paramSetBlob->data, paramSetBlob->size, &paramSet);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertList CmGetParamSet fail, ret = %d", ret);
            break;
        }

        ret = CmParamSetToParams(paramSet, params, CM_ARRAY_SIZE(params));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertList CmParamSetToParams fail, ret = %d", ret);
            break;
        }

        ret = CmGetProcessInfoForIPC(cmContext);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmGetProcessInfoForIPC fail, ret = %d", ret);
            break;
        }
    } while (0);
    CmFreeParamSet(&paramSet);
    return ret;
}

void CmIpcServiceGetCertificateList01(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *contextReply)
{
    uint32_t store;
    (void)outData;
    struct CmContext cmContext = {0};
    struct CmBlob certificateList = { 0, NULL };
    struct CmMutableBlob certFileList = { 0, NULL };
    struct CmParamOut params[] = {
        {
            .tag = CM_TAG_PARAM0_UINT32,
            .uint32Param = &store
        },
    };

    do {
        int ret = CmParsesInputParcel(paramSetBlob, params, &cmContext);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertList CmParsesParcel fail, ret = %d", ret);
            break;
        }

        ret = CmServiceGetCertList(&cmContext, store, &certFileList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertList fail, ret = %d", ret);
            break;
        }

        ret = CmServiceGetCertListPack01(&cmContext, store, &certFileList, &certificateList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmServiceGetCertListPack pack fail, ret = %d", ret);
            break;
        }

        CmSendResponse(contextReply, ret, &certificateList);
    } while (0);
    if (ret != CM_SUCCESS) {
        CmSendResponse(contextReply, ret, NULL);
    }
    CM_FREE_BLOB(certificateList);
    CM_FREE_BLOB(certFileList);
}

static int32_t CmServiceGetCertInfoPack(const struct CmBlob *certificateData, uint32_t status,
    struct CmBlob *certificateInfo)
{
    int32_t retVal = CM_SUCCESS;
    uint32_t offset = 0;
    uint32_t buffSize;

    const struct CmBlob *tempBlob = &(((const struct CmBlob *)certificateData->data)[0]);

    /* buff struct: cert len + cert data + cert staus */
    buffSize = sizeof(uint32_t) + MAX_LEN_CERTIFICATE + sizeof(uint32_t);
    certificateInfo->data = (uint8_t *)CmMalloc(buffSize);
    if (certificateInfo->data == NULL) {
        retVal = CMR_ERROR_MALLOC_FAIL;
        return retVal;
    }
    certificateInfo->size = buffSize;

    retVal = CopyBlobToBuffer(tempBlob, certificateInfo, &offset);
    if (retVal != CM_SUCCESS) {
        CM_LOG_E("copy certificateInfo failed");
        return retVal;
    }

    retVal = CopyUint32ToBuffer(status, certificateInfo, &offset);
    if (retVal != CM_SUCCESS) {
        CM_LOG_E("Copy certificate count failed");
        return retVal;
    }

    return retVal;
}

void CmIpcServiceGetCertificateInfo01(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *contextReply)
{
    (void)outData;
    uint32_t store;
    uint32_t status = 0;
    struct CmBlob certUri = { 0, NULL };
    struct CmBlob certificateData = { 0, NULL };
    struct CmBlob certificateInfo = { 0, NULL };
    struct CmContext cmContext = {0};
    struct CmParamOut params[] = {
        {   .tag = CM_TAG_PARAM0_BUFFER,
            .blob = &certUri},
        {   .tag = CM_TAG_PARAM0_UINT32,
            .uint32Param = &store},
    };

    do {
        int ret = CmParsesInputParcel(paramSetBlob, params, &cmContext);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertInfo CmParsesParcel fail, ret = %d", ret);
            break;
        }

        ret = CmGetServiceCertInfo(&cmContext, &certUri, store, &certificateData, &status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertInfo fail, ret = %d", ret);
            break;
        }

        ret = CmServiceGetCertInfoPack(&certificateData, status, &certificateInfo);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmServiceGetCertInfoPack pack fail, ret = %d", ret);
            break;
        }
        CmSendResponse(contextReply, ret, &certificateInfo);
    } while (0);
    if (ret != CM_SUCCESS) {
        CmSendResponse(contextReply, ret, NULL);
    }
    CM_FREE_BLOB(certificateInfo);
    CM_FREE_BLOB(certificateData);
}

void CmIpcServiceSetCertStatus01(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *contextReply)
{
    (void)outData;
    uint32_t store;
    uint32_t status;
    struct CmBlob certUri = { 0, NULL };
    struct CmContext cmContext = {0};
    struct CmParamOut params[] = {
        {   .tag = CM_TAG_PARAM0_BUFFER,
            .blob = &certUri},
        {   .tag = CM_TAG_PARAM0_UINT32,
            .uint32Param = &store},
        {   .tag = CM_TAG_PARAM1_UINT32,
            .uint32Param = &status},
    };

    do {
        int ret = CmParsesInputParcel(paramSetBlob, params, &cmContext);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("SetCertStatus CmParsesParcel fail, ret = %d", ret);
            break;
        }

        ret = CertManagerSetCertificatesStatus(&cmContext, certUri, store, status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("set cert status fail, ret = %d", ret);
            break;
        }
    } while (0);
    CmSendResponse(contextReply, ret, NULL);
}

static int32_t CmWriteUserCert(const struct CmContext *context, struct CmMutableBlob *pathBlob,
    const struct CmBlob *userCert, const struct CmBlob *certAlias, struct CmBlob *certUri)
{
    int32_t ret = CM_SUCCESS;
    char *userUri = NULL;

    do {
        ret = BuildUserUri(&userUri, (char *)certAlias->data, CM_URI_TYPE_CERTIFICATE, context);
        if (ret != CM_SUCCESS || userUri == NULL) {
            CM_LOG_E("BuildUserUri failed");
            break;
        }

        certUri->data = (uint8_t *)CMMalloc(MAX_LEN_URI);
        if (certUri->data == NULL) {
            ret = CMR_ERROR_MALLOC_FAIL;
            break;
        }
        if (memset_s(certUri->data, MAX_LEN_URI, 0, MAX_LEN_URI) != EOK) {
            ret = CMR_ERROR;
            break;
        }
        certUri->size = (uint32_t)strlen(userUri) + 1;
        if (memcpy_s(certUri->data, MAX_LEN_URI, (uint8_t *)userUri, certUri->size) != EOK) {
            ret = CMR_ERROR;
            break;
        }

        if (CmFileWrite((char*)pathBlob.data, userUri, 0, userCert->data, userCert->size) != CMR_OK) {
            CM_LOG_E("Failed to write certificate: %s in to %s", certAlias->data, pathBlob.data);
            ret = CMR_FILE_WRITE_ERROR;
            break;
        }
    } while (0);

    if (userUri != NULL) {
        CmFree(userUri);
    }
    return ret;
}

static int32_t CmCheckCallerPermission(const struct CmContext *ipcInfo)
{
    (void)ipcInfo;

    return CM_SUCCESS;
}

static int32_t CmInstallUserCert(const struct CmContext *context, const struct CmBlob *userCert,
    const struct CmBlob *certAlias, struct CmBlob *certUri)
{
    int32_t ret = CM_SUCCESS;
    uint8_t pathBuf[CERT_MAX_PATH_LEN] = {0};
    struct CmMutableBlob pathBlob = { sizeof(pathBuf), pathBuf };
    uint32_t store = CM_USER_TRUSTED_STORE;

    do {
        ret = CmCheckCallerPermission(context);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Check caller permission fail");
            break;
        }

        X509 *userCertX509 = InitCertContext(userCert->data, userCert->size);
        if (userCertX509 == NULL) {
            CM_LOG_E("Parse X509 cert fail");
            ret = CM_FAILURE;
            break;
        }

        ret = CmGetCertFilePath(context, store, &pathBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed obtain path for store:%d path:%s", store, pathBuf);
            break;
        }

        ret = CmWriteUserCert(context, &pathBlob, userCert, certAlias, certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerWriteUserCert fail");
            ret = CM_FAILURE;
            break;
        }

        ret = CmSetStatusEnable(context, &pathBlob, certUri, store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerUpdateStatusFile fail");
            ret = CM_FAILURE;
            break;
        }
    } while (0);

    if (userCertX509 != NULL) {
        FreeCertContext(userCertX509);
    }
    return ret;
}

void CmIpcServiceInstallUserCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *contextReply)
{
    (void)outData;
    struct CmBlob userCert = { 0, NULL };
    struct CmBlob certAlias = { 0, NULL };
    struct CmBlob certUri = { 0, NULL };
    struct CmContext cmContext = {0};
    struct CmParamOut params[] = {
        {
            .tag = CM_TAG_PARAM0_BUFFER,
            .blob = &userCert
        }, {
            .tag = CM_TAG_PARAM1_BUFFER,
            .blob = &certAlias
        },
    };

    do {
        int ret = CmParsesInputParcel(paramSetBlob, params, &cmContext);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("InstallUserCert CmParsesParcel fail, ret = %d", ret);
            break;
        }

        ret = CmInstallUserCert(&cmContext, &userCert, &certAlias, &certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerInstallUserCert fail, ret = %d", ret);
        }

        CmSendResponse(contextReply, ret, &certUri);
    } while (0);

    if (ret != CM_SUCCESS) {
        CmSendResponse(contextReply, ret, NULL);
    }
    CM_FREE_BLOB(certUri);
}

static int32_t CmComparisonCallerIdWithUri(const struct CmContext *context,
    const struct CmBlob *certUri)
{
    uint32_t useridObj;
    uint32_t uidObj;
    struct CMUri uriObj;
    (void)memset_s(&uriObj, sizeof(uriObj), 0, sizeof(uriObj));

    int32_t ret = CertManagerUriDecode(&uriObj, (char *)uri->data);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uri decode failed, ret = %d", ret);
        return ret;
    }

    if (uriObj.user == NULL) {
        CM_LOG_E("uri user invalid");
        (void)CertManagerFreeUri(&uriObj);
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    useridObj = atoi(uriObj.user);

    if (uriObj.app == NULL) {
        CM_LOG_E("uri app invalid");
        (void)CertManagerFreeUri(&uriObj);
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    uidObj = atoi(uriObj.app);
    if ((context->userId == useridObj) && (context->uid == uidObj)) {
        ret = CM_SUCCESS;
    } else {
        (void)CertManagerFreeUri(&uriObj);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    (void)CertManagerFreeUri(&uriObj);
    return ret;
}

static int32_t CmUninstallUserCert(const struct CmContext *context, const struct CmBlob *certUri)
{
    int32_t ret = CM_SUCCESS;
    ASSERT_ARGS(context && certUri && certUri->data && certUri->size);
    uint8_t pathBuf[CERT_MAX_PATH_LEN] = {0};
    struct CmMutableBlob pathBlob = { sizeof(pathBuf), pathBuf };
    uint32_t store = CM_USER_TRUSTED_STORE;

    do {
        ret = CmCheckCallerPermission(&context);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Caller haven't permission, ret = %d", ret);
            break;
        }

        ret = CmComparisonCallerIdWithUri(&context, certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CallerId don't match uri, ret = %d", ret);
            break;
        }

        ret = CmGetCertFilePath(context, store, &pathBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed obtain path for store %d", store);
            break;
        }

        ret = CmRemoveUserCert(&pathBlob, certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("RemoveUserCertFile fail, ret = %d", ret);
            break;
        }

        ret = CmSetStatusEnable(context, &pathBlob, certUri, store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UpdateStatusFile fail, ret = %d", ret);
            break;
        }
    } while (0);

    return ret;
}

void CmIpcServiceUninstallUserCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *contextReply)
{
    (void)outData;
    struct CmBlob certUri = { 0, NULL };
    struct CmContext cmContext = {0};
    struct CmParamOut params[] = {
        {
            .tag = CM_TAG_PARAM0_BUFFER,
            .blob = &certUri
        },
    };

    do {
        int ret = CmParsesInputParcel(paramSetBlob, params, &cmContext);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("UninstallUserCert CmParsesParcel fail, ret = %d", ret);
            break;
        }

        ret = CmUninstallUserCert(&cmContext, &certUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CertManagerUninstallUserCert fail, ret = %d", ret);
            break;
        }
    } while (0);

    CmSendResponse(contextReply, ret, NULL);
}

static int32_t CmUninstallAllUserCert(const struct CmContext *context)
{
    int32_t ret = CM_SUCCESS;
    uint32_t store = CERT_MANAGER_USER_TRUSTED_STORE;
    struct CmMutableBlob certPathList = { 0, NULL };

    do {
        ret = CmCheckCallerPermission(context);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Caller haven't permission, ret = %d", ret);
            break;
        }

        ret = CmGetCertPathList(context, store, &certPathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertPathList fail, ret = %d", ret);
            (void)CmFreeCertPaths(&certPathList);
            break;
        }

        ret = CmRemoveAllUserCert(context, store, &certPathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("RemoveAllUserCert fail, ret = %d", ret);
            (void)CmFreeCertPaths(&certPathList);
            break;
        }
    } while (0);
    if (uidPathList.data != NULL) {
        (void)CmFreeCertPaths(&certPathList);
    }
    return ret;
}

void CmIpcServiceUninstallAllUserCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *contextReply)
{
    (void)outData;
    struct CmContext cmContext = {0};

    do {
        int32_t ret = CmGetProcessInfoForIPC(&cmContext);
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

    CmSendResponse(contextReply, ret, NULL);
}
