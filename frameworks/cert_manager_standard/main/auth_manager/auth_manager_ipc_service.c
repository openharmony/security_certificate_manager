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

#include "auth_manager_ipc_service.h"

#include "cm_log.h"
#include "cm_mem.h"
#include "cm_response.h"

#include "cert_manager_service.h"

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

    int32_t ret;
    do {
        struct CmBlob keyUri = { 0, NULL };
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

    CM_LOG_I("CmIpcServiceGrantAppCertificate end:%d", ret);
    CmSendResponse(context, ret, outData);
    CmFreeParamSet(&paramSet);
}

void CmIpcServiceGetAuthorizedAppList(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context)
{
    struct CmContext cmContext = { 0, 0, {0} };
    struct CmParamSet *paramSet = NULL;

    int32_t ret;
    do {
        struct CmBlob keyUri = { 0, NULL };
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

    int32_t ret;
    do {
        struct CmBlob authUri = { 0, NULL };
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

    int32_t ret;
    do {
        uint32_t appUid = 0;
        struct CmBlob keyUri = { 0, NULL };
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
