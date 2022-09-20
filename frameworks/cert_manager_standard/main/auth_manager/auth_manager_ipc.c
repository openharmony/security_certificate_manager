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

#include "cm_client_ipc.h"
#include "cm_ipc_check.h"

#include "cm_ipc_serialization.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_param.h"

#include "cm_request.h"

static int32_t ClientSerializationAndSend(enum CmMessage message, const struct CmParam *params,
    uint32_t paramCount, struct CmBlob *outBlob)
{
    struct CmParamSet *sendParamSet = NULL;
    int32_t ret = CmParamsToParamSet(params, paramCount, &sendParamSet);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("pack params failed, ret = %d", ret);
        return ret;
    }

    struct CmBlob parcelBlob = { sendParamSet->paramSetSize, (uint8_t *)sendParamSet };
    ret = SendRequest(message, &parcelBlob, outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("send request failed, ret = %d", ret);
    }
    CmFreeParamSet(&sendParamSet);

    return ret;
}

static int32_t FormatAppUidList(const struct CmBlob *replyBlob, struct CmAppUidList *appUidList)
{
    if (replyBlob->size < sizeof(uint32_t)) { /* app uid count: 4 bytes */
        CM_LOG_E("invalid reply size[%u]", replyBlob->size);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    /* get app uid count */
    uint32_t count = 0;
    (void)memcpy_s(&count, sizeof(uint32_t), replyBlob->data, sizeof(uint32_t));
    uint32_t offset = sizeof(uint32_t);

    /* check reply total len */
    if ((count > MAX_OUT_BLOB_SIZE) || (replyBlob->size < (sizeof(uint32_t) + count * sizeof(uint32_t)))) {
        CM_LOG_E("invalid reply size[%u]", replyBlob->size);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (appUidList->appUidCount < count) {
        CM_LOG_E("input app list count[%u] too small", appUidList->appUidCount);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    if (count != 0) {
        if (appUidList->appUid == NULL) {
            CM_LOG_E("input appUid NULL");
            return CMR_ERROR_INVALID_ARGUMENT;
        }
        uint32_t uidListSize = count * sizeof(uint32_t);
        (void)memcpy_s(appUidList->appUid, uidListSize, replyBlob->data + offset, uidListSize);
    }
    appUidList->appUidCount = count;
    return CM_SUCCESS;
}

int32_t CmClientGrantAppCertificate(const struct CmBlob *keyUri, uint32_t appUid, struct CmBlob *authUri)
{
    if (CmCheckBlob(keyUri) != CM_SUCCESS || CmCheckBlob(authUri) != CM_SUCCESS) {
        CM_LOG_E("invalid keyUri or authUri");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *keyUri },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = appUid },
    };

    int32_t ret = ClientSerializationAndSend(CM_MSG_GRANT_APP_CERT, params, CM_ARRAY_SIZE(params), authUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("grant app serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientGetAuthorizedAppList(const struct CmBlob *keyUri, struct CmAppUidList *appUidList)
{
    if (CmCheckBlob(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid keyUri");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (appUidList->appUidCount > MAX_OUT_BLOB_SIZE) { /* ensure not out of bounds */
        CM_LOG_E("invalid app uid list count[%u]", appUidList->appUidCount);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t outLen = sizeof(uint32_t) + appUidList->appUidCount * sizeof(uint32_t);
    uint8_t *outData = CmMalloc(outLen);
    if (outData == NULL) {
        CM_LOG_E("malloc out data failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(outData, outLen, 0, outLen);
    struct CmBlob outBlob = { outLen, outData };

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *keyUri },
    };

    int32_t ret = ClientSerializationAndSend(CM_MSG_GET_AUTHED_LIST, params, CM_ARRAY_SIZE(params), &outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get authed list serialization and send failed, ret = %d", ret);
        CmFree(outData);
        return ret;
    }

    ret = FormatAppUidList(&outBlob, appUidList);
    CmFree(outData);
    return ret;
}

int32_t CmClientIsAuthorizedApp(const struct CmBlob *authUri)
{
    if (CmCheckBlob(authUri) != CM_SUCCESS) {
        CM_LOG_E("invalid authUri");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *authUri },
    };

    struct CmBlob outBlob = { 0, NULL };
    int32_t ret = ClientSerializationAndSend(CM_MSG_CHECK_IS_AUTHED_APP, params, CM_ARRAY_SIZE(params), &outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("check is authed serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientRemoveGrantedApp(const struct CmBlob *keyUri, uint32_t appUid)
{
    if (CmCheckBlob(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid keyUri");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *keyUri },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = appUid },
    };

    struct CmBlob outBlob = { 0, NULL };
    int32_t ret = ClientSerializationAndSend(CM_MSG_REMOVE_GRANT_APP, params, CM_ARRAY_SIZE(params), &outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("remove granted app serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientInit(const struct CmBlob *authUri, const struct CmSignatureSpec *spec, struct CmBlob *handle)
{
    if (CmCheckBlob(authUri) != CM_SUCCESS || CmCheckBlob(handle) != CM_SUCCESS) {
        CM_LOG_E("invalid handle or inData");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmBlob signSpec = { sizeof(struct CmSignatureSpec), (uint8_t *)spec };
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *authUri },
        { .tag = CM_TAG_PARAM1_BUFFER, .blob = signSpec },
    };

    int32_t ret = ClientSerializationAndSend(CM_MSG_INIT, params, CM_ARRAY_SIZE(params), handle);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("update serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientUpdate(const struct CmBlob *handle, const struct CmBlob *inData)
{
    if (CmCheckBlob(handle) != CM_SUCCESS || CmCheckBlob(inData) != CM_SUCCESS) {
        CM_LOG_E("invalid handle or inData");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *handle },
        { .tag = CM_TAG_PARAM1_BUFFER, .blob = *inData },
    };

    struct CmBlob outBlob = { 0, NULL };
    int32_t ret = ClientSerializationAndSend(CM_MSG_UPDATE, params, CM_ARRAY_SIZE(params), &outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("update serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientFinish(const struct CmBlob *handle, const struct CmBlob *inData, struct CmBlob *outData)
{
    if (CmCheckBlob(handle) != CM_SUCCESS) { /* finish: inData and outData can be {0, NULL} */
        CM_LOG_E("invalid handle");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *handle },
        { .tag = CM_TAG_PARAM1_BUFFER, .blob = *inData },
    };

    int32_t ret = ClientSerializationAndSend(CM_MSG_FINISH, params, CM_ARRAY_SIZE(params), outData);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("finish serialization and send failed, ret = %d", ret);
    }
    return ret;
}

int32_t CmClientAbort(const struct CmBlob *handle)
{
    if (CmCheckBlob(handle) != CM_SUCCESS) {
        CM_LOG_E("invalid handle");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = *handle },
    };

    struct CmBlob outBlob = { 0, NULL };
    int32_t ret = ClientSerializationAndSend(CM_MSG_ABORT, params, CM_ARRAY_SIZE(params), &outBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("abort serialization and send failed, ret = %d", ret);
    }
    return ret;
}

static const uint8_t g_certPwd[] = "123456";
static const uint8_t g_rsaP12Certinfo[] = {
    0x30, 0x82, 0x0b, 0xc1, 0x02, 0x01, 0x03, 0x30, 0x82, 0x0b, 0x87, 0x06, 0x09, 0x2a, 0x86, 0x48,
};

static const uint8_t g_eccP12Certinfo[] = {
    0x30, 0x82, 0x04, 0x6a, 0x02, 0x01, 0x03, 0x30, 0x82, 0x04, 0x30, 0x06, 0x09, 0x2a, 0x86, 0x48,
};

#define CERT_KEY_ALG_RSA 1
#define CERT_KEY_ALG_ECC 2

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
    return CmInstallAppCert(&appCert, &appCertPwd, alias, store);
}
