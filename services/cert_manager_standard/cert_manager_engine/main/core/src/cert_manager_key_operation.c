/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "cert_manager_key_operation.h"

#include "securec.h"

#include "cert_manager_mem.h"
#include "cert_manager_session_mgr.h"
#include "cert_manager_crypto_operation.h"
#include "cert_manager_uri.h"
#include "cm_cert_property_rdb.h"
#include "cm_log.h"
#include "cm_type.h"
#include "cm_util.h"

#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"

#define HAP_USER_ID 100
struct PropertyToHuks {
    uint32_t cmProperty;
    uint32_t huksProperty;
};

static struct PropertyToHuks g_cmPurposeProperty[] = {
    { CM_KEY_PURPOSE_SIGN, HKS_KEY_PURPOSE_SIGN },
    { CM_KEY_PURPOSE_VERIFY, HKS_KEY_PURPOSE_VERIFY },
};

static struct PropertyToHuks g_cmPaddingProperty[] = {
    { CM_PADDING_NONE, HKS_PADDING_NONE },
    { CM_PADDING_OAEP, HKS_PADDING_OAEP },
    { CM_PADDING_PSS, HKS_PADDING_PSS },
    { CM_PADDING_PKCS1_V1_5, HKS_PADDING_PKCS1_V1_5 },
    { CM_PADDING_PKCS5, HKS_PADDING_PKCS5 },
    { CM_PADDING_PKCS7, HKS_PADDING_PKCS7 },
};

static struct PropertyToHuks g_cmDigestProperty[] = {
    { CM_DIGEST_NONE, HKS_DIGEST_NONE },
    { CM_DIGEST_MD5, HKS_DIGEST_MD5 },
    { CM_DIGEST_SHA1, HKS_DIGEST_SHA1 },
    { CM_DIGEST_SHA224, HKS_DIGEST_SHA224 },
    { CM_DIGEST_SHA256, HKS_DIGEST_SHA256 },
    { CM_DIGEST_SHA384, HKS_DIGEST_SHA384 },
    { CM_DIGEST_SHA512, HKS_DIGEST_SHA512 },
    { CM_DIGEST_SM3, HKS_DIGEST_SM3 },
};

static struct PropertyToHuks g_cmLevelProperty[] = {
    { CM_AUTH_STORAGE_LEVEL_EL1, HKS_AUTH_STORAGE_LEVEL_DE },
    { CM_AUTH_STORAGE_LEVEL_EL2, HKS_AUTH_STORAGE_LEVEL_CE },
    { CM_AUTH_STORAGE_LEVEL_EL4, HKS_AUTH_STORAGE_LEVEL_ECE },
};

#define INVALID_PROPERTY_VALUE 0xFFFF
#define DEFAULT_LEN_USED_FOR_MALLOC 1024

// LCOV_EXCL_START
static int32_t AddUserIdParam(struct HksParamSet *paramSet, enum CmAuthStorageLevel level, const struct CmBlob *uri)
{
    if (level == CM_AUTH_STORAGE_LEVEL_EL1) {
        CM_LOG_D("level is el1");
        return CM_SUCCESS;
    }
    struct CMUri uriObj;
    (void)memset_s(&uriObj, sizeof(uriObj), 0, sizeof(uriObj));

    int32_t ret = CertManagerUriDecode(&uriObj, (char *)uri->data); //uri->data已被校验有\0结尾
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to decode uri, ret = %d", ret);
        return ret;
    }
    do {
        if (uriObj.user == NULL) {
            CM_LOG_E("uri format is invalid");
            ret = CMR_ERROR_INVALID_ARGUMENT_URI;
            break;
        }

        uint32_t userId = 0;
        if (CmIsNumeric(uriObj.user, strlen(uriObj.user) + 1, &userId) != CM_SUCCESS) {
            CM_LOG_E("parse string to uint32 failed.");
            ret = CMR_ERROR_INVALID_ARGUMENT_URI;
            break;
        }
        /* If the caller is SA and the level is not EL1,
            the initial value of userid needs to be set and passed to HUKS.  */
        if (userId == 0) {
            userId = HAP_USER_ID;
        }
        struct HksParam userIdParam = {
            .tag = HKS_TAG_SPECIFIC_USER_ID,
            .uint32Param = userId,
        };
        ret = HksAddParams(paramSet, &userIdParam, 1);
        if (ret != HKS_SUCCESS) {
            CM_LOG_E("add userIdParam tag failed");
            break;
        }
    } while (0);
    (void)CertManagerFreeUri(&uriObj);
    return ret;
}

static int32_t ConstructParamSet(const struct HksParam *params, uint32_t paramCount, struct HksParamSet **outParamSet,
    enum CmAuthStorageLevel level, const struct CmBlob *uri)
{
    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        CM_LOG_E("init huks paramset failed, ret = %d", ret);
        return ret;
    }

    ret = AddUserIdParam(paramSet, level, uri);
    if (ret != HKS_SUCCESS) {
        CM_LOG_E("add userid param failed, ret = %d", ret);
        HksFreeParamSet(&paramSet);
        return ret;
    }

    ret = HksAddParams(paramSet, params, paramCount);
    if (ret != HKS_SUCCESS) {
        CM_LOG_E("add huks params failed, ret = %d", ret);
        HksFreeParamSet(&paramSet);
        return ret;
    }

    ret = HksBuildParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        CM_LOG_E("build huks paramSet failed, ret = %d", ret);
        HksFreeParamSet(&paramSet);
        return ret;
    }

    *outParamSet = paramSet;
    return CM_SUCCESS;
}

static int32_t GetKeyAlias(struct HksBlob *keyAlias, struct CmBlob *encodeTarget)
{
    int32_t ret = CM_SUCCESS;
    if (keyAlias->size > MAX_LEN_MAC_KEY) {
        ret = GetNameEncode((struct CmBlob *)keyAlias, encodeTarget);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("base64urlsha256 failed");
            return ret;
        }
        keyAlias->data = encodeTarget->data;
        keyAlias->size = encodeTarget->size;
    }
    return ret;
}

static uint32_t TranslateToHuksLevel(enum CmAuthStorageLevel level)
{
    uint32_t res = HKS_AUTH_STORAGE_LEVEL_DE;
    for (uint32_t i = 0; i < CM_ARRAY_SIZE(g_cmLevelProperty); ++i) {
        if (level == g_cmLevelProperty[i].cmProperty) {
            res = (uint32_t)g_cmLevelProperty[i].huksProperty;
        }
    }
    return res;
}

int32_t CmKeyOpGenMacKey(const struct CmBlob *alias, enum CmAuthStorageLevel level)
{
    uint32_t huksAuthStorageLevel = TranslateToHuksLevel(level);
    struct HksParam genMacKeyParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = huksAuthStorageLevel },
    };

    struct HksParamSet *paramSet = NULL;
    int32_t ret = ConstructParamSet(genMacKeyParams, sizeof(genMacKeyParams) / sizeof(struct HksParam),
        &paramSet, level, alias);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("construct gen mac key paramSet failed");
        return CMR_ERROR_KEY_GENERATE_PARAM_FAILED;
    }

    struct HksBlob keyAlias = { alias->size, alias->data };

    uint8_t encodeBuf[MAX_LEN_BASE64URL_SHA256] = { 0 };
    struct CmBlob encodeTarget = { sizeof(encodeBuf), encodeBuf };
    ret = GetKeyAlias(&keyAlias, &encodeTarget);
    if (ret != CM_SUCCESS) {
        HksFreeParamSet(&paramSet);
        CM_LOG_E("get keyalias failed");
        return ret;
    }

    ret = HksGenerateKey(&keyAlias, paramSet, NULL);
    HksFreeParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        CM_LOG_E("hks generate key failed, ret = %d", ret);
        return CMR_ERROR_KEY_GENERATE_FAILED;
    }
    return CM_SUCCESS;
}

int32_t CmKeyOpGenMacKeyIfNotExist(const struct CmBlob *alias)
{
    struct HksParam keyExistParams[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    };
    struct HksParamSet *paramSet = NULL;
    int32_t ret = ConstructParamSet(keyExistParams, sizeof(keyExistParams) / sizeof(struct HksParam), &paramSet,
        CM_AUTH_STORAGE_LEVEL_EL1, alias);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to construct key exist paramSet");
        return CMR_ERROR_KEY_CHECK_EXIST_PARAM_FAILED;
    }

    struct HksBlob keyAlias = { alias->size, alias->data };

    uint8_t encodeBuf[MAX_LEN_BASE64URL_SHA256] = { 0 };
    struct CmBlob encodeTarget = { sizeof(encodeBuf), encodeBuf };
    ret = GetKeyAlias(&keyAlias, &encodeTarget);
    if (ret != CM_SUCCESS) {
        HksFreeParamSet(&paramSet);
        CM_LOG_E("get keyalias failed");
        return ret;
    }

    ret = HksKeyExist(&keyAlias, paramSet);
    HksFreeParamSet(&paramSet);
    if (ret == HKS_SUCCESS) {
        return ret;
    }
    if (ret != HKS_ERROR_NOT_EXIST) {
        CM_LOG_E("find mac key failed, ret = %d", ret);
        return CMR_ERROR_KEY_CHECK_EXIST_FAILED;
    }

    return CmKeyOpGenMacKey(alias, CM_AUTH_STORAGE_LEVEL_EL1);
}

int32_t CmKeyOpDeleteKey(const struct CmBlob *alias, enum CmAuthStorageLevel level)
{
    uint32_t huksAuthStorageLevel = TranslateToHuksLevel(level);
    struct HksParam deleteKeyParams[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = huksAuthStorageLevel },
    };
    struct HksParamSet *paramSet = NULL;
    int32_t ret = ConstructParamSet(deleteKeyParams, sizeof(deleteKeyParams) / sizeof(struct HksParam), &paramSet,
        level, alias);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to construct delete key paramSet");
        return CMR_ERROR_KEY_OPERATION_FAILED;
    }

    struct HksBlob keyAlias = { alias->size, alias->data };

    uint8_t encodeBuf[MAX_LEN_BASE64URL_SHA256] = { 0 };
    struct CmBlob encodeTarget = { sizeof(encodeBuf), encodeBuf };
    ret = GetKeyAlias(&keyAlias, &encodeTarget);
    if (ret != CM_SUCCESS) {
        HksFreeParamSet(&paramSet);
        CM_LOG_E("get keyalias failed");
        return ret;
    }

    ret = HksDeleteKey(&keyAlias, paramSet);
    HksFreeParamSet(&paramSet);
    if ((ret != HKS_SUCCESS) && (ret != HKS_ERROR_NOT_EXIST)) {
        CM_LOG_E("hks delete key failed, ret = %d", ret);
        return CMR_ERROR_KEY_OPERATION_FAILED;
    }

    return CM_SUCCESS;
}

int32_t CmKeyOpCalcMac(const struct CmBlob *alias, const struct CmBlob *srcData,
    struct CmBlob *mac, enum CmAuthStorageLevel level)
{
    uint32_t huksAuthStorageLevel = TranslateToHuksLevel(level);
    struct HksParam macParams[] = {
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = HKS_ALG_HMAC },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = HKS_AES_KEY_SIZE_256 },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = HKS_KEY_PURPOSE_MAC },
        { .tag = HKS_TAG_DIGEST, .uint32Param = HKS_DIGEST_SHA256 },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = huksAuthStorageLevel },
    };

    struct HksParamSet *paramSet = NULL;
    int32_t ret = ConstructParamSet(macParams, sizeof(macParams) / sizeof(struct HksParam), &paramSet,
        level, alias);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("construct mac init paramSet failed");
        return CMR_ERROR_KEY_MAC_PARAM_FAILED;
    }

    do {
        uint64_t handleValue = 0;
        struct HksBlob handle = { sizeof(handleValue), (uint8_t *)&handleValue };
        struct HksBlob keyAlias = { alias->size, alias->data };

        uint8_t encodeBuf[MAX_LEN_BASE64URL_SHA256] = { 0 };
        struct CmBlob encodeTarget = { sizeof(encodeBuf), encodeBuf };
        ret = GetKeyAlias(&keyAlias, &encodeTarget);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get keyalias failed");
            break;
        }

        ret = HksInit(&keyAlias, paramSet, &handle, NULL);
        if (ret != HKS_SUCCESS) {
            CM_LOG_E("mac calc init failed, ret = %d", ret);
            ret = CMR_ERROR_KEY_MAC_INIT_FAILED;
            break;
        }

        struct HksBlob inData = { srcData->size, srcData->data };
        struct HksBlob outMac = { mac->size, mac->data };
        ret = HksFinish(&handle, paramSet, &inData, &outMac);
        if (ret != HKS_SUCCESS) {
            CM_LOG_E("mac calc finish failed, ret = %d", ret);
            ret = CMR_ERROR_KEY_MAC_FINISH_FAILED;
            break;
        }
        mac->size = outMac.size;
    } while (0);

    HksFreeParamSet(&paramSet);
    return ret;
}

int32_t CmKeyOpImportKey(const struct CmBlob *alias, const struct CmKeyProperties *properties,
    const struct CmBlob *keyPair)
{
    uint32_t huksAuthStorageLevel = TranslateToHuksLevel(properties->level);
    struct HksParam importKeyParams[] = {
        { .tag = HKS_TAG_IMPORT_KEY_TYPE, .uint32Param = HKS_KEY_TYPE_KEY_PAIR },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = properties->algType },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = properties->keySize },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = properties->purpose },
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = huksAuthStorageLevel },
    };

    struct HksParamSet *paramSet = NULL;
    int32_t ret = ConstructParamSet(importKeyParams, sizeof(importKeyParams) / sizeof(struct HksParam), &paramSet,
        properties->level, alias);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("construct import key paramSet failed");
        return CMR_ERROR_KEY_IMPORT_PARAM_FAILED;
    }

    struct HksBlob keyAlias = { alias->size, alias->data };
    struct HksBlob key = { keyPair->size, keyPair->data };

    uint8_t encodeBuf[MAX_LEN_BASE64URL_SHA256] = { 0 };
    struct CmBlob encodeTarget = { sizeof(encodeBuf), encodeBuf };
    ret = GetKeyAlias(&keyAlias, &encodeTarget);
    if (ret != CM_SUCCESS) {
        HksFreeParamSet(&paramSet);
        CM_LOG_E("get keyalias failed");
        return ret;
    }

    ret = HksImportKey(&keyAlias, paramSet, &key);
    HksFreeParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        CM_LOG_E("hks import key failed, ret = %d", ret);
        return CMR_ERROR_KEY_IMPORT_FAILED;
    }
    return CM_SUCCESS;
}

static void FillKeySpec(const struct HksParamSet *paramSet, struct CmKeyProperties *spec)
{
    for (uint32_t i = 0; i < paramSet->paramsCnt; ++i) {
        switch (paramSet->params[i].tag) {
            case HKS_TAG_ALGORITHM:
                spec->algType = paramSet->params[i].uint32Param;
                break;
            case HKS_TAG_KEY_SIZE:
                spec->keySize = paramSet->params[i].uint32Param;
                break;
            default:
                break;
        }
    }
}

static void TranslateToHuksProperties(const struct CmSignatureSpec *spec, struct CmKeyProperties *keyProperties)
{
    keyProperties->purpose = INVALID_PROPERTY_VALUE;
    keyProperties->padding = INVALID_PROPERTY_VALUE;
    keyProperties->digest = INVALID_PROPERTY_VALUE;
    keyProperties->level = INVALID_PROPERTY_VALUE;

    for (uint32_t i = 0; i < CM_ARRAY_SIZE(g_cmPurposeProperty); ++i) {
        if (spec->purpose == g_cmPurposeProperty[i].cmProperty) {
            keyProperties->purpose = g_cmPurposeProperty[i].huksProperty;
            break;
        }
    }

    for (uint32_t i = 0; i < CM_ARRAY_SIZE(g_cmPaddingProperty); ++i) {
        if (spec->padding == g_cmPaddingProperty[i].cmProperty) {
            keyProperties->padding = g_cmPaddingProperty[i].huksProperty;
            break;
        }
    }

    for (uint32_t i = 0; i < CM_ARRAY_SIZE(g_cmDigestProperty); ++i) {
        if (spec->digest == g_cmDigestProperty[i].cmProperty) {
            keyProperties->digest = g_cmDigestProperty[i].huksProperty;
            break;
        }
    }

    CM_LOG_D("purpose[%u], digest[%u], padding[%u]", spec->purpose, spec->digest, spec->padding);
}

static int32_t GetKeyProperties(const struct CmBlob *commonUri, struct CmKeyProperties *keySpec,
    enum CmAuthStorageLevel level)
{
    struct HksParamSet *outParamSet = (struct HksParamSet*)CMMalloc(DEFAULT_LEN_USED_FOR_MALLOC);
    if (outParamSet == NULL) {
        CM_LOG_E("malloc failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    outParamSet->paramSetSize = DEFAULT_LEN_USED_FOR_MALLOC;

    uint32_t huksAuthStorageLevel = TranslateToHuksLevel(level);
    struct HksParam getKeyParams[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = huksAuthStorageLevel },
    };
    struct HksParamSet *inParamSet = NULL;
    int32_t ret = ConstructParamSet(getKeyParams, sizeof(getKeyParams) / sizeof(struct HksParam), &inParamSet,
        level, commonUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to construct get key inParamSet");
        CM_FREE_PTR(outParamSet);
        return CMR_ERROR_KEY_OPERATION_FAILED;
    }

    struct HksBlob keyAlias = { commonUri->size, commonUri->data };
    uint8_t encodeBuf[MAX_LEN_BASE64URL_SHA256] = { 0 };
    struct CmBlob encodeTarget = { sizeof(encodeBuf), encodeBuf };
    ret = GetKeyAlias(&keyAlias, &encodeTarget);
    if (ret != CM_SUCCESS) {
        CM_FREE_PTR(outParamSet);
        HksFreeParamSet(&inParamSet);
        CM_LOG_E("get keyalias failed");
        return ret;
    }

    ret = HksGetKeyParamSet(&keyAlias, inParamSet, outParamSet);

    HksFreeParamSet(&inParamSet);
    if (ret != HKS_SUCCESS) {
        CM_LOG_E("get paramSet from huks failed, ret = %d", ret);
        CM_FREE_PTR(outParamSet);
        return ret;
    }

    FillKeySpec(outParamSet, keySpec);
    CM_FREE_PTR(outParamSet);
    return ret;
}

static int32_t AddParamsToParamSet(const struct CmBlob *commonUri, const struct CmSignatureSpec *spec,
    struct HksParamSet *paramSet, enum CmAuthStorageLevel level)
{
    struct CmKeyProperties inputKeyProp = {0};
    TranslateToHuksProperties(spec, &inputKeyProp);

    int32_t ret;
    do {
        struct CmKeyProperties keySpec = {0};
        ret = GetKeyProperties(commonUri, &keySpec, level);
        if (ret != HKS_SUCCESS) {
            CM_LOG_E("Failed to get key properties, ret = %d", ret);
            break;
        }

        uint32_t huksAuthStorageLevel = TranslateToHuksLevel(level);
        struct HksParam params[] = {
            { .tag = HKS_TAG_ALGORITHM, .uint32Param = keySpec.algType },
            { .tag = HKS_TAG_KEY_SIZE, .uint32Param = keySpec.keySize },
            { .tag = HKS_TAG_PURPOSE, .uint32Param = inputKeyProp.purpose },
            { .tag = HKS_TAG_DIGEST, .uint32Param = inputKeyProp.digest },
            { .tag = HKS_TAG_PADDING, .uint32Param = inputKeyProp.padding },
            { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = huksAuthStorageLevel },
        };

        ret = AddUserIdParam(paramSet, level, commonUri);
        if (ret != HKS_SUCCESS) {
            CM_LOG_E("add userid param failed");
            break;
        }

        ret = HksAddParams(paramSet, params, sizeof(params) / sizeof(struct HksParam));
        if (ret != HKS_SUCCESS) {
            CM_LOG_E("add params failed");
            break;
        }

        /* In the case of RSA PSS-Padding, set the salt length to the digest length */
        if ((keySpec.algType == HKS_ALG_RSA) && (inputKeyProp.padding == HKS_PADDING_PSS)) {
            struct HksParam saltLenParam = {
                .tag = HKS_TAG_RSA_PSS_SALT_LEN_TYPE,
                .uint32Param = HKS_RSA_PSS_SALTLEN_DIGEST
            };
            ret = HksAddParams(paramSet, &saltLenParam, 1);
            if (ret != HKS_SUCCESS) {
                CM_LOG_E("add saltLen tag failed");
                break;
            }
        }
    } while (0);

    return (ret == HKS_SUCCESS) ? CM_SUCCESS : CMR_ERROR_KEY_OPERATION_FAILED;
}

static int32_t ConstructInitParamSet(const struct CmBlob *commonUri, const struct CmSignatureSpec *spec,
    struct HksParamSet **outParamSet, enum CmAuthStorageLevel level)
{
    struct HksParamSet *paramSet = NULL;
    int32_t ret = HksInitParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        CM_LOG_E("init paramSet failed, ret = %d", ret);
        return CMR_ERROR_KEY_OPERATION_FAILED;
    }

    ret = AddParamsToParamSet(commonUri, spec, paramSet, level);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("add params failed");
        HksFreeParamSet(&paramSet);
        return ret;
    }

    ret = HksBuildParamSet(&paramSet);
    if (ret != HKS_SUCCESS) {
        CM_LOG_E("build params failed, ret = %d", ret);
        HksFreeParamSet(&paramSet);
        return CMR_ERROR_KEY_OPERATION_FAILED;
    }

    *outParamSet = paramSet;
    return CM_SUCCESS;
}

static int32_t ServiceSignVerifyUpdate(const struct CmBlob *handle, const struct HksParamSet *paramSet,
    const struct CmBlob *inData)
{
    uint32_t temp = 0;
    struct HksBlob tempOut = { sizeof(uint32_t), (uint8_t *)&temp };

    struct HksBlob handleHks = { handle->size, handle->data };
    struct HksBlob inDataHks = { inData->size, inData->data };

    int32_t ret = HksUpdate(&handleHks, paramSet, &inDataHks, &tempOut);
    if (ret != HKS_SUCCESS) {
        CM_LOG_E("huks update fail, ret = %d", ret);
        CmDeleteSession(handle);
        return CMR_ERROR_KEY_UPDATE_FAILED;
    }
    return CM_SUCCESS;
}

static int32_t ServiceSignVerifyFinish(const struct CmBlob *handle, const struct HksParamSet *paramSet,
    const struct CmBlob *inData, struct CmBlob *outData)
{
    struct HksBlob handleHks = { handle->size, handle->data };
    struct HksBlob inDataHks = { inData->size, inData->data };
    struct HksBlob outDataHks = { outData->size, outData->data };

    int32_t ret = HksFinish(&handleHks, paramSet, &inDataHks, &outDataHks);
    CmDeleteSession(handle);
    if (ret != HKS_SUCCESS) {
        CM_LOG_E("huks finish fail, ret = %d", ret);
        return CMR_ERROR_KEY_FINISH_FAILED;
    }
    outData->size = outDataHks.size;
    return CM_SUCCESS;
}

static int32_t ServiceSignVerifyAbort(const struct CmBlob *handle, const struct HksParamSet *paramSet)
{
    struct HksBlob handleHks = { handle->size, handle->data };

    int32_t ret = HksAbort(&handleHks, paramSet);
    CmDeleteSession(handle);
    if (ret != HKS_SUCCESS) {
        CM_LOG_E("huks abort fail, ret = %d", ret);
        return CMR_ERROR_KEY_ABORT_FAILED;
    }
    return CM_SUCCESS;
}

int32_t CmKeyOpInit(const struct CmContext *context, const struct CmBlob *alias, const struct CmSignatureSpec *spec,
    enum CmAuthStorageLevel level, struct CmBlob *handle)
{
    struct HksParamSet *paramSet = NULL;
    int32_t ret = ConstructInitParamSet(alias, spec, &paramSet, level);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("construct init paramSet failed, ret = %d", ret);
        return CMR_ERROR_KEY_INIT_PARAM_FAILED;
    }

    do {
        struct HksBlob keyAlias = { alias->size, alias->data };
        uint8_t encodeBuf[MAX_LEN_BASE64URL_SHA256] = { 0 };
        struct CmBlob encodeTarget = { sizeof(encodeBuf), encodeBuf };
        ret = GetKeyAlias(&keyAlias, &encodeTarget);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get keyalias failed");
            break;
        }

        struct HksBlob handleOut = { handle->size, handle->data };
        ret = HksInit(&keyAlias, paramSet, &handleOut, NULL);
        if (ret != HKS_SUCCESS) {
            CM_LOG_E("Huks init failed, ret = %d", ret);
            ret = CMR_ERROR_KEY_INIT_FAILED;
            break;
        }
        handle->size = handleOut.size;

        struct CmSessionNodeInfo info = { context->userId, context->uid, *alias };
        ret = CmCreateSession(&info, handle, true);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("create session failed, ret = %d", ret);
            break;
        }
    } while (0);

    HksFreeParamSet(&paramSet);
    return ret;
}

int32_t CmKeyOpProcess(enum CmSignVerifyCmd cmdId, const struct CmContext *context, const struct CmBlob *handle,
    const struct CmBlob *inData, struct CmBlob *outData)
{
    struct CmSessionNodeInfo info = { context->userId, context->uid, { 0, NULL } };
    if (CmQuerySession(&info, handle) == NULL) {
        CM_LOG_E("session handle not exist");
        return (cmdId == SIGN_VERIFY_CMD_ABORT) ? CM_SUCCESS : CMR_ERROR_NOT_EXIST;
    }

    struct HksParam params[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE },
    };
    struct HksParamSet *paramSet = NULL;
    /* There is no need to specify level and userid. Pass the default values instead. */
    int32_t ret = ConstructParamSet(params, sizeof(params) / sizeof(struct HksParam), &paramSet,
        CM_AUTH_STORAGE_LEVEL_EL1, NULL);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to construct paramSet");
        CmDeleteSession(handle);
        return CMR_ERROR_KEY_PROCESS_PARAM_FAILED;
    }

    switch (cmdId) {
        case SIGN_VERIFY_CMD_UPDATE:
            ret = ServiceSignVerifyUpdate(handle, paramSet, inData);
            break;
        case SIGN_VERIFY_CMD_FINISH:
            ret = ServiceSignVerifyFinish(handle, paramSet, inData, outData);
            break;
        case SIGN_VERIFY_CMD_ABORT:
            ret = ServiceSignVerifyAbort(handle, paramSet);
            break;
        default:
            ret = CMR_ERROR_INVALID_ARGUMENT;
            break;
    }

    HksFreeParamSet(&paramSet);
    return ret;
}
// LCOV_EXCL_STOP
