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

#include "stdio.h"
#include "stdbool.h"
#include "stdint.h"
#include "cert_manager_type.h"
#include "cert_manager_file.h"
#include "cert_manager_status.h"
#include "cert_manager_mem.h"
#include "cert_manager_util.h"
#include "cm_log.h"
#include "cm_type.h"
#include "hks_api.h"
#include "hks_type.h"
#include "hks_param.h"

#define CMALG(x)      (x)
#define CMPURPOSE(x)  (x)
#define CMDIGEST(x)   (x)
#define CMPADDING(x)  (x)
#define CMAUTHTYPE(x) (x)

int32_t CertManagerBuildKeySpec(struct HksParamSet **params, const struct CMKeyProperties *properties)
{
    int32_t rc = CMR_OK;
    ASSERT_CM_CALL(HksInitParamSet(params));

    struct HksParam p[] = {
        { .tag = HKS_TAG_IMPORT_KEY_TYPE, .uint32Param = HKS_KEY_TYPE_KEY_PAIR },
        { .tag = HKS_TAG_ALGORITHM, .uint32Param = CMALG(properties->alg) },
        { .tag = HKS_TAG_KEY_SIZE, .uint32Param = properties->size },
        { .tag = HKS_TAG_PURPOSE, .uint32Param = CMPURPOSE(properties->purpose) },
        { .tag = HKS_TAG_DIGEST, .uint32Param =  CMDIGEST(properties->digest) },
        { .tag = HKS_TAG_PADDING, .uint32Param = CMPADDING(properties->padding) },
    };
    TRY_CM_CALL(HksAddParams(*params, p, sizeof(p) / sizeof(struct HksParam)), rc);

    if (properties->authType != CM_AUTH_TYPE_NONE) {
        struct HksParam authParams[] = {
            { .tag = HKS_TAG_NO_AUTH_REQUIRED, .boolParam = false },
            { .tag = HKS_TAG_USER_AUTH_TYPE, .uint32Param = CMAUTHTYPE(properties->authType) },
            { .tag = HKS_TAG_AUTH_TIMEOUT, .uint32Param = properties->authTimeout },
        };
        TRY_CM_CALL(HksAddParams(*params, authParams, sizeof(authParams) / sizeof(struct HksParam)), rc);
    }

    TRY_CM_CALL(HksBuildParamSet(params), rc);

finally:
    if (rc != HKS_SUCCESS && *params != NULL) {
        HksFreeParamSet(params);
        *params = NULL;
    }
    return CM_ERROR(rc);
}

static int32_t CertManagerBuildMacKeySpec(struct HksParamSet **params)
{
    struct CMKeyProperties props = {
        .alg = HKS_ALG_HMAC,
        .size = CM_HMAC_KEY_SIZE_256,
        .padding = 0,
        .purpose = HKS_KEY_PURPOSE_MAC,
        .digest = HKS_DIGEST_SHA256
    };
    return CertManagerBuildKeySpec(params, &props);
}

int32_t CertManagerHmac(const char *uri, const struct CmBlob *data, struct CmMutableBlob *mac)
{
    ASSERT_ARGS(uri && data && mac);

    int rc = CMR_OK;

    struct HksBlob in =  HKS_BLOB(data);
    struct HksBlob out = HKS_BLOB(mac);
    struct HksBlob alias = { .size = strlen(uri), .data = (uint8_t *) uri };

    struct HksParamSet *params = NULL;
    TRY_FUNC(CertManagerBuildMacKeySpec(&params), rc);
    TRY_CM_CALL(HksMac(&alias, params, &in, &out), rc);

    CM_LOG_D("Mac computed. Len=%u\n", out.size);
    mac->size = out.size;

finally:
    if (params != NULL) {
        HksFreeParamSet(&params);
    }
    return rc;
}

int32_t CertManagerGenerateHmacKey(const char *uri)
{
    ASSERT_ARGS(uri);
    int32_t rc = CMR_OK;
    struct HksParamSet *params = NULL;

    TRY_FUNC(CertManagerBuildMacKeySpec(&params), rc);

    struct HksBlob alias = {.size = strlen(uri), .data = (uint8_t *) uri};

    int32_t hksRc = HksKeyExist(&alias, NULL);
    if (hksRc == HKS_ERROR_NOT_EXIST) {
        TRY_CM_CALL(HksGenerateKey(&alias, params, NULL), rc);
    } else {
        rc = CM_ERROR(hksRc);
    }

finally:
    if (params != NULL) {
        HksFreeParamSet(&params);
    }
    return rc;
}