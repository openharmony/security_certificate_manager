/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "cert_manager_crypto_operation.h"

#include "securec.h"

#include "cm_log.h"
#include "cm_type.h"

#include "blob.h"
#include "md.h"
#include "rand.h"

int32_t CmGetRandom(struct CmBlob *random)
{
    HcfRand *randObj = NULL;
    struct HcfBlob randomBlob = { NULL, 0 };

    int32_t ret = CMR_ERROR_KEY_OPERATION_FAILED;
    do {
        int32_t retHcf = (int32_t)HcfRandCreate(&randObj);
        if (retHcf != HCF_SUCCESS) {
            CM_LOG_E("creat random obj failed, ret = %d", retHcf);
            break;
        }

        retHcf = (int32_t)randObj->generateRandom(randObj, random->size, &randomBlob);
        if (retHcf != HCF_SUCCESS) {
            CM_LOG_E("generate random value failed, ret = %d", retHcf);
            break;
        }

        if (memcpy_s(random->data, random->size, randomBlob.data, randomBlob.len) != EOK) {
            CM_LOG_E("copy random value failed");
            break;
        }
        random->size = randomBlob.len;
        ret = CM_SUCCESS;
    } while (0);

    HcfBlobDataClearAndFree(&randomBlob);
    HcfObjDestroy(randObj);

    return ret;
}

int32_t CmGetHash(const struct CmBlob *inData, struct CmBlob *hash)
{
    HcfMd *mdObj = NULL;
    struct HcfBlob outBlob = { NULL, 0 };

    int32_t ret = CMR_ERROR_KEY_OPERATION_FAILED;
    do {
        int32_t retHcf = (int32_t)HcfMdCreate("SHA256", &mdObj);
        if (retHcf != HCF_SUCCESS) {
            CM_LOG_E("creat hash obj failed, ret = %d", retHcf);
            break;
        }

        HcfBlob inBlob = { .data = inData->data, .len = inData->size };
        retHcf = mdObj->update(mdObj, &inBlob);
        if (retHcf != HCF_SUCCESS) {
            CM_LOG_E("hash update failed, ret = %d", retHcf);
            break;
        }
        retHcf = mdObj->doFinal(mdObj, &outBlob);
        if (retHcf != HCF_SUCCESS) {
            CM_LOG_E("hash final failed, ret = %d", retHcf);
            break;
        }

        if (hash->size < outBlob.len) {
            CM_LOG_E("hash input size[%u] too small", hash->size);
            ret = CMR_ERROR_BUFFER_TOO_SMALL;
            break;
        }
        if (memcpy_s(hash->data, hash->size, outBlob.data, outBlob.len) != EOK) {
            CM_LOG_E("copy hash value failed");
            break;
        }
        hash->size = outBlob.len;
        ret = CM_SUCCESS;
    } while (0);

    HcfBlobDataClearAndFree(&outBlob);
    HcfObjDestroy(mdObj);
    return ret;
}

