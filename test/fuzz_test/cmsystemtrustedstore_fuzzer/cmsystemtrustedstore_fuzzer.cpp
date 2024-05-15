/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cmsystemtrustedstore_fuzzer.h"

#include "cm_fuzz_test_common.h"
#include "cert_manager_api.h"
#include "cm_test_common.h"
#include "cm_ipc_client_serialization.h"
#include "cm_ipc_service.h"
#include "cm_param.h"
#include "cert_manager_status.h"

using namespace CmFuzzTest;
namespace OHOS {
    constexpr uint32_t MIN_DATA_USE_TIME = 6;
    static bool SetSysCertStatus(uint8_t *tmpData, uint32_t *remainSize, uint32_t *offset, struct CmBlob *keyUri)
    {
        if (TenPercentChanceOfBeingTrue(tmpData, remainSize, offset)) {
            if (!GetCmBlobFromBuffer(tmpData, remainSize, offset, keyUri)) {
                return false;
            }
        }
        uint32_t store = CM_SYSTEM_TRUSTED_STORE;
        if (TenPercentChanceOfBeingTrue(tmpData, remainSize, offset)) {
            if (!GetUintFromBuffer(tmpData, remainSize, offset, &store)) {
                return false;
            }
        }

        uint32_t state = CERT_STATUS_ENABLED;
        if (TenPercentChanceOfBeingTrue(tmpData, remainSize, offset)) {
            if (!GetUintFromBuffer(tmpData, remainSize, offset, &state)) {
                return false;
            }
        }

        struct CmParam params01[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = *keyUri },
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = store },
            { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = state },
        };

        struct CmParamSet *paramSet01 = nullptr;
        int32_t ret = CmParamsToParamSet(&params01[0], CM_ARRAY_SIZE(params01), &paramSet01);
        if (ret != CM_SUCCESS) {
            return false;
        }
        struct CmBlob paramSetBlob = { paramSet01->paramSetSize, reinterpret_cast<uint8_t*>(paramSet01) };
        (void)CmIpcServiceSetCertStatus(&paramSetBlob, nullptr, nullptr);
        CmFreeParamSet(&paramSet01);
        return true;
    }

    static bool GetAllSysCert(uint8_t *tmpData, uint32_t *remainSize, uint32_t *offset)
    {
        uint32_t store = CM_SYSTEM_TRUSTED_STORE;
        if (TenPercentChanceOfBeingTrue(tmpData, remainSize, offset)) {
            if (!GetUintFromBuffer(tmpData, remainSize, offset, &store)) {
                return false;
            }
        }
        uint8_t *certListBlobData = reinterpret_cast<uint8_t *>(CmMalloc(CERT_LIST_LEN));
        if (certListBlobData == nullptr) {
            return false;
        }
        struct CmBlob certListBlob = { CERT_LIST_LEN, certListBlobData };
        struct CmParam params02[] = {
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = store },
        };
        struct CmParamSet *paramSet02 = nullptr;
        int32_t ret = CmParamsToParamSet(&params02[0], CM_ARRAY_SIZE(params02), &paramSet02);
        if (ret != CM_SUCCESS) {
            CmFree(certListBlobData);
            return false;
        }
        struct CmBlob paramSetBlob = { paramSet02->paramSetSize, reinterpret_cast<uint8_t*>(paramSet02) };
        (void)CmIpcServiceGetCertificateList(&paramSetBlob, &certListBlob, nullptr);
        CmFree(certListBlobData);
        CmFreeParamSet(&paramSet02);
        return true;
    }

    static bool GetSysCert(uint8_t *tmpData, uint32_t *remainSize, uint32_t *offset, struct CmBlob *keyUri)
    {
        if (TenPercentChanceOfBeingTrue(tmpData, remainSize, offset)) {
            if (!GetCmBlobFromBuffer(tmpData, remainSize, offset, keyUri)) {
                return false;
            }
        }
        uint32_t store = CM_SYSTEM_TRUSTED_STORE;
        if (TenPercentChanceOfBeingTrue(tmpData, remainSize, offset)) {
            if (!GetUintFromBuffer(tmpData, remainSize, offset, &store)) {
                return false;
            }
        }
        uint8_t *certInfoData = reinterpret_cast<uint8_t *>(CmMalloc(CERT_INFO_LEN));
        if (certInfoData == nullptr) {
            return false;
        }
        CmBlob certInfoBlob = { CERT_INFO_LEN, certInfoData };
        struct CmParam params03[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = *keyUri },
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = store },
        };
        struct CmParamSet *paramSet03 = nullptr;
        int32_t ret = CmParamsToParamSet(&params03[0], CM_ARRAY_SIZE(params03), &paramSet03);
        if (ret != CM_SUCCESS) {
            CmFree(certInfoData);
            return false;
        }
        struct CmBlob paramSetBlob = { paramSet03->paramSetSize, reinterpret_cast<uint8_t*>(paramSet03) };
        (void)CmIpcServiceGetCertificateInfo(&paramSetBlob, &certInfoBlob, nullptr);
        CmFree(certInfoData);
        CmFreeParamSet(&paramSet03);
        return true;
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint8_t *tmpData = nullptr;
        if (!CopyMyData(data, size, sizeof(uint32_t) * MIN_DATA_USE_TIME, &tmpData)) {
            return false;
        }

        uint32_t remainSize = static_cast<uint32_t>(size);
        uint32_t offset = 0;
        CertmanagerTest::SetATPermission();

        bool ret = false;
        uint8_t keyUriData[] = "1d3472b9.0";
        struct CmBlob keyUri = { sizeof(keyUriData), &keyUriData[0] };

        do {
            if (!SetSysCertStatus(tmpData, &remainSize, &offset, &keyUri)) {
                break;
            }

            if (!GetAllSysCert(tmpData, &remainSize, &offset)) {
                break;
            }

            if (!GetSysCert(tmpData, &remainSize, &offset, &keyUri)) {
                break;
            }
            ret = true;
        } while (0);
        CmFree(tmpData);
        return ret;
    }
}


/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}

