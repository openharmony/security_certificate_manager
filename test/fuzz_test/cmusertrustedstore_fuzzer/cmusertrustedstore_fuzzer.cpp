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

#include "cmusertrustedstore_fuzzer.h"

#include "cm_fuzz_test_common.h"
#include "cert_manager_api.h"
#include "cm_cert_data_user.h"
#include "cm_ipc_client_serialization.h"
#include "cm_ipc_service.h"
#include "cm_param.h"
#include "cert_manager_status.h"
#include "cm_type.h"

using namespace CmFuzzTest;
namespace OHOS {
    constexpr uint32_t TEST_USERID = 100;
    constexpr uint32_t MIN_DATA_USE_TIME = 10;
    static bool InstallUserCert(uint8_t *tmpData, uint32_t *remainSize, uint32_t *offset, struct CmBlob *keyUri)
    {
        uint32_t userId = TEST_USERID;
        if (TenPercentChanceOfBeingTrue(tmpData, remainSize, offset)) {
            if (!GetUintFromBuffer(tmpData, remainSize, offset, &userId)) {
                return false;
            }
        }

        uint32_t status = CERT_STATUS_ENABLED;
        if (TenPercentChanceOfBeingTrue(tmpData, remainSize, offset)) {
            if (!GetUintFromBuffer(tmpData, remainSize, offset, &status)) {
                return false;
            }
        }
        struct CmBlob userCert = { sizeof(g_certData01), const_cast<uint8_t *>(g_certData01) };
        static uint8_t certAliasBuf01[] = "40dc992e";
        struct CmBlob certAlias = { sizeof(certAliasBuf01), certAliasBuf01 };
        struct CmParam params01[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = userCert },
            { .tag = CM_TAG_PARAM1_BUFFER, .blob = certAlias },
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = userId },
            { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = status },
        };
        struct CmParamSet *paramSet01 = NULL;
        int32_t ret = CmParamsToParamSet(params01, CM_ARRAY_SIZE(params01), &paramSet01);
        if (ret != CM_SUCCESS) {
            return false;
        }
        struct CmBlob paramSetBlob = { paramSet01->paramSetSize, reinterpret_cast<uint8_t *>(paramSet01) };
        (void)CmIpcServiceInstallUserCert(&paramSetBlob, keyUri, nullptr);
        CmFreeParamSet(&paramSet01);
        return true;
    }
    static bool SetUserCertStatus(uint8_t *tmpData, uint32_t *remainSize, uint32_t *offset, struct CmBlob *keyUri)
    {
        if (TenPercentChanceOfBeingTrue(tmpData, remainSize, offset)) {
            if (!GetCmBlobFromBuffer(tmpData, remainSize, offset, keyUri)) {
                return false;
            }
        }
        uint32_t store = CM_USER_TRUSTED_STORE;
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

        struct CmParam params02[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = *keyUri },
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = store },
            { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = state },
        };

        struct CmParamSet *paramSet02 = nullptr;
        int32_t ret = CmParamsToParamSet(&params02[0], CM_ARRAY_SIZE(params02), &paramSet02);
        if (ret != CM_SUCCESS) {
            return false;
        }
        struct CmBlob paramSetBlob = { paramSet02->paramSetSize, reinterpret_cast<uint8_t*>(paramSet02) };
        (void)CmIpcServiceSetUserCertStatus(&paramSetBlob, nullptr, nullptr);
        CmFreeParamSet(&paramSet02);
        return true;
    }

    static bool GetAllUserCert(uint8_t *tmpData, uint32_t *remainSize, uint32_t *offset)
    {
        uint32_t store = CM_USER_TRUSTED_STORE;
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
        struct CmParam params03[] = {
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = store },
        };
        struct CmParamSet *paramSet03 = nullptr;
        int32_t ret = CmParamsToParamSet(&params03[0], CM_ARRAY_SIZE(params03), &paramSet03);
        if (ret != CM_SUCCESS) {
            CmFree(certListBlobData);
            return false;
        }
        struct CmBlob paramSetBlob = { paramSet03->paramSetSize, reinterpret_cast<uint8_t*>(paramSet03) };
        (void)CmIpcServiceGetUserCertList(&paramSetBlob, &certListBlob, nullptr);
        CmFree(certListBlobData);
        CmFreeParamSet(&paramSet03);
        return true;
    }

    static bool GetUserCert(uint8_t *tmpData, uint32_t *remainSize, uint32_t *offset, struct CmBlob *keyUri)
    {
        if (TenPercentChanceOfBeingTrue(tmpData, remainSize, offset)) {
            if (!GetCmBlobFromBuffer(tmpData, remainSize, offset, keyUri)) {
                return false;
            }
        }
        uint32_t store = CM_USER_TRUSTED_STORE;
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
        struct CmParam params04[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = *keyUri },
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = store },
        };
        struct CmParamSet *paramSet04 = nullptr;
        int32_t ret = CmParamsToParamSet(&params04[0], CM_ARRAY_SIZE(params04), &paramSet04);
        if (ret != CM_SUCCESS) {
            CmFree(certInfoData);
            return false;
        }
        struct CmBlob paramSetBlob = { paramSet04->paramSetSize, reinterpret_cast<uint8_t*>(paramSet04) };
        (void)CmIpcServiceGetUserCertInfo(&paramSetBlob, &certInfoBlob, nullptr);
        CmFree(certInfoData);
        CmFreeParamSet(&paramSet04);
        return true;
    }

    static bool UnInstallUserCert(uint8_t *tmpData, uint32_t *remainSize, uint32_t *offset, struct CmBlob *keyUri)
    {
        if (TenPercentChanceOfBeingTrue(tmpData, remainSize, offset)) {
            if (!GetCmBlobFromBuffer(tmpData, remainSize, offset, keyUri)) {
                return false;
            }
        }

        uint32_t store = CM_USER_TRUSTED_STORE;
        if (TenPercentChanceOfBeingTrue(tmpData, remainSize, offset)) {
            if (!GetUintFromBuffer(tmpData, remainSize, offset, &store)) {
                return false;
            }
        }
        struct CmParam params05[] = {
            { .tag = CM_TAG_PARAM0_BUFFER, .blob = *keyUri },
            { .tag = CM_TAG_PARAM0_UINT32, .uint32Param = store },
        };
        struct CmParamSet *paramSet05 = NULL;
        int32_t ret = CmParamsToParamSet(params05, CM_ARRAY_SIZE(params05), &paramSet05);
        if (ret != CM_SUCCESS) {
            return false;
        }
        struct CmBlob paramSetBlob = { paramSet05->paramSetSize, reinterpret_cast<uint8_t *>(paramSet05) };
        (void)CmIpcServiceUninstallUserCert(&paramSetBlob, nullptr, nullptr);
        CmFreeParamSet(&paramSet05);
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
        SetATPermission();

        bool ret = false;
        uint8_t keyUriData[] = "1d3472b9.0";
        struct CmBlob keyUri = { sizeof(keyUriData), &keyUriData[0] };

        do {
            if (!InstallUserCert(tmpData, &remainSize, &offset, &keyUri)) {
                break;
            }

            if (!SetUserCertStatus(tmpData, &remainSize, &offset, &keyUri)) {
                break;
            }

            if (!GetAllUserCert(tmpData, &remainSize, &offset)) {
                break;
            }

            if (!GetUserCert(tmpData, &remainSize, &offset, &keyUri)) {
                break;
            }

            if (!UnInstallUserCert(tmpData, &remainSize, &offset, &keyUri)) {
                break;
            }
            ret = true;
        } while (0);
        (void)CmIpcServiceUninstallAllUserCert(nullptr, nullptr, nullptr);
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

