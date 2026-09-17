/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "cmopenauthdialogforukeydriver_fuzzer.h"

#include "cert_manager_api.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"

namespace {
const uint32_t MAX_ABILITY_NAME_LEN = 128;
const uint32_t MAX_KEY_URI_LEN = 4096;

void DummyCallback(int32_t resultCode, void *userData)
{
    (void)resultCode;
    (void)userData;
}
}

using namespace CmFuzzTest;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        /* fuzz layout: [4B abilityType][4B timeout][rest: abilityName + keyUri + customData bytes] */
        uint32_t abilityType = 0;
        uint32_t timeout = 0;
        const uint8_t *payload = data;
        size_t payloadSize = size;
        if (size >= 8) {
            if (memcpy_s(&abilityType, sizeof(abilityType), data, sizeof(abilityType)) != EOK) {
                return false;
            }
            if (memcpy_s(&timeout, sizeof(timeout), data + 4, sizeof(timeout)) != EOK) {
                return false;
            }
            payload = data + 8;
            payloadSize = size - 8;
        }

        uint32_t abilityNameSize = (payloadSize > MAX_ABILITY_NAME_LEN) ? MAX_ABILITY_NAME_LEN :
            static_cast<uint32_t>(payloadSize);
        size_t restSize = payloadSize - abilityNameSize;
        uint32_t keyUriSize = (restSize > MAX_KEY_URI_LEN) ? MAX_KEY_URI_LEN :
            static_cast<uint32_t>(restSize);

        struct UkeyAuthDialogInfo dialogInfo = {
            .abilityName = { abilityNameSize, const_cast<uint8_t *>(payload) },
            .abilityType = abilityType,
        };
        struct UkeyAuthRequest ukeyAuthRequest = {
            .keyUri = { keyUriSize, const_cast<uint8_t *>(payload + abilityNameSize) },
            .timeoutDuration = timeout,
            .scene = CM_UKEY_AUTH_SCENE_LOGIN,   /* Task 6 删除该字段时同步删本行 */
            .customData = { 0, nullptr },
        };

        CertmanagerTest::MockHapToken mockHap;
        (void)CmOpenUkeyAuthDialogForDriver(&dialogInfo, &ukeyAuthRequest, DummyCallback, nullptr);

        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
