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

#include "cmopenukeyauthdialog_fuzzer.h"

#include "cert_manager_api.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"

namespace {
const uint32_t MAX_KEY_URI_LEN = 4096;

void UkeyAuthDialogResultCallback(int32_t resultCode, void *userData)
{
    (void)resultCode;
    (void)userData;
}
}

using namespace CmFuzzTest;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t keyUriSize = (size > MAX_KEY_URI_LEN) ? MAX_KEY_URI_LEN :
            static_cast<uint32_t>(size);

        struct UkeyAuthRequest ukeyAuthRequest = {
            .keyUri = { keyUriSize, const_cast<uint8_t *>(data) }
        };

        CertmanagerTest::MockHapToken mockHap;
        (void)CmOpenUkeyAuthDialog(&ukeyAuthRequest, UkeyAuthDialogResultCallback, nullptr);

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
