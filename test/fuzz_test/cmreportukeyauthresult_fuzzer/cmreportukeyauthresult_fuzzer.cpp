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

#include "cmreportukeyauthresult_fuzzer.h"

#include "cert_manager_api.h"
#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"

namespace {
const uint32_t MAX_REQUEST_ID_LEN = 32;
}

using namespace CmFuzzTest;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        uint32_t requestIdSize = (size > MAX_REQUEST_ID_LEN) ? MAX_REQUEST_ID_LEN :
            static_cast<uint32_t>(size);

        /* resultCode 取满 4 字节：覆盖 JS 协议码（29700001/2/3/6）、负值与未知值
         * 的白名单折叠路径（spec §9.3），而非仅 0..255 */
        int32_t resultCode = 0;
        if (size >= MAX_REQUEST_ID_LEN + sizeof(resultCode)) {
            if (memcpy_s(&resultCode, sizeof(resultCode), data + MAX_REQUEST_ID_LEN,
                sizeof(resultCode)) != EOK) {
                return false;
            }
        }

        struct CmBlob requestId = { requestIdSize, const_cast<uint8_t *>(data) };

        CertmanagerTest::MockHapToken mockHap;
        (void)CmReportUkeyAuthResult(&requestId, resultCode);

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
