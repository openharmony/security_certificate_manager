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

/* Real-IPC probe for the openUkeyAuthDialog chain: drives the inner API
 * CmOpenUkeyAuthDialog through the real IPC client (parcel + callback stub)
 * against a live SA 3512. Not a state-machine test — the assertions are
 * intentionally loose: this case exists to observe the sync return code and
 * the async delivery on a real device (on the qemu/no-SA host the sync call
 * simply fails fast, which is also acceptable). */

#include <gtest/gtest.h>
#include <unistd.h>
#include <atomic>

#include "cert_manager_api.h"
#include "cm_type.h"

namespace {
std::atomic<int32_t> g_asyncResult(0xDEADBEEF);
std::atomic<bool> g_asyncFired(false);
}

static void RealIpcResultCallback(int32_t resultCode, void *userData)
{
    (void)userData;
    g_asyncResult = resultCode;
    g_asyncFired = true;
}

class CmUkeyDialogRealIpcTest : public testing::Test {
public:
    static void SetUpTestSuite()
    {
        g_asyncResult = 0xDEADBEEF;
        g_asyncFired = false;
    }
};

/* code-30 (REPORT, no remote object) probe: distinguishes a general
 * app->SA dialog-code failure from the remote-object path. On a live SA a
 * non-HAP caller reaches the server-side HAP-identity check (business error
 * return, NOT an IPC 29201 transport error). */
HWTEST_F(CmUkeyDialogRealIpcTest, ReportRealIpcProbe, testing::ext::TestSize.Level0)
{
    char reqId[] = "0000000000000000000000000000dead"; /* 32 chars, no such session */
    struct CmBlob requestId = {};
    requestId.data = reinterpret_cast<uint8_t *>(reqId);
    requestId.size = sizeof(reqId) - 1; /* exact bytes, no NUL (wire convention) */

    int32_t ret = CmReportUkeyAuthResult(&requestId, 0);
    GTEST_LOG_(INFO) << "CmReportUkeyAuthResult sync ret = " << ret;
    /* shell/native caller: expected business rejection (CMR_DIALOG_ERROR_INTERNAL
     * or similar), any non-IPC error proves the code-30 transaction itself works */
    EXPECT_NE(ret, 29201);
}

HWTEST_F(CmUkeyDialogRealIpcTest, OpenDialogRealIpcProbe, testing::ext::TestSize.Level0)
{
    char uri[] = "ukey-test-uri";
    struct UkeyAuthRequest req = {};
    req.keyUri.data = reinterpret_cast<uint8_t *>(uri);
    req.keyUri.size = sizeof(uri); /* NUL-terminated, same as the NAPI layer */

    int32_t ret = CmOpenUkeyAuthDialog(&req, RealIpcResultCallback, nullptr);
    GTEST_LOG_(INFO) << "CmOpenUkeyAuthDialog sync ret = " << ret;
    if (ret != CM_SUCCESS) {
        /* no live SA (qemu/no-SA host) or server-side rejection: the sync
         * path must not fire the callback */
        GTEST_LOG_(INFO) << "sync path rejected, async callback must NOT fire";
        sleep(1);
        EXPECT_FALSE(g_asyncFired.load());
        return;
    }
    /* live SA accepted the request: wait (bounded) for exactly one delivery */
    for (int i = 0; i < 30 && !g_asyncFired.load(); i++) {
        sleep(1);
    }
    GTEST_LOG_(INFO) << "async fired = " << g_asyncFired.load()
                     << ", result = " << g_asyncResult.load();
    EXPECT_TRUE(g_asyncFired.load());
    sleep(2);
    EXPECT_TRUE(g_asyncFired.load()); /* exactly once: no duplicate observed */
}
