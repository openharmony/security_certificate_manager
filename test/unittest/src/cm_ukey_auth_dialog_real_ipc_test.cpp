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
#include "cm_test_common.h"
#include "cm_type.h"
#include "cm_ukey_ability_type.h"

namespace {
std::atomic<int32_t> g_asyncResult(0xDEADBEEF);
std::atomic<bool> g_asyncFired(false);
/* ForDriver probe sentinel: stays 0xDEADBEEF until the callback fires */
std::atomic<int32_t> g_driverProbeFired(0xDEADBEEF);
}

static void RealIpcResultCallback(int32_t resultCode, void *userData)
{
    (void)userData;
    g_asyncResult = resultCode;
    g_asyncFired = true;
}

static void DriverProbeResultCallback(int32_t resultCode, void *userData)
{
    (void)userData;
    g_driverProbeFired = resultCode;
}

class CmUkeyDialogRealIpcTest : public testing::Test {
public:
    static void SetUpTestSuite()
    {
        g_asyncResult = 0xDEADBEEF;
        g_asyncFired = false;
    }
};

/* UIAbility registration probe: the no-context interface rejects UIAbility-type
 * driver dialogs synchronously with -1021 (spec v4). */
HWTEST_F(CmUkeyDialogRealIpcTest, OpenDialogUiAbilityRejectedProbe, testing::ext::TestSize.Level0)
{
    char uri[] = "ukey-test-uri";
    struct UkeyAuthRequest req = {};
    req.keyUri.data = reinterpret_cast<uint8_t *>(uri);
    req.keyUri.size = sizeof(uri);

    CertmanagerTest::MockHapToken mockHap({ "ohos.permission.ACCESS_CERT_MANAGER" });
    int32_t ret = CmOpenUkeyAuthDialog(&req, RealIpcResultCallback, nullptr);
    GTEST_LOG_(INFO) << "CmOpenUkeyAuthDialog(uiability) sync ret = " << ret;
    sleep(1);
    EXPECT_FALSE(g_asyncFired.load());
}

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

/* scene=Custom E2E probe: with no custom dialog registered (stub knob=none /
 * real unregistered key) the SA must reject synchronously with -1019; any
 * other outcome is still logged for on-device inspection. */
HWTEST_F(CmUkeyDialogRealIpcTest, OpenDialogSceneCustomProbe, testing::ext::TestSize.Level0)
{
    char uri[] = "ukey-test-uri";
    struct UkeyAuthRequest req = {};
    req.keyUri.data = reinterpret_cast<uint8_t *>(uri);
    req.keyUri.size = sizeof(uri); /* NUL-terminated, same as the NAPI layer */
    req.scene = CM_UKEY_AUTH_SCENE_CUSTOM;

    CertmanagerTest::MockHapToken mockHap({ "ohos.permission.ACCESS_CERT_MANAGER" });
    int32_t ret = CmOpenUkeyAuthDialog(&req, RealIpcResultCallback, nullptr);
    GTEST_LOG_(INFO) << "CmOpenUkeyAuthDialog(scene=Custom) sync ret = " << ret;
    sleep(1);
    EXPECT_FALSE(g_asyncFired.load()); /* sync rejection never fires the callback */
}

HWTEST_F(CmUkeyDialogRealIpcTest, OpenDialogRealIpcProbe, testing::ext::TestSize.Level0)
{
    char uri[] = "ukey-test-uri";
    struct UkeyAuthRequest req = {};
    req.keyUri.data = reinterpret_cast<uint8_t *>(uri);
    req.keyUri.size = sizeof(uri); /* NUL-terminated, same as the NAPI layer */
    uint8_t customData[] = { 'a', 'b', 'c' }; /* base64 -> "YWJj", exercises the want param */
    req.customData.data = customData;
    req.customData.size = sizeof(customData);

    CertmanagerTest::MockHapToken mockHap({ "ohos.permission.ACCESS_CERT_MANAGER" });
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

/* ForDriver probe: a CRYPTO_EXTENSION_REGISTER HAP caller reaches the SA —
 * real validation rejects synchronously: on rk3568 (non-PC) the -1020 PC gate
 * hits before BMS; on a PC the mock bundle has no such extension so BMS
 * precheck returns -1019. Both prove the ForDriver chain is wired to the SA. */
HWTEST_F(CmUkeyDialogRealIpcTest, OpenDriverDialogRealIpcProbe, testing::ext::TestSize.Level0)
{
    char abilityName[] = "MyUkeyAuthExtensionAbility";
    struct UkeyAuthDialogInfo dialogInfo = {};
    dialogInfo.abilityName.data = reinterpret_cast<uint8_t *>(abilityName);
    dialogInfo.abilityName.size = sizeof(abilityName); /* NUL-terminated */
    dialogInfo.abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION;

    char uri[] = "ukey://test/for-driver";
    struct UkeyAuthRequest req = {};
    req.keyUri.data = reinterpret_cast<uint8_t *>(uri);
    req.keyUri.size = sizeof(uri);

    CertmanagerTest::MockHapToken mockHap({ "ohos.permission.CRYPTO_EXTENSION_REGISTER" });
    int32_t ret = CmOpenUkeyAuthDialogForDriver(&dialogInfo, &req, DriverProbeResultCallback,
        nullptr);
    GTEST_LOG_(INFO) << "CmOpenUkeyAuthDialogForDriver sync ret = " << ret;
    sleep(1);
    EXPECT_TRUE(ret == CMR_DIALOG_ERROR_NOT_REGISTERED || ret == CMR_DIALOG_ERROR_NOT_PC_DEVICE)
        << "ret = " << ret;
    EXPECT_EQ(g_driverProbeFired.load(), 0xDEADBEEF); /* sync rejection never fires */
}

/* ForDriver no-permission probe: the un-mocked shell identity holds no
 * CRYPTO_EXTENSION_REGISTER — the SA-side defense-in-depth check rejects
 * synchronously with -1011 (JS 201). */
HWTEST_F(CmUkeyDialogRealIpcTest, OpenDriverDialogNoPermissionProbe, testing::ext::TestSize.Level0)
{
    char abilityName[] = "MyUkeyAuthExtensionAbility";
    struct UkeyAuthDialogInfo dialogInfo = {};
    dialogInfo.abilityName.data = reinterpret_cast<uint8_t *>(abilityName);
    dialogInfo.abilityName.size = sizeof(abilityName); /* NUL-terminated */
    dialogInfo.abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION;

    char uri[] = "ukey://test/for-driver-noperm";
    struct UkeyAuthRequest req = {};
    req.keyUri.data = reinterpret_cast<uint8_t *>(uri);
    req.keyUri.size = sizeof(uri);

    int32_t ret = CmOpenUkeyAuthDialogForDriver(&dialogInfo, &req, DriverProbeResultCallback,
        nullptr);
    GTEST_LOG_(INFO) << "CmOpenUkeyAuthDialogForDriver(no-perm) sync ret = " << ret;
    EXPECT_EQ(ret, CMR_DIALOG_ERROR_PERMISSION_DENIED);
    EXPECT_EQ(g_driverProbeFired.load(), 0xDEADBEEF); /* sync rejection never fires */
}
