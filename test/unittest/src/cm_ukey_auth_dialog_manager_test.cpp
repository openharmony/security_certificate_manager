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

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <set>

#include "string_ex.h"

#include "cm_system_dialog_connection.h"
#include "cm_ukey_auth_dialog_manager.h"

namespace OHOS::Security::CertManager {
class FakeLauncher : public SystemDialogLauncher {
public:
    int32_t Connect(const sptr<IAbilityConnection> &conn) override
    {
        connectCount_++;
        conn_ = static_cast<CmSystemDialogConnection *>(conn.GetRefPtr()); /* always this type on the manager side */
        return connectRet_;
    }
    void Disconnect(const sptr<IAbilityConnection> &conn) override
    {
        disconnectCount_++;
    }
    int32_t connectRet_ = 0; int connectCount_ = 0; int disconnectCount_ = 0;
    sptr<CmSystemDialogConnection> conn_; // needed to access paramsJson for verification
};

/* IRemoteStub requires a broker interface with a valid descriptor; a minimal
 * local broker keeps the fake's public surface unchanged. */
class CmTestBroker : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"cm.test.dialog");
};

class FakeClientCallback : public IRemoteStub<CmTestBroker> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override
    {
        if (code == CM_UKEY_DIALOG_CALLBACK_CMD) { lastCode_ = data.ReadInt32(); called_++; }
        return 0;
    }
    int32_t lastCode_ = -1; int called_ = 0;
};

class CmUkeyAuthDialogManagerTest : public testing::Test {
public:
    void SetUp() override
    {
        manager_ = &CmUkeyAuthDialogManager::GetInstance();
        launcher_ = std::make_shared<FakeLauncher>();
        querier_ = [this](const struct CmBlob *keyUri, std::string &bundle,
                      std::string &ability, uint32_t &type) -> int32_t {
            bundle = driverBundle_; ability = driverAbility_; type = abilityType_; return querierRet_;
        };
        manager_->SetLauncher(launcher_);
        manager_->SetAbilityQuerier(querier_);
        manager_->SetPcChecker([this]() { return pcMode_; }); /* D15 seam */
        manager_->SetTimeoutRangeForTest(2, 3, 5, 100); // min/default/max total (s), 100ms grace
        manager_->SetKeepAliveIntervalForTest(50); // fast keep-alive for F1 tests
        manager_->SetUnloadRenewal([this]() { renewalCount_++; });
        manager_->SetTimerPostFailForTest(false); // reset F8 fault injection
        driverChecker_ = [this](const std::string &, const std::string &, int32_t) -> bool {
            return bmsOk_;
        };
        manager_->SetDriverAbilityChecker(driverChecker_);
    }
    CmUkeyAuthDialogManager *manager_;
    std::shared_ptr<FakeLauncher> launcher_;
    AbilityQuerier querier_;
    std::string driverBundle_ = "com.example.ukeydrv";
    std::string driverAbility_ = "DrvUIExtAbility";
    int32_t querierRet_ = 0;
    uint32_t abilityType_ = CM_UKEY_ABILITY_TYPE_UIEXTENSION;
    int renewalCount_ = 0; // keep-alive renewal hook fire count (F1)
    bool pcMode_ = true; // pc checker injection (D15): default allows UIExtension path
    DriverAbilityChecker driverChecker_;
    bool bmsOk_ = true;
    std::string callerBundle_ = "com.example.ukeydriver";
    std::string driverAbilityName_ = "MyUkeyAuthExtensionAbility";
    /* convenience wrapper for the OpenDialog signature (customData optional) */
    int32_t Open(uint32_t timeout = 0, const struct CmBlob *customData = nullptr)
    {
        return manager_->OpenDialog(&keyUri_, 100, timeout, customData, client_);
    }
    /* convenience wrapper for OpenDriverDialog (spec v4 §4.1 ForDriver routing) */
    int32_t OpenDriver(uint32_t abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION, uint32_t timeout = 0,
        const struct CmBlob *customData = nullptr)
    {
        UkeyDriverDialogRequest req;
        req.abilityName = { static_cast<uint32_t>(driverAbilityName_.size() + 1),
            reinterpret_cast<uint8_t *>(const_cast<char *>(driverAbilityName_.c_str())) };
        req.abilityType = abilityType;
        req.keyUri = keyUri_;
        req.callerUid = 100;
        req.callerBundleName = callerBundle_;
        req.userId = 100;
        req.timeoutSec = timeout;
        if (customData != nullptr) {
            req.customData = *customData;
        }
        req.clientCallback = client_;
        return manager_->OpenDriverDialog(req);
    }
    sptr<FakeClientCallback> client_ = sptr<FakeClientCallback>(new FakeClientCallback());
    struct CmBlob keyUri_ = { 8, reinterpret_cast<uint8_t *>(const_cast<char *>("testuri")) };
};

/* Routing matrix (spec v4 §4.1/D22): query failure = not registered ->
 * sync reject -1019 (29700003); the SA no longer launches the system
 * default dialog */
HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDialogAbilityQueryFail, testing::ext::TestSize.Level0)
{
    querierRet_ = -51; // HUKS query error -> treated as not-registered -> sync reject
    ASSERT_EQ(Open(), CMR_DIALOG_ERROR_NOT_REGISTERED);
    EXPECT_EQ(launcher_->connectCount_, 0);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDialogWrongAbilityType, testing::ext::TestSize.Level0)
{
    /* spec v4: UIAbility dialogs are unsupported - as soon as the query sees one, reject -1021 (29700003) */
    abilityType_ = CM_UKEY_ABILITY_TYPE_UIABILITY;
    ASSERT_EQ(Open(), CMR_DIALOG_ERROR_UIABILITY_NOT_SUPPORTED);
    ASSERT_EQ(Open(), CMR_DIALOG_ERROR_UIABILITY_NOT_SUPPORTED);
    EXPECT_EQ(launcher_->connectCount_, 0); /* no connection established */
    EXPECT_EQ(manager_->GetRequestIdForTest(), ""); /* single-flight not occupied by any session */
}

HWTEST_F(CmUkeyAuthDialogManagerTest, PcGateBlocksUiExtensionWhenNotPc, testing::ext::TestSize.Level0)
{
    /* rule 6 (spec D10/D15): non-PC and non-PC mode -> -1020 (fail-closed, including a default checker) */
    pcMode_ = false;
    ASSERT_EQ(Open(), CMR_DIALOG_ERROR_NOT_PC_DEVICE);
    EXPECT_EQ(launcher_->connectCount_, 0);
    pcMode_ = true;
    ASSERT_EQ(Open(), CM_SUCCESS);
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup
}

HWTEST_F(CmUkeyAuthDialogManagerTest, CustomDataValidated, testing::ext::TestSize.Level0)
{
    uint8_t big[CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE + 1] = { 0 };
    struct CmBlob tooBig = { sizeof(big), big };
    ASSERT_EQ(Open(0, &tooBig), CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED);
    EXPECT_EQ(launcher_->connectCount_, 0);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, ParamsJsonCarriesCustomData, testing::ext::TestSize.Level0)
{
    /* UIExtension path: customData is written base64-encoded (spec §6.2/D18); since v4 the JSON has no scene */
    uint8_t data[3] = { 'a', 'b', 'c' };
    struct CmBlob customData = { 3, data };
    ASSERT_EQ(Open(0, &customData), CM_SUCCESS);
    auto conn = launcher_->conn_;
    ASSERT_NE(conn, nullptr);
    const std::string &params = conn->GetParamsJson();
    EXPECT_NE(params.find("\"customData\":\"YWJj\""), std::string::npos); /* base64("abc") */
    EXPECT_EQ(params.find("\"scene\""), std::string::npos); /* no scene in v4 */
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup
}

HWTEST_F(CmUkeyAuthDialogManagerTest, Base64Vectors, testing::ext::TestSize.Level0)
{
    /* RFC 4648 test vectors + boundaries (spec §8.4) */
    struct { const char *in; size_t len; const char *out; } vectors[] = {
        { "", 0, "" },
        { "f", 1, "Zg==" },
        { "fo", 2, "Zm8=" },
        { "foo", 3, "Zm9v" },
        { "foob", 4, "Zm9vYg==" },
        { "fooba", 5, "Zm9vYmE=" },
        { "foobar", 6, "Zm9vYmFy" },
    };
    for (auto &v : vectors) {
        EXPECT_EQ(CmBase64Encode(reinterpret_cast<const uint8_t *>(v.in), v.len), v.out);
    }
    uint8_t ff[3] = { 0xFF, 0xFF, 0xFF };
    EXPECT_EQ(CmBase64Encode(ff, sizeof(ff)), "////");
}

HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDialogConnectFail, testing::ext::TestSize.Level0)
{
    launcher_->connectRet_ = 29160333; // arbitrary aafwk error
    ASSERT_EQ(Open(0), CMR_DIALOG_ERROR_INTERNAL);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, SingleFlightRejected, testing::ext::TestSize.Level0)
{
    ASSERT_EQ(Open(0), CM_SUCCESS);
    ASSERT_EQ(Open(0), CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS);
    /* cleanup: finish the pending session explicitly, so the 50ms periodic
     * keep-alive task cannot fire a dangling renewalCount_++ in the window
     * between fixture teardown and the next case's SetUp (SetLauncher aborts
     * the session) */
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0);
}

/* requestId must come from the CSPRNG: distinct across sessions (a testable
 * proxy for unpredictability) + 32-char hex format */
HWTEST_F(CmUkeyAuthDialogManagerTest, RequestIdUniquePerSession, testing::ext::TestSize.Level0)
{
    const int sessions = 16;
    std::set<std::string> ids;
    for (int i = 0; i < sessions; i++) {
        ASSERT_EQ(Open(0), CM_SUCCESS);
        std::string reqId = manager_->GetRequestIdForTest();
        EXPECT_EQ(reqId.size(), 32u); /* 16 bytes hex */
        for (char c : reqId) {
            EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
        }
        ids.insert(reqId);
        manager_->OnReport(reqId, driverBundle_, 0); /* cleanup, single-flight */
    }
    EXPECT_EQ(ids.size(), static_cast<size_t>(sessions)); /* no duplicates */
}

HWTEST_F(CmUkeyAuthDialogManagerTest, NormalReportDeliversCode, testing::ext::TestSize.Level0)
{
    ASSERT_EQ(Open(0), CM_SUCCESS);
    // Retrieve the requestId: the manager must expose a test retrieval interface GetRequestIdForTest()
    std::string reqId = manager_->GetRequestIdForTest();
    EXPECT_EQ(reqId.size(), 32u); // 16 bytes hex
    ASSERT_EQ(manager_->OnReport(reqId, "com.example.ukeydrv", 0), CM_SUCCESS);
    EXPECT_EQ(client_->called_, 1);
    EXPECT_EQ(client_->lastCode_, 0);
    EXPECT_EQ(launcher_->disconnectCount_, 1);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, ReportWrongBundleRejected, testing::ext::TestSize.Level0)
{
    Open(0);
    ASSERT_EQ(manager_->OnReport(manager_->GetRequestIdForTest(), "com.example.other", 0),
        CMR_DIALOG_ERROR_INTERNAL);
    EXPECT_EQ(client_->called_, 0); // session still pending
    manager_->OnReport(manager_->GetRequestIdForTest(), "com.example.ukeydrv", 29700002); // cleanup
}

HWTEST_F(CmUkeyAuthDialogManagerTest, ReportUnknownCodeFolded, testing::ext::TestSize.Level0)
{
    Open(0);
    ASSERT_EQ(manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 12345), CM_SUCCESS);
    EXPECT_EQ(client_->lastCode_, CMR_DIALOG_ERROR_INTERNAL); // folded to 29700001
}

HWTEST_F(CmUkeyAuthDialogManagerTest, DisconnectThenGraceReport, testing::ext::TestSize.Level0)
{
    /* Widen this case's grace window (500ms): we assert "report within the
     * grace period succeeds", and the default 100ms grace between two
     * adjacent manager calls may not be enough on a loaded machine */
    manager_->SetTimeoutRangeForTest(2, 3, 5, 500);
    ASSERT_EQ(Open(0), CM_SUCCESS);
    std::string reqId = manager_->GetRequestIdForTest();
    manager_->OnDialogDisconnected(reqId); // enter grace
    ASSERT_EQ(manager_->OnReport(reqId, driverBundle_, 0), CM_SUCCESS); // within grace
    EXPECT_EQ(client_->lastCode_, 0);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, GraceTimeoutMeansCancel, testing::ext::TestSize.Level0)
{
    Open(0);
    manager_->OnDialogDisconnected(manager_->GetRequestIdForTest());
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); // > 100ms grace
    EXPECT_EQ(client_->called_, 1);
    EXPECT_EQ(client_->lastCode_, CMR_DIALOG_ERROR_OPERATION_CANCELS);
    EXPECT_EQ(launcher_->disconnectCount_, 1);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, TotalTimeoutMeansReportTimeout, testing::ext::TestSize.Level0)
{
    Open(0);
    std::this_thread::sleep_for(std::chrono::milliseconds(3500)); // > 3s total, with margin
    EXPECT_EQ(client_->called_, 1);
    EXPECT_EQ(client_->lastCode_, CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT);
    EXPECT_EQ(launcher_->disconnectCount_, 1);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, ParamsJsonCarriesTimeout, testing::ext::TestSize.Level0)
{
    /* the normalized session timeout must reach the driver dialog via the
     * parameters json (spec §6.2, seconds): default -> preconfigured test value,
     * explicit value -> that value, over-max -> clamped to the server max */
    Open(0); // default -> 3s (preconfigured)
    auto conn = launcher_->conn_;
    ASSERT_NE(conn, nullptr);
    EXPECT_NE(conn->GetParamsJson().find("\"timeout\":3"), std::string::npos);
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup

    Open(4); // explicit 4s
    conn = launcher_->conn_;
    ASSERT_NE(conn, nullptr);
    EXPECT_NE(conn->GetParamsJson().find("\"timeout\":4"), std::string::npos);
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup

    Open(999999999); // over configured max -> clamp 5
    conn = launcher_->conn_;
    ASSERT_NE(conn, nullptr);
    EXPECT_NE(conn->GetParamsJson().find("\"timeout\":5"), std::string::npos);
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup

    Open(1); // below configured min -> clamp 2
    conn = launcher_->conn_;
    ASSERT_NE(conn, nullptr);
    EXPECT_NE(conn->GetParamsJson().find("\"timeout\":2"), std::string::npos);
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup
}

HWTEST_F(CmUkeyAuthDialogManagerTest, CustomTimeoutTakesEffect, testing::ext::TestSize.Level0)
{
    /* explicit short timeout overrides the preconfigured test timeout */
    Open(2); // 2s < default 3s
    std::this_thread::sleep_for(std::chrono::milliseconds(2500)); // > 2s, with margin
    EXPECT_EQ(client_->called_, 1);
    EXPECT_EQ(client_->lastCode_, CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, TimeoutClampedToMax, testing::ext::TestSize.Level0)
{
    /* timeout above the configured max is clamped: a clamped request must NOT
     * fire within the short window */
    Open(999999999); // > max -> clamp
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_EQ(client_->called_, 0); // still waiting (clamped to 5s), not fired
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup
    EXPECT_EQ(client_->lastCode_, 0);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, LateReportAfterDoneIgnored, testing::ext::TestSize.Level0)
{
    Open(0);
    std::string reqId = manager_->GetRequestIdForTest();
    manager_->OnReport(reqId, driverBundle_, 0);
    ASSERT_EQ(manager_->OnReport(reqId, driverBundle_, 0), CMR_DIALOG_ERROR_INTERNAL);
    EXPECT_EQ(client_->called_, 1); // exactly once
}

/* Fake system dialog service stub recording the START_DIALOG parcel
 * (key/value pairs of the ON_ABILITY_CONNECT_DONE command). */
class FakeDialogService : public IRemoteStub<CmTestBroker> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override
    {
        if (code == IAbilityConnection::ON_ABILITY_CONNECT_DONE) {
            int32_t size = data.ReadInt32();
            for (int32_t i = 0; i < size; ++i) {
                keys_.push_back(Str16ToStr8(data.ReadString16()));
                values_.push_back(Str16ToStr8(data.ReadString16()));
            }
        }
        return 0;
    }
    std::vector<std::string> keys_;
    std::vector<std::string> values_;
};

HWTEST_F(CmUkeyAuthDialogManagerTest, ConnectionParcelFormat, testing::ext::TestSize.Level0)
{
    sptr<FakeDialogService> svc = sptr<FakeDialogService>(new FakeDialogService());
    CmSystemDialogConnection conn("req123", "com.example.ukeydrv", "DrvUIExtAbility",
        R"({"keyUri":"u1","requestId":"req123","timeout":600})");
    conn.OnAbilityConnectDone(AppExecFwk::ElementName(), svc, 0);
    ASSERT_EQ(svc->keys_.size(), 3u);
    EXPECT_EQ(svc->keys_[0], "bundleName");
    EXPECT_EQ(svc->values_[0], "com.example.ukeydrv");
    EXPECT_EQ(svc->keys_[1], "abilityName");
    EXPECT_EQ(svc->values_[1], "DrvUIExtAbility");
    EXPECT_EQ(svc->keys_[2], "parameters");
    EXPECT_EQ(svc->values_[2], R"({"keyUri":"u1","requestId":"req123","timeout":600})");
}

/* ---- F1: SA keep-alive during WAITING_REPORT ---- */

HWTEST_F(CmUkeyAuthDialogManagerTest, KeepAliveFiresPeriodicallyAndCancelsOnFinish,
    testing::ext::TestSize.Level0)
{
    ASSERT_EQ(Open(0), CM_SUCCESS);
    std::string reqId = manager_->GetRequestIdForTest();
    /* 250ms accommodates >=2 firings at the 50ms interval (including the
     * startup jitter of the runner thread's first creation) */
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    EXPECT_GE(renewalCount_, 2); // armed on success + periodic re-arm
    ASSERT_EQ(manager_->OnReport(reqId, driverBundle_, 0), CM_SUCCESS);
    int afterFinish = renewalCount_;
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    EXPECT_EQ(renewalCount_, afterFinish); // cancelled on finish
}

HWTEST_F(CmUkeyAuthDialogManagerTest, KeepAliveNotArmedOnSyncFailure, testing::ext::TestSize.Level0)
{
    querierRet_ = -51; // not registered -> reject before session (spec v4 D22)
    ASSERT_EQ(Open(), CMR_DIALOG_ERROR_NOT_REGISTERED);
    querierRet_ = 0;
    abilityType_ = CM_UKEY_ABILITY_TYPE_UIABILITY; // UIAbility rejected before session
    ASSERT_EQ(Open(), CMR_DIALOG_ERROR_UIABILITY_NOT_SUPPORTED);
    abilityType_ = CM_UKEY_ABILITY_TYPE_UIEXTENSION;
    launcher_->connectRet_ = 29160333; // connect fail -> reject before session
    ASSERT_EQ(Open(), CMR_DIALOG_ERROR_INTERNAL);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    EXPECT_EQ(renewalCount_, 0);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, KeepAliveCancelledOnAbort, testing::ext::TestSize.Level0)
{
    ASSERT_EQ(Open(0), CM_SUCCESS);
    manager_->SetTimeoutRangeForTest(2, 3, 5, 100); // reconfiguration aborts the active session
    /* Assert "no further firing after the abort" rather than "the abort
     * completes before the first firing": the latter depends on the gap
     * between two adjacent statements being < 50ms, which gets flaky on a
     * loaded machine */
    int afterAbort = renewalCount_;
    std::this_thread::sleep_for(std::chrono::milliseconds(150)); // > 50ms interval
    EXPECT_EQ(renewalCount_, afterAbort); // no further keep-alive after the abort
}

/* ---- F2: client death monitoring ---- */

HWTEST_F(CmUkeyAuthDialogManagerTest, ClientDeathAbortsSessionWithoutResult,
    testing::ext::TestSize.Level0)
{
    ASSERT_EQ(Open(0), CM_SUCCESS);
    std::string reqId = manager_->GetRequestIdForTest();
    manager_->OnClientDied(reqId);
    EXPECT_EQ(manager_->GetRequestIdForTest(), ""); // session cleared
    EXPECT_EQ(client_->called_, 0); // no result delivered to the dead client
    EXPECT_EQ(launcher_->disconnectCount_, 1); // dialog connection torn down
    int afterDeath = renewalCount_;
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    EXPECT_EQ(renewalCount_, afterDeath); // keep-alive cancelled on abort
    EXPECT_EQ(Open(0), CM_SUCCESS); // single-flight free
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup
}

HWTEST_F(CmUkeyAuthDialogManagerTest, ClientDeathUnknownRequestIdNoop, testing::ext::TestSize.Level0)
{
    ASSERT_EQ(Open(0), CM_SUCCESS);
    std::string reqId = manager_->GetRequestIdForTest();
    manager_->OnClientDied(reqId + "ff"); // unknown request id
    manager_->OnClientDied("00000000000000000000000000000000"); // expired request id
    EXPECT_EQ(manager_->GetRequestIdForTest(), reqId); // session untouched
    EXPECT_EQ(client_->called_, 0);
    EXPECT_EQ(launcher_->disconnectCount_, 0);
    manager_->OnReport(reqId, driverBundle_, 0); // cleanup
}

/* ---- F8: timer PostTask failure hardening ---- */

HWTEST_F(CmUkeyAuthDialogManagerTest, TotalTimeoutPostFailRejectsOpen, testing::ext::TestSize.Level0)
{
    manager_->SetTimerPostFailForTest(true);
    ASSERT_EQ(Open(0), CMR_DIALOG_ERROR_INTERNAL);
    EXPECT_EQ(manager_->GetRequestIdForTest(), ""); // session not stored
    EXPECT_EQ(client_->called_, 0); // no result delivered
    EXPECT_EQ(launcher_->disconnectCount_, 1); // established connection rolled back
    EXPECT_EQ(renewalCount_, 0); // keep-alive not armed
    manager_->SetTimerPostFailForTest(false);
    EXPECT_EQ(Open(0), CM_SUCCESS); // single-flight free
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup
}

/* ---- OpenDriverDialog (spec v4 §4.1 ForDriver routing, D23) ---- */
HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDriverDialogWrongAbilityTypeRejected, testing::ext::TestSize.Level0)
{
    /* SA-side abilityType defense: only UIExtension is admitted, everything else -1014 (29700006) */
    ASSERT_EQ(OpenDriver(CM_UKEY_ABILITY_TYPE_UIABILITY), CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED);
    ASSERT_EQ(OpenDriver(2), CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED);
    EXPECT_EQ(launcher_->connectCount_, 0);
    EXPECT_EQ(manager_->GetRequestIdForTest(), "");
}

HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDriverDialogBmsCheckFails, testing::ext::TestSize.Level0)
{
    /* BMS precheck failure (ability missing / not a UKEY_AUTH extension) -> -1019 (29700003, D23) */
    bmsOk_ = false;
    ASSERT_EQ(OpenDriver(), CMR_DIALOG_ERROR_NOT_REGISTERED);
    EXPECT_EQ(launcher_->connectCount_, 0);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDriverDialogAbilityNameBoundary, testing::ext::TestSize.Level0)
{
    /* A 256-char legal name (blob 257 with NUL) passes the length check and
     * reaches the BMS check (spec v4.1 D24 boundary) */
    std::string longName(256, 'a');
    UkeyDriverDialogRequest longReq;
    longReq.abilityName = { static_cast<uint32_t>(longName.size() + 1),
        reinterpret_cast<uint8_t *>(const_cast<char *>(longName.c_str())) };
    longReq.abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION;
    longReq.keyUri = keyUri_;
    longReq.callerBundleName = callerBundle_;
    longReq.clientCallback = client_;
    ASSERT_EQ(manager_->OpenDriverDialog(longReq), CM_SUCCESS);
    manager_->OnReport(manager_->GetRequestIdForTest(), callerBundle_, 0); // cleanup
    /* A NUL-only name is an empty string after stripping -> rejected as an argument */
    const char *nulName = "";
    UkeyDriverDialogRequest nulReq;
    nulReq.abilityName = { 1, reinterpret_cast<uint8_t *>(const_cast<char *>(nulName)) };
    nulReq.abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION;
    nulReq.keyUri = keyUri_;
    nulReq.callerBundleName = callerBundle_;
    nulReq.clientCallback = client_;
    ASSERT_EQ(manager_->OpenDriverDialog(nulReq), CMR_ERROR_INVALID_ARGUMENT);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDriverDialogPcGate, testing::ext::TestSize.Level0)
{
    /* ForDriver has no fallback: non-PC -> -1020 (29700005, D25 v2) */
    pcMode_ = false;
    ASSERT_EQ(OpenDriver(), CMR_DIALOG_ERROR_NOT_PC_DEVICE);
    EXPECT_EQ(launcher_->connectCount_, 0);
    pcMode_ = true;
    ASSERT_EQ(OpenDriver(), CM_SUCCESS);
    manager_->OnReport(manager_->GetRequestIdForTest(), callerBundle_, 0); // cleanup
}

HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDriverDialogParamsAndOwner, testing::ext::TestSize.Level0)
{
    /* Success path: owner = caller bundle (IPC token source); params JSON
     * has no scene and the target = callerBundle/driverAbilityName
     * (spec §6.2/D26) */
    uint8_t data[3] = { 'a', 'b', 'c' };
    struct CmBlob customData = { 3, data };
    ASSERT_EQ(OpenDriver(CM_UKEY_ABILITY_TYPE_UIEXTENSION, 0, &customData), CM_SUCCESS);
    ASSERT_EQ(launcher_->connectCount_, 1);
    auto conn = launcher_->conn_;
    ASSERT_NE(conn, nullptr);
    const std::string &params = conn->GetParamsJson();
    EXPECT_NE(params.find("\"keyUri\":\"testuri\""), std::string::npos);
    EXPECT_NE(params.find("\"appUid\":100"), std::string::npos);
    EXPECT_NE(params.find("\"action\":\"UkeyPINAuth\""), std::string::npos);
    EXPECT_NE(params.find("\"ability.want.params.uiExtensionType\":\"ukeyAuth\""), std::string::npos);
    EXPECT_NE(params.find("\"customData\":\"YWJj\""), std::string::npos);
    EXPECT_EQ(params.find("\"scene\""), std::string::npos); /* no scene in v4 */
    /* The reporting responsible party = caller bundle; reports from others are rejected */
    std::string reqId = manager_->GetRequestIdForTest();
    ASSERT_EQ(manager_->OnReport(reqId, driverBundle_, 0), CMR_DIALOG_ERROR_INTERNAL);
    ASSERT_EQ(manager_->OnReport(reqId, callerBundle_, 0), CM_SUCCESS);
    EXPECT_EQ(client_->lastCode_, 0);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDriverDialogSharesSingleFlight, testing::ext::TestSize.Level0)
{
    /* The two interfaces share single-flight (D26): after OpenDialog takes
     * the slot, ForDriver is rejected with -1018, and vice versa */
    ASSERT_EQ(Open(), CM_SUCCESS);
    ASSERT_EQ(OpenDriver(), CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS);
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup
    ASSERT_EQ(OpenDriver(), CM_SUCCESS);
    ASSERT_EQ(Open(), CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS);
    manager_->OnReport(manager_->GetRequestIdForTest(), callerBundle_, 0); // cleanup
}

HWTEST_F(CmUkeyAuthDialogManagerTest, GraceTimerPostFailFinishesSession, testing::ext::TestSize.Level0)
{
    ASSERT_EQ(Open(0), CM_SUCCESS);
    std::string reqId = manager_->GetRequestIdForTest();
    manager_->SetTimerPostFailForTest(true);
    manager_->OnDialogDisconnected(reqId); // grace arm fails -> finish as cancel
    EXPECT_EQ(client_->called_, 1);
    EXPECT_EQ(client_->lastCode_, CMR_DIALOG_ERROR_OPERATION_CANCELS); // no hanging session
    EXPECT_EQ(manager_->GetRequestIdForTest(), "");
    EXPECT_EQ(launcher_->disconnectCount_, 1);
    manager_->SetTimerPostFailForTest(false);
}
}
