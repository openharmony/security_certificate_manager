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

#include "string_ex.h"

#include "cm_system_dialog_connection.h"
#include "cm_ukey_auth_dialog_manager.h"

namespace OHOS::Security::CertManager {
class FakeLauncher : public SystemDialogLauncher {
public:
    int32_t Connect(const sptr<IAbilityConnection> &conn) override
    {
        connectCount_++;
        conn_ = static_cast<CmSystemDialogConnection *>(conn.GetRefPtr()); /* manager 侧必为该类型 */
        return connectRet_;
    }
    void Disconnect(const sptr<IAbilityConnection> &conn) override
    {
        disconnectCount_++;
    }
    int32_t connectRet_ = 0; int connectCount_ = 0; int disconnectCount_ = 0;
    sptr<CmSystemDialogConnection> conn_; // 需要访问 paramsJson 验证
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
        manager_->SetTimeoutForTest(200, 100); // 200ms total, 100ms grace
        manager_->SetKeepAliveIntervalForTest(50); // fast keep-alive for F1 tests
        manager_->SetUnloadRenewal([this]() { renewalCount_++; });
        manager_->SetTimerPostFailForTest(false); // reset F8 fault injection
    }
    CmUkeyAuthDialogManager *manager_;
    std::shared_ptr<FakeLauncher> launcher_;
    AbilityQuerier querier_;
    std::string driverBundle_ = "com.example.ukeydrv";
    std::string driverAbility_ = "DrvUIExtAbility";
    int32_t querierRet_ = 0;
    uint32_t abilityType_ = CM_UKEY_ABILITY_TYPE_UIEXTENSION;
    int renewalCount_ = 0; // keep-alive renewal hook fire count (F1)
    sptr<FakeClientCallback> client_ = sptr<FakeClientCallback>(new FakeClientCallback());
    struct CmBlob keyUri_ = { 8, reinterpret_cast<uint8_t *>(const_cast<char *>("testuri")) };
};

HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDialogAbilityQueryFail, testing::ext::TestSize.Level0)
{
    querierRet_ = -51; // HUKS query error -> treated as not-registered
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, 0, client_), CMR_DIALOG_ERROR_UKEY_ABILITY_NOT_SUPPORTED);
    EXPECT_EQ(launcher_->connectCount_, 0);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDialogWrongAbilityType, testing::ext::TestSize.Level0)
{
    abilityType_ = CM_UKEY_ABILITY_TYPE_UIABILITY; // registered as UIAbility, not UIExtensionAbility
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, 0, client_), CMR_DIALOG_ERROR_UKEY_ABILITY_NOT_SUPPORTED);
    EXPECT_EQ(launcher_->connectCount_, 0);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDialogConnectFail, testing::ext::TestSize.Level0)
{
    launcher_->connectRet_ = 29160333; // arbitrary aafwk error
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, 0, client_), CMR_DIALOG_ERROR_INTERNAL);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, SingleFlightRejected, testing::ext::TestSize.Level0)
{
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, 0, client_), CM_SUCCESS);
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, 0, client_), CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, NormalReportDeliversCode, testing::ext::TestSize.Level0)
{
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, 0, client_), CM_SUCCESS);
    // 取回 requestId：manager 需提供测试取回接口 GetRequestIdForTest()
    std::string reqId = manager_->GetRequestIdForTest();
    EXPECT_EQ(reqId.size(), 32u); // 16 bytes hex
    ASSERT_EQ(manager_->OnReport(reqId, "com.example.ukeydrv", 0), CM_SUCCESS);
    EXPECT_EQ(client_->called_, 1);
    EXPECT_EQ(client_->lastCode_, 0);
    EXPECT_EQ(launcher_->disconnectCount_, 1);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, ReportWrongBundleRejected, testing::ext::TestSize.Level0)
{
    manager_->OpenDialog(&keyUri_, 100, 0, client_);
    ASSERT_EQ(manager_->OnReport(manager_->GetRequestIdForTest(), "com.example.other", 0),
        CMR_DIALOG_ERROR_INTERNAL);
    EXPECT_EQ(client_->called_, 0); // session still pending
    manager_->OnReport(manager_->GetRequestIdForTest(), "com.example.ukeydrv", 29700002); // cleanup
}

HWTEST_F(CmUkeyAuthDialogManagerTest, ReportUnknownCodeFolded, testing::ext::TestSize.Level0)
{
    manager_->OpenDialog(&keyUri_, 100, 0, client_);
    ASSERT_EQ(manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 12345), CM_SUCCESS);
    EXPECT_EQ(client_->lastCode_, CMR_DIALOG_ERROR_INTERNAL); // folded to 29700001
}

HWTEST_F(CmUkeyAuthDialogManagerTest, DisconnectThenGraceReport, testing::ext::TestSize.Level0)
{
    manager_->OpenDialog(&keyUri_, 100, 0, client_);
    std::string reqId = manager_->GetRequestIdForTest();
    manager_->OnDialogDisconnected(reqId); // enter grace
    ASSERT_EQ(manager_->OnReport(reqId, driverBundle_, 0), CM_SUCCESS); // within 100ms
    EXPECT_EQ(client_->lastCode_, 0);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, GraceTimeoutMeansCancel, testing::ext::TestSize.Level0)
{
    manager_->OpenDialog(&keyUri_, 100, 0, client_);
    manager_->OnDialogDisconnected(manager_->GetRequestIdForTest());
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); // > 100ms grace
    EXPECT_EQ(client_->called_, 1);
    EXPECT_EQ(client_->lastCode_, CMR_DIALOG_ERROR_OPERATION_CANCELS);
    EXPECT_EQ(launcher_->disconnectCount_, 1);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, TotalTimeoutMeansReportTimeout, testing::ext::TestSize.Level0)
{
    manager_->OpenDialog(&keyUri_, 100, 0, client_);
    std::this_thread::sleep_for(std::chrono::milliseconds(400)); // > 200ms total
    EXPECT_EQ(client_->called_, 1);
    EXPECT_EQ(client_->lastCode_, CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT);
    EXPECT_EQ(launcher_->disconnectCount_, 1);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, ParamsJsonCarriesTimeout, testing::ext::TestSize.Level0)
{
    /* the normalized session timeout must reach the driver dialog via the
     * parameters json (spec §6.2): default -> preconfigured test value,
     * explicit value -> that value, over-max -> clamped to the server max */
    manager_->OpenDialog(&keyUri_, 100, 0, client_); // default -> 200ms (preconfigured)
    auto conn = launcher_->conn_;
    ASSERT_NE(conn, nullptr);
    EXPECT_NE(conn->GetParamsJson().find("\"timeout\":200"), std::string::npos);
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup

    manager_->OpenDialog(&keyUri_, 100, 150, client_); // explicit 150ms
    conn = launcher_->conn_;
    ASSERT_NE(conn, nullptr);
    EXPECT_NE(conn->GetParamsJson().find("\"timeout\":150"), std::string::npos);
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup

    manager_->OpenDialog(&keyUri_, 100, 999999999, client_); // over max -> clamp 600000
    conn = launcher_->conn_;
    ASSERT_NE(conn, nullptr);
    EXPECT_NE(conn->GetParamsJson().find("\"timeout\":600000"), std::string::npos);
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup
}

HWTEST_F(CmUkeyAuthDialogManagerTest, CustomTimeoutTakesEffect, testing::ext::TestSize.Level0)
{
    /* explicit short timeout overrides the preconfigured test timeout */
    manager_->OpenDialog(&keyUri_, 100, 150, client_); // 150ms
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    EXPECT_EQ(client_->called_, 1);
    EXPECT_EQ(client_->lastCode_, CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, TimeoutClampedToMax, testing::ext::TestSize.Level0)
{
    /* timeout above the server max is clamped: with the preconfigured short
     * test timeout, a clamped request must NOT fire within the short window */
    manager_->OpenDialog(&keyUri_, 100, 999999999, client_); // > max -> clamp
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_EQ(client_->called_, 0); // still waiting (clamped to 10min), not fired
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup
    EXPECT_EQ(client_->lastCode_, 0);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, LateReportAfterDoneIgnored, testing::ext::TestSize.Level0)
{
    manager_->OpenDialog(&keyUri_, 100, 0, client_);
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
        R"({"keyUri":"u1","requestId":"req123","timeout":600000})");
    conn.OnAbilityConnectDone(AppExecFwk::ElementName(), svc, 0);
    ASSERT_EQ(svc->keys_.size(), 3u);
    EXPECT_EQ(svc->keys_[0], "bundleName");
    EXPECT_EQ(svc->values_[0], "com.example.ukeydrv");
    EXPECT_EQ(svc->keys_[1], "abilityName");
    EXPECT_EQ(svc->values_[1], "DrvUIExtAbility");
    EXPECT_EQ(svc->keys_[2], "parameters");
    EXPECT_EQ(svc->values_[2], R"({"keyUri":"u1","requestId":"req123","timeout":600000})");
}

/* ---- F1: SA keep-alive during WAITING_REPORT ---- */

HWTEST_F(CmUkeyAuthDialogManagerTest, KeepAliveFiresPeriodicallyAndCancelsOnFinish,
    testing::ext::TestSize.Level0)
{
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, 0, client_), CM_SUCCESS);
    std::string reqId = manager_->GetRequestIdForTest();
    std::this_thread::sleep_for(std::chrono::milliseconds(130)); // >= 2 fires at 50ms
    EXPECT_GE(renewalCount_, 2); // armed on success + periodic re-arm
    ASSERT_EQ(manager_->OnReport(reqId, driverBundle_, 0), CM_SUCCESS);
    int afterFinish = renewalCount_;
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    EXPECT_EQ(renewalCount_, afterFinish); // cancelled on finish
}

HWTEST_F(CmUkeyAuthDialogManagerTest, KeepAliveNotArmedOnSyncFailure, testing::ext::TestSize.Level0)
{
    querierRet_ = -51; // ability query fail -> reject before session
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, 0, client_), CMR_DIALOG_ERROR_UKEY_ABILITY_NOT_SUPPORTED);
    querierRet_ = 0;
    launcher_->connectRet_ = 29160333; // connect fail -> reject before session
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, 0, client_), CMR_DIALOG_ERROR_INTERNAL);
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    EXPECT_EQ(renewalCount_, 0);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, KeepAliveCancelledOnAbort, testing::ext::TestSize.Level0)
{
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, 0, client_), CM_SUCCESS);
    manager_->SetTimeoutForTest(200, 100); // reconfiguration aborts the active session
    std::this_thread::sleep_for(std::chrono::milliseconds(150)); // > 50ms interval
    EXPECT_EQ(renewalCount_, 0); // cancelled before the first fire
}

/* ---- F2: client death monitoring ---- */

HWTEST_F(CmUkeyAuthDialogManagerTest, ClientDeathAbortsSessionWithoutResult,
    testing::ext::TestSize.Level0)
{
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, 0, client_), CM_SUCCESS);
    std::string reqId = manager_->GetRequestIdForTest();
    manager_->OnClientDied(reqId);
    EXPECT_EQ(manager_->GetRequestIdForTest(), ""); // session cleared
    EXPECT_EQ(client_->called_, 0); // no result delivered to the dead client
    EXPECT_EQ(launcher_->disconnectCount_, 1); // dialog connection torn down
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    EXPECT_EQ(renewalCount_, 0); // keep-alive cancelled on abort
    EXPECT_EQ(manager_->OpenDialog(&keyUri_, 100, 0, client_), CM_SUCCESS); // single-flight free
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup
}

HWTEST_F(CmUkeyAuthDialogManagerTest, ClientDeathUnknownRequestIdNoop, testing::ext::TestSize.Level0)
{
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, 0, client_), CM_SUCCESS);
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
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, 0, client_), CMR_DIALOG_ERROR_INTERNAL);
    EXPECT_EQ(manager_->GetRequestIdForTest(), ""); // session not stored
    EXPECT_EQ(client_->called_, 0); // no result delivered
    EXPECT_EQ(launcher_->disconnectCount_, 1); // established connection rolled back
    EXPECT_EQ(renewalCount_, 0); // keep-alive not armed
    manager_->SetTimerPostFailForTest(false);
    EXPECT_EQ(manager_->OpenDialog(&keyUri_, 100, 0, client_), CM_SUCCESS); // single-flight free
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup
}

HWTEST_F(CmUkeyAuthDialogManagerTest, GraceTimerPostFailFinishesSession, testing::ext::TestSize.Level0)
{
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, 0, client_), CM_SUCCESS);
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
