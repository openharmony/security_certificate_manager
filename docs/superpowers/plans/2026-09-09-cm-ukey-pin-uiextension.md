# CM UKey Pin UIExtensionAbility 弹框 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 实现无 context 的 `openUkeyAuthDialog(ukeyAuthRequest)` 重载与 `reportUkeyAuthResult(requestId, resultCode)` 上报接口，打通"证书管理 SA → 系统弹窗服务（com.ohos.systemui.dialog）→ UKey 驱动自定义 UIExtensionAbility → 主动上报结果"全链路。

**Architecture:** Kit 层（NAPI/ANI）经新增 IPC 消息（CM_MSG_OPEN_UKEY_AUTH_DIALOG / CM_MSG_REPORT_UKEY_AUTH_RESULT）请求 SA 3512；SA 侧新增会话管理器（requestId 单飞状态机：LAUNCHING→WAITING_REPORT→GRACE_WAITING→DONE，5min 总超时/10s 宽限），经 `ExtensionManagerClient::ConnectServiceExtensionAbility` 连接系统弹窗服务拉起驱动 UIExtensionAbility，驱动完成后回调 `reportUkeyAuthResult` 上报，SA 校验身份（bundleName 比对）后经客户端回调 stub 异步应答。

**Tech Stack:** C（innerkit/IPC 序列化）+ C++（SA manager/NAPI/ANI）+ ArkTS d.ts（interface/sdk-js 独立仓）；GN + Ninja；gtest + libFuzzer。

**Spec:** `docs/superpowers/specs/2026-09-03-cm-ukey-pin-uiextension-design.md`（本计划随附，执行者须同时阅读；所有设计决策 D1-D8 以 spec 为准）

## Global Constraints

以下约束对每个任务生效（摘自 spec 与仓 AGENTS.md，逐条必查）：

1. **工作目录**：所有构建命令在 OpenHarmony 源码根 `/home/wanghaixiang/ohos_master` 执行。certificate_manager 仓路径 `base/security/certificate_manager`；`interface/sdk-js` 是**独立 git 仓**（Task 8 单独提交）。
2. **分支**：开始前在 certificate_manager 仓执行 `git -C base/security/certificate_manager checkout -b cm-ukey-pin-impl cm-ukey-pin-design`。
3. **提交**：`git commit -s`，消息小写 `feat: ...` / `fix: ...` / `test: ...`；不提交 out/ 产物。
4. **新文件**必须带 Apache-2.0 头（照抄同目录任一现有文件的头部，年份 2026）。
5. **编码**：4 空格禁 Tab；C 主体；内存用 `CmMalloc`/`CmFree`（禁裸 malloc/free）；日志用 `CM_LOG_I/W/E/D`（禁 printf/hilog 直调）；敏感缓冲清零 `memset_s`；C++ 命名空间 `OHOS::Security::CertManager`；类 `DISALLOW_COPY_AND_MOVE`。
6. **IPC 四件套**：消息码只追加在 `CM_MSG_MAX` 之前（`frameworks/cert_manager_standard/main/common/include/cert_manager_service_ipc_interface_code.h:56`，受 CODEOWNERS 审查）；proxy/stub/innerkit 必须同任务同步。
7. **HUKS 依赖（已解除，用户裁定 2026-09-09）**：仅消费现有 `HksQueryAbilityInfo`（返回 bundle/ability 名，`base/security/huks/interfaces/inner_api/huks_standard/main/include/hks_api.h:133`，本树已存在）；ability 类型**不经 HUKS 查询**——老接口（argc==2）恒走原路径（默认 UIAbility，现状零变化），新接口（argc==1）固定按 UIExtensionAbility 处理，SA 仅以查询结果非空为门槛（空 → `-1016`/`29700008`）。**禁止修改 base/security/huks 仓**。
8. **错误码（spec D8，全链路统一）**：内部 `-1016`(`CMR_DIALOG_ERROR_UKEY_ABILITY_NOT_SUPPORTED`)→JS `29700008`；`-1017`(`CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT`)→`29700009`；`-1018`(`CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS`)→`29700010`。宽限超时→`CMR_DIALOG_ERROR_OPERATION_CANCELS`→`29700002`。
9. **上报 resultCode 白名单**：`{0, 29700001, 29700002, 29700003, 29700006}`，未知值折叠为 29700001。
10. **构建验证命令**（每个任务收尾必跑受影响目标）：
    - `./build.sh --product-name rk3568 --build-only-gn`（仅 GN 变更时）
    - `./build.sh --product-name rk3568 --build-target cm_sdk_test`
    - `./build.sh --product-name rk3568 --build-target cert_manager_service`
    - 单测执行：`out/rk3568/tests/unittest/certificate_manager/certificate_manager/cm_sdk_test --gtest_filter=CmUkeyAuthDialogManagerTest.*`
11. **安全红线**：日志不得输出密钥/PIN 等敏感内容（keyUri/requestId 可打）；REPORT 通道身份校验（bundleName 比对）不可绕过；OPEN 服务端必须校验 `ohos.permission.ACCESS_CERT_MANAGER`。
12. **TDD 适用性声明**：Task 2/3 为纯逻辑模块，完整 TDD（先测后码）；Task 1/4/5/6/7 的交付物受编译型 IPC 链路限制，验证 = 编译通过 + 既有测试回归 + Task 9 fuzz；Task 8 为 d.ts 声明，验证 = 与 spec §5.1 逐字对照。此为本仓工程现实，spec §13 已认可。

## 文件结构总览

| 任务 | 文件 | 动作 |
|---|---|---|
| T1 | `interfaces/innerkits/cert_manager_standard/main/include/cm_type.h` | 修改：`UkeyAuthRequest`、3 内部错误码、回调 typedef |
| T1 | `interfaces/innerkits/.../cert_manager_api.h` | 修改：2 个新 API 声明 |
| T1 | `frameworks/.../common/include/cert_manager_service_ipc_interface_code.h` | 修改：2 消息码 |
| T1 | `interfaces/kits/common/include/cm_dialog_api_common.h` | 修改：3 个 JS 错误码枚举 + 文案 |
| T1 | `interfaces/kits/common/include/cm_dialog_api_common.h`（映射表） | 修改：DIALOG_CODE_TO_JS_CODE_MAP / MSG_MAP |
| T2 | `services/.../os_dependency/dialog/cm_ukey_auth_dialog_manager.{h,cpp}` | 新建：会话管理器 |
| T2 | `test/unittest/src/cm_ukey_auth_dialog_manager_test.cpp` | 新建：状态机单测 |
| T3 | `services/.../os_dependency/dialog/cm_system_dialog_connection.{h,cpp}` | 新建：连接 + launcher |
| T3 | `services/.../os_dependency/dialog/BUILD.gn` | 新建：dialog 静态库 |
| T3 | `services/.../os_dependency/BUILD.gn` | 修改：sa 库依赖 dialog |
| T4 | `services/.../os_dependency/idl/cm_ipc/cm_ukey_auth_dialog_ipc_service.{h,cpp}` | 新建：SA 处理器 |
| T4 | `services/.../os_dependency/sa/cm_sa.cpp` | 修改：路由 |
| T4 | `services/.../os_dependency/idl/BUILD.gn` | 修改：源文件与依赖 |
| T5 | `frameworks/.../os_dependency/cm_ipc/src/cm_ipc_dialog_client.{h,cpp}` | 新建：客户端 + 回调 stub |
| T5 | `frameworks/.../os_dependency/cm_ipc/include/cm_ipc_client.h` | 修改：extern C 声明 |
| T5 | `frameworks/.../os_dependency/BUILD.gn` | 修改：sources |
| T5 | `interfaces/innerkits/.../source/cert_manager_api.c` | 修改：转发实现 |
| T6 | `interfaces/kits/napi/src/dialog/cm_napi_open_ukey_auth_dialog.cpp` | 修改：argc 分叉 |
| T6 | `interfaces/kits/napi/src/dialog/cm_napi_report_ukey_auth_result.cpp` + include | 新建 |
| T6 | `interfaces/kits/napi/src/dialog/cm_napi_dialog.cpp` | 修改：注册 |
| T7 | `interfaces/kits/ani/certificate_manager_dialog_ani/`（ets/src/include） | 新建 + 修改 |
| T8 | `interface/sdk-js/api/@ohos.security.certManagerDialog.d.ts`（+zh-cn 镜像） | 修改（独立仓） |
| T9 | `test/fuzz_test/cmopenukeyauthdialog_fuzzer/`、`cmreportukeyauthresult_fuzzer/` | 新建 ×2 |
| T10 | 构建回归 + spec 状态更新 | — |

---

### Task 1: 基础定义层（类型、错误码、IPC 消息码、映射表）

**Files:**
- Modify: `base/security/certificate_manager/interfaces/innerkits/cert_manager_standard/main/include/cm_type.h`
- Modify: `base/security/certificate_manager/interfaces/innerkits/cert_manager_standard/main/include/cert_manager_api.h`
- Modify: `base/security/certificate_manager/frameworks/cert_manager_standard/main/common/include/cert_manager_service_ipc_interface_code.h`
- Modify: `base/security/certificate_manager/interfaces/kits/common/include/cm_dialog_api_common.h`

**Interfaces:**
- Produces（后续所有任务依赖）:
  - `struct UkeyAuthRequest { struct CmBlob keyUri; };`（cm_type.h）
  - `typedef void (*CmUkeyAuthDialogResultCallback)(int32_t resultCode, void *userData);`
  - `CMR_DIALOG_ERROR_UKEY_ABILITY_NOT_SUPPORTED = -1016`、`CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT = -1017`、`CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS = -1018`（cm_type.h `CmErrorCode` 的 dialog 段，现最大 -1015）
  - `CM_MSG_OPEN_UKEY_AUTH_DIALOG`、`CM_MSG_REPORT_UKEY_AUTH_RESULT`（枚举，`CM_MSG_MAX` 前）
  - kits/common `ErrorCode` 枚举追加 `DIALOG_ERROR_UKEY_ABILITY_NOT_SUPPORTED = 29700008`、`DIALOG_ERROR_UKEY_AUTH_REPORT_TIMEOUT = 29700009`、`DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS = 29700010`

- [ ] **Step 1: 确认现有 HUKS 查询接口存在（存在性检查）**

```bash
grep -n "HksQueryAbilityInfo" base/security/huks/interfaces/inner_api/huks_standard/main/include/hks_api.h
```
Expected: 存在声明（返回 bundle/ability 名；类型不经 HUKS，见 Global Constraint 7）。

- [ ] **Step 2: cm_type.h 追加类型与错误码**

在 `CmErrorCode` 枚举 `CMR_DIALOG_ERROR_START_UIABILITY_FAILED = -1015`（cm_type.h:263）之后追加：

```c
    CMR_DIALOG_ERROR_UKEY_ABILITY_NOT_SUPPORTED = -1016, /* ukey ability query empty or not UIExtensionAbility */
    CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT = -1017, /* provider did not report result within total timeout */
    CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS = -1018, /* another ukey pin dialog session is in progress */
```

在 `struct UkeyInfo`（cm_type.h:560）附近追加：

```c
struct UkeyAuthRequest {
    struct CmBlob keyUri; /* ukey credential uri, max 256 bytes */
};
```

- [ ] **Step 3: cert_manager_api.h 追加 API 声明**

在 `CmImportUkeyCert` 声明（cert_manager_api.h:101）之后：

```c
typedef void (*CmUkeyAuthDialogResultCallback)(int32_t resultCode, void *userData);

/**
 * Open the ukey pin auth dialog provided by the driver's custom UIExtensionAbility.
 * Returns sync validation result; final dialog result is delivered via callback exactly once.
 */
CM_API_EXPORT int32_t CmOpenUkeyAuthDialog(const struct UkeyAuthRequest *ukeyAuthRequest,
    CmUkeyAuthDialogResultCallback callback, void *userData);

/**
 * Called by the driver's UIExtensionAbility to report the auth result. Returns sync validation result.
 */
CM_API_EXPORT int32_t CmReportUkeyAuthResult(const struct CmBlob *requestId, int32_t resultCode);
```

- [ ] **Step 4: IPC 消息码追加**

`cert_manager_service_ipc_interface_code.h:54`（`CM_MSG_IMPORT_UKEY_CERTIFICATE,` 之后、`CM_MSG_MAX` 之前）：

```c
    CM_MSG_OPEN_UKEY_AUTH_DIALOG,
    CM_MSG_REPORT_UKEY_AUTH_RESULT,
```

- [ ] **Step 5: kits/common 错误码与映射**

`cm_dialog_api_common.h`：`ErrorCode` 枚举 `DIALOG_ERROR_NO_AVAILABLE_CERTIFICATE = 29700007` 后追加三个值（Step Interfaces 所列）；`DIALOG_CODE_TO_JS_CODE_MAP` 追加：

```cpp
    { CMR_DIALOG_ERROR_UKEY_ABILITY_NOT_SUPPORTED, DIALOG_ERROR_UKEY_ABILITY_NOT_SUPPORTED },
    { CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT, DIALOG_ERROR_UKEY_AUTH_REPORT_TIMEOUT },
    { CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS, DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS },
```

`DIALOG_CODE_TO_MSG_MAP` 追加（文案常量先定义在文件上部 const std::string 区）：

```cpp
static const std::string UKEY_ABILITY_NOT_SUPPORTED_MSG =
    "the ukey driver has not registered a custom pin dialog of the UIExtensionAbility type.";
static const std::string UKEY_AUTH_REPORT_TIMEOUT_MSG =
    "the ukey driver did not report the auth result within the timeout.";
static const std::string UKEY_DIALOG_IN_PROGRESS_MSG =
    "another ukey pin auth dialog is already in progress.";
```

- [ ] **Step 6: 编译验证**

```bash
cd /home/wanghaixiang/ohos_master && ./build.sh --product-name rk3568 --build-only-gn && ./build.sh --product-name rk3568 --build-target cert_manager_sdk
```
Expected: GN 与编译均成功（纯声明无实现，不破坏链接——尚无调用方）。

- [ ] **Step 7: Commit**

```bash
git -C base/security/certificate_manager add -A && git -C base/security/certificate_manager commit -s -m "feat: add ukey auth dialog types, error codes and ipc msg codes"
```

---

### Task 2: SA 会话管理器（TDD 核心）

**Files:**
- Create: `base/security/certificate_manager/services/cert_manager_standard/cert_manager_service/main/os_dependency/dialog/cm_ukey_auth_dialog_manager.h`
- Create: `base/security/certificate_manager/services/cert_manager_standard/cert_manager_service/main/os_dependency/dialog/cm_ukey_auth_dialog_manager.cpp`
- Create: `base/security/certificate_manager/test/unittest/src/cm_ukey_auth_dialog_manager_test.cpp`
- Modify: `base/security/certificate_manager/test/BUILD.gn`（sources 追加新测试文件）

**Interfaces:**
- Consumes: Task 1 的错误码。
- Produces（Task 3/4 依赖，签名固定）:

```cpp
namespace OHOS::Security::CertManager {
constexpr uint32_t CM_UKEY_DIALOG_TOTAL_TIMEOUT_MS = 300000; // 5min, spec D5
constexpr uint32_t CM_UKEY_DIALOG_GRACE_TIMEOUT_MS = 10000;  // 10s, spec D5

// 结果回调分发命令码（SA->client 回调 stub 的 SendRequest code）
constexpr uint32_t CM_UKEY_DIALOG_CALLBACK_CMD = 1;

class SystemDialogLauncher {           // T3 提供真实实现，T2 单测注入 fake
public:
    virtual ~SystemDialogLauncher() = default;
    virtual int32_t Connect(const sptr<IAbilityConnection> &conn) = 0;
    virtual void Disconnect(const sptr<IAbilityConnection> &conn) = 0;
};

// ability 查询注入点（生产环境由 T4 装配为 HksQueryAbilityInfo 适配函数：
// 仅返回 bundle/ability 名，查询失败即视为"未注册自定义弹框"——类型不经 HUKS，D3）
using AbilityQuerier = std::function<int32_t(const struct CmBlob *keyUri,
    std::string &bundleName, std::string &abilityName)>;

class CmUkeyAuthDialogManager {
public:
    static CmUkeyAuthDialogManager &GetInstance();
    void SetLauncher(std::shared_ptr<SystemDialogLauncher> launcher);
    void SetAbilityQuerier(AbilityQuerier querier);
    void SetTimeoutForTest(uint32_t totalMs, uint32_t graceMs);
    // 同步返回校验码（CM_SUCCESS / -1016 / -1017 / -1018 / CMR_DIALOG_ERROR_INTERNAL）
    int32_t OpenDialog(const struct CmBlob *keyUri, uint32_t callerUid,
        const sptr<IRemoteObject> &clientCallback);
    // 返回 CM_SUCCESS（已接受）或 CMR_DIALOG_ERROR_INTERNAL（会话不存在/身份不符/终态）
    int32_t OnReport(const std::string &requestId, const std::string &callerBundleName,
        int32_t resultCode);
    void OnDialogDisconnected(const std::string &requestId);
};
}
```

- [ ] **Step 1: 写失败测试**

`cm_ukey_auth_dialog_manager_test.cpp`（文件头照抄 Apache-2.0）。测试依赖注入：FakeLauncher 记录 Connect/Disconnect 调用；FakeQuerier 可编程返回；FakeClientCallback 为 `IRemoteStub` 派生，记录 `SendRequest(CM_UKEY_DIALOG_CALLBACK_CMD)` 收到的 code；定时器用 `SetTimeoutForTest(200, 100)` 短超时。

```cpp
#include <gtest/gtest.h>
#include "cm_ukey_auth_dialog_manager.h"

namespace OHOS::Security::CertManager {
class FakeLauncher : public SystemDialogLauncher {
public:
    int32_t Connect(const sptr<IAbilityConnection> &conn) override { connectCount_++; conn_ = conn; return connectRet_; }
    void Disconnect(const sptr<IAbilityConnection> &conn) override { disconnectCount_++; }
    int32_t connectRet_ = 0; int connectCount_ = 0; int disconnectCount_ = 0;
    sptr<IAbilityConnection> conn_;
};

class FakeClientCallback : public IRemoteStub<IRemoteBroker> {
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
                      std::string &ability) -> int32_t {
            bundle = driverBundle_; ability = driverAbility_; return querierRet_;
        };
        manager_->SetLauncher(launcher_);
        manager_->SetAbilityQuerier(querier_);
        manager_->SetTimeoutForTest(200, 100); // 200ms total, 100ms grace
    }
    CmUkeyAuthDialogManager *manager_;
    std::shared_ptr<FakeLauncher> launcher_;
    std::string driverBundle_ = "com.example.ukeydrv";
    std::string driverAbility_ = "DrvUIExtAbility";
    int32_t querierRet_ = 0;
    sptr<FakeClientCallback> client_ = sptr<FakeClientCallback>(new FakeClientCallback());
    struct CmBlob keyUri_ = { 8, reinterpret_cast<uint8_t *>(const_cast<char *>("testuri")) };
};

HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDialogAbilityQueryFail, testing::ext::TestSize.Level0)
{
    querierRet_ = -51; // HUKS query error -> treated as not-registered
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, client_), CMR_DIALOG_ERROR_UKEY_ABILITY_NOT_SUPPORTED);
    EXPECT_EQ(launcher_->connectCount_, 0);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDialogConnectFail, testing::ext::TestSize.Level0)
{
    launcher_->connectRet_ = 29160333; // arbitrary aafwk error
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, client_), CMR_DIALOG_ERROR_INTERNAL);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, SingleFlightRejected, testing::ext::TestSize.Level0)
{
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, client_), CM_SUCCESS);
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, client_), CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, NormalReportDeliversCode, testing::ext::TestSize.Level0)
{
    ASSERT_EQ(manager_->OpenDialog(&keyUri_, 100, client_), CM_SUCCESS);
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
    manager_->OpenDialog(&keyUri_, 100, client_);
    ASSERT_EQ(manager_->OnReport(manager_->GetRequestIdForTest(), "com.example.other", 0),
        CMR_DIALOG_ERROR_INTERNAL);
    EXPECT_EQ(client_->called_, 0); // session still pending
    manager_->OnReport(manager_->GetRequestIdForTest(), "com.example.ukeydrv", 29700002); // cleanup
}

HWTEST_F(CmUkeyAuthDialogManagerTest, ReportUnknownCodeFolded, testing::ext::TestSize.Level0)
{
    manager_->OpenDialog(&keyUri_, 100, client_);
    ASSERT_EQ(manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 12345), CM_SUCCESS);
    EXPECT_EQ(client_->lastCode_, CMR_DIALOG_ERROR_INTERNAL); // folded to 29700001
}

HWTEST_F(CmUkeyAuthDialogManagerTest, DisconnectThenGraceReport, testing::ext::TestSize.Level0)
{
    manager_->OpenDialog(&keyUri_, 100, client_);
    std::string reqId = manager_->GetRequestIdForTest();
    manager_->OnDialogDisconnected(reqId); // enter grace
    ASSERT_EQ(manager_->OnReport(reqId, driverBundle_, 0), CM_SUCCESS); // within 100ms
    EXPECT_EQ(client_->lastCode_, 0);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, GraceTimeoutMeansCancel, testing::ext::TestSize.Level0)
{
    manager_->OpenDialog(&keyUri_, 100, client_);
    manager_->OnDialogDisconnected(manager_->GetRequestIdForTest());
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); // > 100ms grace
    EXPECT_EQ(client_->called_, 1);
    EXPECT_EQ(client_->lastCode_, CMR_DIALOG_ERROR_OPERATION_CANCELS);
    EXPECT_EQ(launcher_->disconnectCount_, 1);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, TotalTimeoutMeansReportTimeout, testing::ext::TestSize.Level0)
{
    manager_->OpenDialog(&keyUri_, 100, client_);
    std::this_thread::sleep_for(std::chrono::milliseconds(400)); // > 200ms total
    EXPECT_EQ(client_->called_, 1);
    EXPECT_EQ(client_->lastCode_, CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT);
    EXPECT_EQ(launcher_->disconnectCount_, 1);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, LateReportAfterDoneIgnored, testing::ext::TestSize.Level0)
{
    manager_->OpenDialog(&keyUri_, 100, client_);
    std::string reqId = manager_->GetRequestIdForTest();
    manager_->OnReport(reqId, driverBundle_, 0);
    ASSERT_EQ(manager_->OnReport(reqId, driverBundle_, 0), CMR_DIALOG_ERROR_INTERNAL);
    EXPECT_EQ(client_->called_, 1); // exactly once
}
}
```

注意：manager 需补 `std::string GetRequestIdForTest();` 公有方法（仅测试用）。

- [ ] **Step 2: 注册测试到 test/BUILD.gn 并验证编译失败**

`test/BUILD.gn` `cm_sdk_test` sources 追加 `"unittest/src/cm_ukey_auth_dialog_manager_test.cpp"`；deps 追加 dialog 静态库路径 `"${cert_manager_root_dir}/services/cert_manager_standard/cert_manager_service/main/os_dependency/dialog:libcm_ukey_auth_dialog_static"`（Task 3 才建 BUILD.gn——**本任务先建 dialog/BUILD.gn 最小骨架**（仅 manager 源文件），Task 3 再补 connection 与新依赖）：

```bash
cd /home/wanghaixiang/ohos_master && ./build.sh --product-name rk3568 --build-target cm_sdk_test
```
Expected: FAIL，`cm_ukey_auth_dialog_manager.h: No such file or directory`。

- [ ] **Step 3: 实现 manager**

`cm_ukey_auth_dialog_manager.h`：按 Interfaces 块声明 + `GetRequestIdForTest()`。头文件 include：`<functional>/<mutex>/<string>`、`iremote_stub.h`、`iremote_object.h`、`cm_type.h`、`ability_connect_callback_interface.h`。

`cm_ukey_auth_dialog_manager.cpp` 关键实现（完整文件在此基础上补全 Apache 头与 include）：

```cpp
namespace OHOS::Security::CertManager {
namespace {
std::string GenerateRequestId() // 16 random bytes -> 32 hex chars
{
    uint8_t buf[16] = {0};
    FILE *f = fopen("/dev/urandom", "r");
    if (f == nullptr || fread(buf, 1, sizeof(buf), f) != sizeof(buf)) { /* fallback: loop counter + time */ }
    if (f != nullptr) { fclose(f); }
    static const char hex[] = "0123456789abcdef";
    std::string id;
    for (auto b : buf) { id += hex[b >> 4]; id += hex[b & 0xF]; }
    return id;
}
bool IsValidReportCode(int32_t code)
{
    return code == 0 || code == DIALOG_ERROR_GENERIC || code == DIALOG_ERROR_OPERATION_CANCELED ||
        code == DIALOG_ERROR_INSTALL_FAILED || code == DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
}
} // namespace

CmUkeyAuthDialogManager &CmUkeyAuthDialogManager::GetInstance() { static CmUkeyAuthDialogManager inst; return inst; }

int32_t CmUkeyAuthDialogManager::OpenDialog(const struct CmBlob *keyUri, uint32_t callerUid,
    const sptr<IRemoteObject> &clientCallback)
{
    if (keyUri == nullptr || keyUri->data == nullptr || keyUri->size == 0 ||
        keyUri->size > MAX_LEN_URI || clientCallback == nullptr) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ != nullptr) { return CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS; }
    std::string bundle, ability;
    if (querier_ == nullptr || querier_(keyUri, bundle, ability) != CM_SUCCESS) {
        return CMR_DIALOG_ERROR_UKEY_ABILITY_NOT_SUPPORTED; // query empty == not registered (D3)
    }
    // build session (state=LAUNCHING), requestId=GenerateRequestId()
    // conn = new CmSystemDialogConnection(...)  —— T3 提供；T2 阶段 connection 由 launcher fake 持有，
    //   manager 经 launcher_->Connect(conn) 触发；T2 先以占位 sptr 传递（见 T3 Interfaces）
    if (launcher_ == nullptr || launcher_->Connect(conn) != CM_SUCCESS) {
        return CMR_DIALOG_ERROR_INTERNAL;   // session not stored -> single-flight not occupied
    }
    session_->state = WAITING_REPORT; // connect 同步成功即视为命令将发出（真实异步回调见 T3/T4 集成步骤）
    StartTimer(totalTimeoutMs_, [this, id] { FinishSession(id, CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT); });
    return CM_SUCCESS;
}
```

状态与收尾逻辑（同文件）：`OnReport` 查 requestId→比对 bundle→白名单折叠→`FinishSession(id, code)`；`OnDialogDisconnected` 状态 WAITING_REPORT→GRACE_WAITING + 重启 10s 宽限定时（超时→`FinishSession(id, CMR_DIALOG_ERROR_OPERATION_CANCELS)`）；`FinishSession`：停定时器→`launcher_->Disconnect`→`clientCallback->SendRequest(CM_UKEY_DIALOG_CALLBACK_CMD, parcel(int32 code), TF_ASYNC)`→`session_ = nullptr`；终态后迟到事件直接忽略/报错。定时器用 `AppExecFwk::EventRunner` 专用线程（"cm_ukey_dialog"），T2 单测环境下允许直接使用（EventRunner 可在测试进程创建）。`MAX_LEN_URI` 取 cm_type.h 现有常量（若无则本地 `constexpr uint32_t MAX_LEN_KEY_URI = 256;`）。

- [ ] **Step 4: 跑测试至全绿**

```bash
cd /home/wanghaixiang/ohos_master && ./build.sh --product-name rk3568 --build-target cm_sdk_test && \
  out/rk3568/tests/unittest/certificate_manager/certificate_manager/cm_sdk_test --gtest_filter='CmUkeyAuthDialogManagerTest.*'
```
Expected: 10 个用例全部 PASS。

- [ ] **Step 5: Commit**

```bash
git -C base/security/certificate_manager add -A && git -C base/security/certificate_manager commit -s -m "feat: add ukey auth dialog session manager with tdd tests"
```

---

### Task 3: 系统弹窗连接与 launcher（真实实现）

**Files:**
- Create: `.../os_dependency/dialog/cm_system_dialog_connection.h`
- Create: `.../os_dependency/dialog/cm_system_dialog_connection.cpp`
- Modify: `.../os_dependency/dialog/BUILD.gn`（补 connection 源与新 external_deps）
- Modify: `.../os_dependency/BUILD.gn`（sa 静态库 deps += dialog 库）
- Test: `test/unittest/src/cm_ukey_auth_dialog_manager_test.cpp`（追加 connection 组包用例）

**Interfaces:**
- Consumes: Task 2 `SystemDialogLauncher`、`CmUkeyAuthDialogManager::OnDialogDisconnected(requestId)`。
- Produces（Task 4 依赖）:

```cpp
namespace OHOS::Security::CertManager {
class CmSystemDialogConnection : public IAbilityConnection {  // 真实 launcher 持有的连接对象
public:
    CmSystemDialogConnection(const std::string &requestId, const std::string &bundle,
        const std::string &ability, const std::string &paramsJson);
    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int32_t resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode) override;
    void ReleaseWindow(const sptr<IRemoteObject> &remoteObject); // 总超时时发 ON_REMOTE_STATE_CHANGED
};
class RealSystemDialogLauncher : public SystemDialogLauncher {   // 生产装配（want 固定 systemui.dialog）
public:
    int32_t Connect(const sptr<IAbilityConnection> &conn) override;   // ResetCallingIdentity + ConnectServiceExtensionAbility
    void Disconnect(const sptr<IAbilityConnection> &conn) override;   // DisconnectAbility, 忽略已断连错误
};
}
```

- [ ] **Step 1: 写失败测试（追加到 manager 测试文件）**

```cpp
class FakeDialogService : public IRemoteStub<IRemoteBroker> { // 记录 START_DIALOG 报文
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override
    {
        if (code == IAbilityConnection::ON_ABILITY_CONNECT_DONE) {
            int32_t size = data.ReadInt32();
            for (int32_t i = 0; i < size; ++i) { keys_.push_back(Str16ToStr8(data.ReadString16())); values_.push_back(Str16ToStr8(data.ReadString16())); }
        }
        return 0;
    }
    std::vector<std::string> keys_, values_;
};

HWTEST_F(CmUkeyAuthDialogManagerTest, ConnectionParcelFormat, testing::ext::TestSize.Level0)
{
    sptr<FakeDialogService> svc = sptr<FakeDialogService>(new FakeDialogService());
    CmSystemDialogConnection conn("req123", "com.example.ukeydrv", "DrvUIExtAbility",
        R"({"keyUri":"u1","requestId":"req123"})");
    conn.OnAbilityConnectDone(AppExecFwk::ElementName(), svc, 0);
    ASSERT_EQ(svc->keys_.size(), 3u);
    EXPECT_EQ(svc->keys_[0], "bundleName");   EXPECT_EQ(svc->values_[0], "com.example.ukeydrv");
    EXPECT_EQ(svc->keys_[1], "abilityName");  EXPECT_EQ(svc->values_[1], "DrvUIExtAbility");
    EXPECT_EQ(svc->keys_[2], "parameters");
}
```
Expected: 编译 FAIL（CmSystemDialogConnection 未定义）。

- [ ] **Step 2: 实现 connection 与 launcher**

`cm_system_dialog_connection.cpp` 报文格式**逐字段对齐** useriam `ui_extension_ability_connection.cpp:32-67`：

```cpp
void CmSystemDialogConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int32_t resultCode)
{
    if (remoteObject == nullptr) { CmUkeyAuthDialogManager::GetInstance().OnDialogDisconnected(requestId_); return; }
    MessageParcel data; MessageParcel reply; MessageOption option;
    option.SetFlags(MessageOption::TF_ASYNC);
    data.WriteInt32(3); // SIGNAL_NUM, 对齐 useriam
    data.WriteString16(u"bundleName");      data.WriteString16(Str8ToStr16(bundle_));
    data.WriteString16(u"abilityName");     data.WriteString16(Str8ToStr16(ability_));
    data.WriteString16(u"parameters");      data.WriteString16(Str8ToStr16(paramsJson_));
    int32_t err = remoteObject->SendRequest(IAbilityConnection::ON_ABILITY_CONNECT_DONE, data, reply, option);
    if (err != 0) { CM_LOG_E("start dialog cmd failed %{public}d", err); CmUkeyAuthDialogManager::GetInstance().OnDialogDisconnected(requestId_); }
}

void CmSystemDialogConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode)
{
    CmUkeyAuthDialogManager::GetInstance().OnDialogDisconnected(requestId_);
}
```

`RealSystemDialogLauncher::Connect`：

```cpp
int32_t RealSystemDialogLauncher::Connect(const sptr<IAbilityConnection> &conn)
{
    AAFwk::Want want;
    want.SetElementName("com.ohos.systemui", "com.ohos.systemui.dialog");
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    auto ret = AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(want, conn, nullptr, -1);
    IPCSkeleton::SetCallingIdentity(identity);
    return ret;
}
```

manager 侧收尾（本任务同步修改 `cm_ukey_auth_dialog_manager.cpp`）：`OpenDialog` 构建 `paramsJson_`（cJSON 组装 `{"keyUri":..., "appUid":callerUid, "requestId":..., "action":"UkeyPINAuth"}`，cJSON 已在仓依赖中）；`FinishSession` 调 `connection->ReleaseWindow` 后 `launcher_->Disconnect`；生产装配入口 `CmUkeyAuthDialogManager::InitRealDependencies()`（懒初始化 RealSystemDialogLauncher + HUKS 查询适配），由 Task 4 在 SA OnStart/处理器首次调用时触发。

- [ ] **Step 3: BUILD.gn**

`dialog/BUILD.gn` 最终形态：

```gn
import("//base/security/certificate_manager/cert_manager.gni")
import("//build/ohos.gni")

config("cm_ukey_auth_dialog_config") { include_dirs = [ "include" ] }

ohos_static_library("libcm_ukey_auth_dialog_static") {
  subsystem_name = "security"
  part_name = "certificate_manager"
  public_configs = [ ":cm_ukey_auth_dialog_config" ]
  branch_protector_ret = "pac_ret"
  sanitize = { cfi = true; cfi_cross_dso = true; boundary_sanitize = true; debug = false; integer_overflow = true; ubsan = true }
  include_dirs = [ "${cert_manager_root_dir}/interfaces/innerkits/cert_manager_standard/main/include" ]
  sources = [
    "cm_ukey_auth_dialog_manager.cpp",
    "cm_system_dialog_connection.cpp",
  ]
  public_external_deps = [
    "ability_base:want",
    "ability_runtime:extension_manager_client",
    "access_token:libaccesstoken_sdk",
    "cJSON:cjson_static",
    "c_utils:utils",
    "eventhandler:libeventhandler",
    "hilog:libhilog",
    "ipc:ipc_core",
  ]
  cflags_cc = [ "-Wall", "-Werror" ]
  cflags = cflags_cc
  complete_static_lib = true
}
```

（头文件目录布局：`dialog/include/` 放两个 .h，`dialog/` 放 .cpp——按上表 include_dirs 调整；`os_dependency/BUILD.gn` 的 `libcert_manager_service_os_dependency_standard_static` deps 追加 `"dialog:libcm_ukey_auth_dialog_static"`。）

- [ ] **Step 4: 编译 + 全部测试通过**

```bash
cd /home/wanghaixiang/ohos_master && ./build.sh --product-name rk3568 --build-target cm_sdk_test && \
  ./build.sh --product-name rk3568 --build-target cert_manager_service && \
  out/rk3568/tests/unittest/certificate_manager/certificate_manager/cm_sdk_test --gtest_filter='CmUkeyAuthDialogManagerTest.*'
```
Expected: 编译成功，11 个用例 PASS。

- [ ] **Step 5: Commit**

```bash
git -C base/security/certificate_manager add -A && git -C base/security/certificate_manager commit -s -m "feat: add system dialog connection and real launcher for ukey pin dialog"
```

---

### Task 4: SA IPC 路由与处理器

**Files:**
- Create: `.../os_dependency/idl/cm_ipc/cm_ukey_auth_dialog_ipc_service.h`
- Create: `.../os_dependency/idl/cm_ipc/cm_ukey_auth_dialog_ipc_service.cpp`
- Modify: `.../os_dependency/sa/cm_sa.cpp`（`OnRemoteRequest` :258-297）
- Modify: `.../os_dependency/idl/BUILD.gn`（sources + deps）

**Interfaces:**
- Consumes: Task 1 消息码/CM_TAG；Task 2/3 manager（`InitRealDependencies/OpenDialog/OnReport`）。
- Produces（Task 5 客户端按此协议组包）:

```cpp
// 请求 parcel（客户端→SA）：
//   OPEN:   [uint32 size][paramSet blob: CM_TAG_PARAM0_BUFFER=keyUri][remote object 回调stub]
//   REPORT: [uint32 size][paramSet blob: CM_TAG_PARAM0_BUFFER=requestId, CM_TAG_PARAM1_UINT32=resultCode]
// 应答 parcel（SA→客户端）：[int32 同步校验码]（ConvertErrorCode 不覆盖 -1016~-1018，原样透传）
extern "C" int32_t CmIpcServiceOpenUkeyAuthDialog(const struct CmBlob *paramSetBlob,
    const sptr<IRemoteObject> &clientCallback);
extern "C" int32_t CmIpcServiceReportUkeyAuthResult(const struct CmBlob *paramSetBlob);
```

- [ ] **Step 1: 实现处理器**

`cm_ukey_auth_dialog_ipc_service.cpp`（C++，权限与身份校验在本层，manager 保持纯逻辑）：

```cpp
extern "C" int32_t CmIpcServiceOpenUkeyAuthDialog(const struct CmBlob *paramSetBlob,
    const sptr<IRemoteObject> &clientCallback)
{
    struct CmParamSet *paramSet = nullptr;
    struct CmBlob keyUri = { 0, nullptr };
    struct CmParamOut params[] = { { .tag = CM_TAG_PARAM0_BUFFER, .blob = &keyUri } };
    int32_t ret = CmGetParamSet((struct CmParamSet *)paramSetBlob->data, paramSetBlob->size, &paramSet);
    if (ret == CM_SUCCESS) { ret = CmParamSetToParams(paramSet, params, CM_ARRAY_SIZE(params)); }
    if (ret != CM_SUCCESS) { CM_LOG_E("open ukey dialog get params failed"); CmFreeParamSet(&paramSet); return CMR_ERROR_INVALID_ARGUMENT; }
    // 服务端权限校验（纵深防御；NAPI 侧已有一次）
    if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(),
        "ohos.permission.ACCESS_CERT_MANAGER") != PERMISSION_GRANTED) {
        CmFreeParamSet(&paramSet); return CMR_DIALOG_ERROR_PERMISSION_DENIED;
    }
    ret = CmUkeyAuthDialogManager::GetInstance().OpenDialog(&keyUri,
        static_cast<uint32_t>(IPCSkeleton::GetCallingUid()), clientCallback);
    CmFreeParamSet(&paramSet);
    return ret;
}

extern "C" int32_t CmIpcServiceReportUkeyAuthResult(const struct CmBlob *paramSetBlob)
{
    struct CmParamSet *paramSet = nullptr;
    struct CmBlob requestId = { 0, nullptr };
    uint32_t resultCode = 0;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &requestId },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = &resultCode },
    };
    // ... 解包同上 ...
    // 身份校验：仅 HAP token 且 bundleName 与会话驱动一致（manager 内比对，本层只取 bundle）
    Security::AccessToken::HapTokenInfo hapInfo;
    if (AccessTokenKit::GetHapTokenInfo(IPCSkeleton::GetCallingTokenID(), hapInfo) != SUCCESS) {
        CM_LOG_E("report caller is not hap token"); return CMR_DIALOG_ERROR_INTERNAL;
    }
    std::string reqId(reinterpret_cast<char *>(requestId.data), requestId.size);
    return CmUkeyAuthDialogManager::GetInstance().OnReport(reqId, hapInfo.bundleName,
        static_cast<int32_t>(resultCode));
}
```

（`OnStart` 或处理器首调处执行 `CmUkeyAuthDialogManager::GetInstance().InitRealDependencies()`——在 OpenDialog 入口若未初始化则懒初始化，幂等。）

- [ ] **Step 2: cm_sa.cpp 路由**

`OnRemoteRequest` 中（:278 跳过列表追加两码；`GetSrcData` 成功后、`ProcessMessage` 之前插入）：

```cpp
    if (code == static_cast<uint32_t>(CM_MSG_OPEN_UKEY_AUTH_DIALOG) ||
        code == static_cast<uint32_t>(CM_MSG_REPORT_UKEY_AUTH_RESULT)) {
        int32_t ret = CM_SUCCESS;
        if (code == static_cast<uint32_t>(CM_MSG_OPEN_UKEY_AUTH_DIALOG)) {
            sptr<IRemoteObject> remoteCallback = data.ReadRemoteObject();
            ret = (remoteCallback == nullptr) ? CMR_ERROR_NULL_POINTER
                : CmIpcServiceOpenUkeyAuthDialog(&srcData, remoteCallback);
        } else {
            ret = CmIpcServiceReportUkeyAuthResult(&srcData);
        }
        reply.WriteInt32(ret);
        CM_FREE_BLOB(srcData);
        return NO_ERROR;
    }
```

- [ ] **Step 3: idl/BUILD.gn**

sources 追加 `"cm_ipc/cm_ukey_auth_dialog_ipc_service.cpp"`；deps 追加 `"../dialog:libcm_ukey_auth_dialog_static"`；external_deps 追加 `"access_token:libaccesstoken_sdk"`（若未含）。

- [ ] **Step 4: 编译验证**

```bash
cd /home/wanghaixiang/ohos_master && ./build.sh --product-name rk3568 --build-target cert_manager_service && ./build.sh --product-name rk3568 --build-target cm_sdk_test
```
Expected: 编译成功；既有测试全量回归 PASS（`cm_sdk_test` 全跑一遍）。

- [ ] **Step 5: Commit**

```bash
git -C base/security/certificate_manager add -A && git -C base/security/certificate_manager commit -s -m "feat: route open/report ukey auth dialog ipc msgs in sa"
```

---

### Task 5: IPC 客户端、回调 stub 与 inner API 实现

**Files:**
- Create: `base/security/certificate_manager/frameworks/cert_manager_standard/main/os_dependency/cm_ipc/src/cm_ipc_dialog_client.cpp`（实现）与 `cm_ipc/include/cm_ipc_dialog_client.h`（extern C 接口）
- Modify: `frameworks/.../os_dependency/cm_ipc/include/cm_ipc_client.h`（声明）
- Modify: `frameworks/.../os_dependency/BUILD.gn`（`libcert_manager_ipc_client_static` sources 追加新 cpp）
- Modify: `base/security/certificate_manager/interfaces/innerkits/cert_manager_standard/main/source/cert_manager_api.c`

**Interfaces:**
- Consumes: Task 1 头文件声明；Task 4 parcel 协议。
- Produces（Task 6/7 NAPI/ANI 直接调用 inner API；此处补齐实现使链接闭合）:

```c
/* cm_ipc_client.h（extern "C" 块内） */
int32_t CmClientOpenUkeyAuthDialog(const struct CmBlob *keyUri,
    CmUkeyAuthDialogResultCallback callback, void *userData);
int32_t CmClientReportUkeyAuthResult(const struct CmBlob *requestId, int32_t resultCode);
```

- [ ] **Step 1: 实现客户端与回调 stub（cm_ipc_dialog_client.cpp）**

```cpp
namespace OHOS::Security::CertManager {
class CmDialogCallbackStub : public IRemoteStub<IRemoteBroker> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
        MessageOption &option) override
    {
        if (code != CM_UKEY_DIALOG_CALLBACK_CMD) { return 0; }
        int32_t result = data.ReadInt32();
        Deliver(result);   // 触发用户回调（线程安全，恰好一次），随后标记完成
        return 0;
    }
    void Deliver(int32_t result);          // 调用 callback_(result, userData_) 并停止兜底定时器
    void StartFallbackTimer();             // 6min 客户端兜底（> SA 5min）：Deliver(CMR_DIALOG_ERROR_INTERNAL)
    CmUkeyAuthDialogResultCallback callback_ = nullptr;
    void *userData_ = nullptr;
    std::atomic<bool> delivered_{false};
};
}
```

`CmClientOpenUkeyAuthDialog`（extern "C"）：`CmCheckBlob` → 创建 stub（`sptr` + `StartFallbackTimer` 6min）→ 组包（`BuildParamSet`（CM_TAG_PARAM0_BUFFER keyUri，参照 `cm_ipc_client_serialization.c` 现有实现）→ `data.WriteUint32(blob.size); data.WriteBuffer(...); data.WriteRemoteObject(stub)`）→ `SendMessageRequest(CM_MSG_OPEN_UKEY_AUTH_DIALOG, ..., 同步)` → 非 CM_SUCCESS 时销毁 stub 返回错误码（此路径**不**触发 callback，与 spec §4 一致）；成功则 stub 生命周期自管（Deliver 一次后释放）。

`CmClientReportUkeyAuthResult`（extern "C"）：组包（PARAM0_BUFFER requestId + PARAM1_UINT32 resultCode）→ 同步发送 → 返回回执码。回执码经 `ConvertErrorCode` 后为 CMR_DIALOG_* 段原值。

- [ ] **Step 2: cert_manager_api.c 转发**

```c
int32_t CmOpenUkeyAuthDialog(const struct UkeyAuthRequest *ukeyAuthRequest,
    CmUkeyAuthDialogResultCallback callback, void *userData)
{
    if (ukeyAuthRequest == NULL || callback == NULL ||
        ukeyAuthRequest->keyUri.data == NULL || ukeyAuthRequest->keyUri.size == 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CmClientOpenUkeyAuthDialog(&ukeyAuthRequest->keyUri, callback, userData);
}

int32_t CmReportUkeyAuthResult(const struct CmBlob *requestId, int32_t resultCode)
{
    if (requestId == NULL || requestId->data == NULL || requestId->size == 0) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CmClientReportUkeyAuthResult(requestId, resultCode);
}
```

- [ ] **Step 3: BUILD.gn 与编译**

`os_dependency/BUILD.gn` `libcert_manager_ipc_client_static` sources 追加 `"./cm_ipc/src/cm_ipc_dialog_client.cpp"`；external_deps 追加 `"eventhandler:libeventhandler"`（兜底定时器）。

```bash
cd /home/wanghaixiang/ohos_master && ./build.sh --product-name rk3568 --build-target cert_manager_sdk && ./build.sh --product-name rk3568 --build-target cm_sdk_test
```
Expected: 编译成功（四件套闭合），测试回归 PASS。

- [ ] **Step 4: Commit**

```bash
git -C base/security/certificate_manager add -A && git -C base/security/certificate_manager commit -s -m "feat: add ukey dialog ipc client, callback stub and inner api impl"
```

---

### Task 6: NAPI 层

**Files:**
- Modify: `base/security/certificate_manager/interfaces/kits/napi/src/dialog/cm_napi_open_ukey_auth_dialog.cpp`
- Create: `.../napi/src/dialog/cm_napi_report_ukey_auth_result.cpp` + `.../napi/include/dialog/cm_napi_report_ukey_auth_result.h`
- Modify: `.../napi/src/dialog/cm_napi_dialog.cpp`（属性表 :114 附近）

**Interfaces:**
- Consumes: `CmOpenUkeyAuthDialog`/`CmReportUkeyAuthResult`（inner API）。
- Produces: JS 侧 `openUkeyAuthDialog`（1/2 参自适应）与 `reportUkeyAuthResult`。

- [ ] **Step 1: 重构 CMNapiOpenUkeyAuthorizeDialog（argc 分叉）**

新结构（保留原有 metrics/syscap/参数校验骨架）：

```cpp
napi_value CMNapiOpenUkeyAuthorizeDialog(napi_env env, napi_callback_info info)
{
    // ... report/CheckSyscapReturnVoid 原样保留 ...
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != PARAM_SIZE_ONE && argc != PARAM_SIZE_TWO) { ThrowError(env, PARAM_ERROR, "Params number mismatch", &report); return result; }
    auto asyncContext = std::make_shared<CmUIExtensionRequestContext>(env);
    if (argc == PARAM_SIZE_TWO && !ParseCmUIAbilityContextReq(asyncContext->env, argv[0], asyncContext->context)) { /* 原 401 逻辑 */ }
    // UkeyAuthRequest 解析复用 GetUkeyAuthRequest(asyncContext, argv[argc - 1])
    if (argc == PARAM_SIZE_ONE) {                 // 新接口：固定走 SA 新链路（D3，无类型判定）
        return OpenUkeyAuthDialogNoContext(asyncContext, std::move(report));  // promise + threadsafe
    }
    // argc==2（老接口）：原有流程零改动（GetCustomerAuthCertWant + StartUkeyPinAbility），
    // 不做类型分叉（D3：恒按默认 UIAbility 处理）
}
```

`NeedNewPath` 已随 D3 裁定删除：argc==1 恒走新路径；argc==2 恒走原路径（零改动）。

`OpenUkeyAuthDialogNoContext`：

```cpp
// CmUkeyAuthResultContext: env/deferred/tsfn/metricsReport
// CmOpenUkeyAuthDialog(&req, [](int32_t code, void *ctx) {
//     napi_call_threadsafe_function(tsfn, 包装 code);   // IPC 线程 -> JS 线程
// }, ctx);
// JS 线程 UvTsfnCallback: code==0 -> napi_resolve_deferred(undefined) + report.Finish(0)
//                        否则 -> napi_reject_deferred(GenerateBusinessError(env, code, report))
```

- [ ] **Step 2: 新增 report NAPI**

```cpp
napi_value CMNapiReportUkeyAuthResult(napi_env env, napi_callback_info info)
{
    // argc==2: requestId(napi_string, 非空, ≤64 字节) + resultCode(napi_number)
    // 类型/长度不符 -> ThrowError(env, PARAM_ERROR, "parse report params failed")
    // CmReportUkeyAuthResult(&reqIdBlob, resultCode):
    //   CM_SUCCESS -> resolve(undefined)；否则 reject(GenerateBusinessError(env, ret))
}
```

`cm_napi_dialog.cpp` 属性表追加 `DECLARE_NAPI_FUNCTION("reportUkeyAuthResult", CMNapiReportUkeyAuthResult)`；BUILD.gn（napi dialog 模块）sources 追加新 cpp。

- [ ] **Step 3: 编译 + 回归**

```bash
cd /home/wanghaixiang/ohos_master && ./build.sh --product-name rk3568 --build-only-gn && \
  ./build.sh --product-name rk3568 --build-target certmanagerdialog 2>/dev/null || ./build.sh --product-name rk3568 --build-target certificate_manager
```
Expected: 编译成功（NAPI 模块目标名以 `interfaces/kits/napi/BUILD.gn` 内 dialog 模块实际名为准，先 grep 确认）。

- [ ] **Step 4: Commit**

```bash
git -C base/security/certificate_manager add -A && git -C base/security/certificate_manager commit -s -m "feat: napi support no-context openUkeyAuthDialog and reportUkeyAuthResult"
```

---

### Task 7: ANI 层

**Files:**
- Modify: `base/security/certificate_manager/interfaces/kits/ani/certificate_manager_dialog_ani/ets/@ohos.security.certManagerDialog.ets`
- Create: `.../ani/certificate_manager_dialog_ani/src/cm_open_ukey_auth_dialog_no_context.cpp` + include
- Create: `.../ani/certificate_manager_dialog_ani/src/cm_report_ukey_auth_result.cpp` + include
- Modify: `.../ani/certificate_manager_dialog_ani/src/cm_dialog_ani.cpp`（native 注册表 :223 附近）与 `BUILD.gn`（sources）

**Interfaces:**
- Consumes: inner API（Task 5）；现有 `CertManagerAsyncImpl`/`NativeResult` 模式（照抄 `cm_open_ukey_auth_dialog.cpp` 结构）。

- [ ] **Step 1: ets 层新增重载与接口**

```ts
export function openUkeyAuthDialog(ukeyAuthRequest: UkeyAuthRequest): Promise<void> {
    return new Promise<void>((resolve, reject) => {
        let keyUri = ukeyAuthRequest.keyUri;
        if (keyUri === undefined || keyUri === '') {
            let e = new BusinessError(); e.code = 401; e.message = 'the input parameters is invalid.'; throw e;
        }
        let callback = new AsyncCallbackWrapper<void>((err) => { err?.code !== 0 ? reject(err) : resolve(undefined); });
        let result = openUkeyAuthDialogNoContextNative(keyUri, callback);
        if (result.code !== 0) { let e = new BusinessError(); e.code = result.code; e.message = result.message; reject(e); }
    });
}
export function reportUkeyAuthResult(requestId: string, resultCode: number): Promise<void> { /* 同构 */ }
```

- [ ] **Step 2: native 实现**

照抄 `cm_open_ukey_auth_dialog.cpp` 的 `CertManagerAsyncImpl` 派生模式：`CmOpenUkeyAuthDialogNoContext`（无 abilityContext，Invoke 内调 inner API，结果经 `AsyncCallbackWrapper` 回抛）；`CmReportUkeyAuthResult` 同构。`cm_dialog_ani.cpp` 注册 `openUkeyAuthDialogNoContextNative`、`reportUkeyAuthResultNative`。

- [ ] **Step 3: 编译 + Commit**

```bash
cd /home/wanghaixiang/ohos_master && ./build.sh --product-name rk3568 --build-target certificate_manager && \
git -C base/security/certificate_manager add -A && git -C base/security/certificate_manager commit -s -m "feat: ani support no-context openUkeyAuthDialog and reportUkeyAuthResult"
```

---

### Task 8: SDK d.ts（interface/sdk-js 独立仓）

**Files:**
- Modify: `interface/sdk-js/api/@ohos.security.certManagerDialog.d.ts`
- Modify: `interface/sdk-js/zh-cn/api/@ohos.security.certManagerDialog.d.ts`（中文镜像）

**Interfaces:**
- Consumes: spec §5.1（JSDoc 逐字对照）。

- [ ] **Step 1: 独立仓建分支**

```bash
git -C interface/sdk-js checkout -b cm-ukey-pin-impl
```

- [ ] **Step 2: 追加内容（英文主文件）**

(a) `CertificateDialogErrorCode` 枚举追加（含完整 JSDoc，格式对齐现有枚举项）：

```ts
    /**
     * The UKey driver has not registered a custom PIN dialog of the UIExtensionAbility type.
     *
     * @syscap SystemCapability.Security.CertificateManagerDialog
     * @stagemodelonly
     * @since 26.0.0 dynamic&static
     */
    ERROR_UKEY_ABILITY_NOT_SUPPORTED = 29700008,

    /**
     * The UKey driver's PIN dialog did not report the authentication result within the timeout.
     *
     * @syscap SystemCapability.Security.CertificateManagerDialog
     * @stagemodelonly
     * @since 26.0.0 dynamic&static
     */
    ERROR_UKEY_AUTH_REPORT_TIMEOUT = 29700009,

    /**
     * Another UKey PIN authentication dialog is already in progress.
     *
     * @syscap SystemCapability.Security.CertificateManagerDialog
     * @stagemodelonly
     * @since 26.0.0 dynamic&static
     */
    ERROR_UKEY_DIALOG_IN_PROGRESS = 29700010
```

(b) 现有 `openUkeyAuthDialog` 之后追加新重载、其后再追加 `reportUkeyAuthResult`——**JSDoc 与签名逐字取自 spec §5.1**（含 `@throws` 201/401/801/29700001/29700002/29700003/29700006/29700008/29700009/29700010 与 report 的 401/29700001），此处不重复。

- [ ] **Step 3: 中文镜像同步**（zh-cn 文件追加同样成员，注释为中文对应描述）。

- [ ] **Step 4: 对照验证 + Commit**

逐条对照 spec §5.1：重载签名、report 签名、3 个枚举值、全部 `@throws`。

```bash
git -C interface/sdk-js add api/@ohos.security.certManagerDialog.d.ts zh-cn/api/@ohos.security.certManagerDialog.d.ts && \
git -C interface/sdk-js commit -s -m "feat: add no-context openUkeyAuthDialog overload and reportUkeyAuthResult"
```

---

### Task 9: Fuzz 用例

**Files:**
- Create: `base/security/certificate_manager/test/fuzz_test/cmopenukeyauthdialog_fuzzer/{BUILD.gn,cmopenukeyauthdialog_fuzzer.cpp,corpus/}`
- Create: `base/security/certificate_manager/test/fuzz_test/cmreportukeyauthresult_fuzzer/{BUILD.gn,cmreportukeyauthresult_fuzzer.cpp,corpus/}`
- Modify: `base/security/certificate_manager/test/fuzz_test/BUILD.gn`（group deps 追加两个 `:fuzztest`）

**Interfaces:**
- Consumes: inner API（Task 5）。BUILD.gn 结构**逐行照抄** `cmgetukeycertlist_fuzzer/BUILD.gn`（替换目标名与 fuzz_config_file 路径）。

- [ ] **Step 1: 写 fuzzer（示例：open）**

```cpp
void FuzzOpenUkeyAuthDialog(const uint8_t *data, size_t size)
{
    struct UkeyAuthRequest req = { { size, const_cast<uint8_t *>(data) } };
    (void)CmOpenUkeyAuthDialog(&req, [](int32_t code, void *userData) { (void)code; }, nullptr);
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzOpenUkeyAuthDialog(data, size);
    return 0;
}
```
（report 版本：前 32 字节作 requestId、`data[32]` 拼 resultCode 后调 `CmReportUkeyAuthResult`。）

- [ ] **Step 2: 注册 group 并构建**

`test/fuzz_test/BUILD.gn` `fuzztest` group deps 追加：

```gn
    "./cmopenukeyauthdialog_fuzzer:fuzztest",
    "./cmreportukeyauthresult_fuzzer:fuzztest",
```

```bash
cd /home/wanghaixiang/ohos_master && ./build.sh --product-name rk3568 --build-target CmOpenUkeyAuthDialogFuzzTest && ./build.sh --product-name rk3568 --build-target CmReportUkeyAuthResultFuzzTest
```
Expected: 两个 fuzzer 目标编译成功。

- [ ] **Step 3: Commit**

```bash
git -C base/security/certificate_manager add -A && git -C base/security/certificate_manager commit -s -m "test: add fuzzers for openUkeyAuthDialog and reportUkeyAuthResult"
```

---

### Task 10: 全量构建验证与收尾

**Files:**
- Modify: `base/security/certificate_manager/docs/superpowers/specs/2026-09-03-cm-ukey-pin-uiextension-design.md`（状态行）

- [ ] **Step 1: 全量构建**

```bash
cd /home/wanghaixiang/ohos_master && ./build.sh --product-name rk3568 --build-target certificate_manager
```
Expected: 整部件（SDK/SA/NAPI/ANI/fuzz）编译成功，无新增警告（`-Wall -Werror` 把关）。

- [ ] **Step 2: 单测全量回归**

```bash
out/rk3568/tests/unittest/certificate_manager/certificate_manager/cm_sdk_test
```
Expected: 全部 PASS（含既有 22 个测试文件无回归 + 新增 12 个用例）。

- [ ] **Step 3: 四件套完整性核对（AGENTS.md 完成标准 4）**

确认：消息码（T1）↔ proxy/客户端（T5）↔ stub/路由（T4）↔ innerkit（T1 声明 + T5 实现）全部就位；`git log --oneline` 逐提交检查无越界改动（不触碰 HUKS/systemui 仓）。

- [ ] **Step 4: spec 状态更新 + 提交**

spec 头部状态改为"已实现（待联调）"；追加"联调清单"备注（真机：驱动 demo 注册 UIExtensionAbility 类型，成功/取消/失败/超时/伪造上报/断连竞态场景，spec §13）。

```bash
git -C base/security/certificate_manager add -A && git -C base/security/certificate_manager commit -s -m "docs: mark ukey pin uiextension design as implemented"
```

- [ ] **Step 5: 完成报告**

按仓 AGENTS.md"完成报告格式"输出：文件清单、构建/测试结果、风险评估（IPC 兼容/权限/HUKS 依赖）、未完成事项（真机联调、XTS 用例随 XTS 仓节奏单独提交、HUKS 文档对齐项 spec §6.3）。

---

## Self-Review 记录

0. **修订 R6（用户裁定 2026-09-09）**：abilityType 不经 HUKS——老接口恒走原路径、新接口固定 UIExtensionAbility（SA 仅以查询非空为门槛）。已同步修订 GC7、T1 Step 1（门禁改为现有接口存在性确认）、T2（querier 签名去 type 出参、删 OpenDialogWrongAbilityType 用例、manager 校验简化）、T6（删 NeedNewPath/QueryUkeyAbilityType，argc 分叉简化）；spec D3/§4/§6.1/§10.1/§10.2/§11/§12/§14-R3 同步修订。类型一致性复查：AbilityQuerier 新签名在 T2 Interfaces/T2 测试/T2 实现描述三处一致。
1. **Spec coverage**：spec §5（d.ts 重载/report/枚举→T8）、§7（inner API→T1/T5）、§8（IPC 码/parcel/客户端→T1/T5、SA 路由→T4）、§9（manager/connection→T2/T3、BUILD→T3/T4）、§10（kits/common 映射→T1、NAPI argc 分叉→T6、ANI→T7）、§13（单测→T2/T3、fuzz→T9、构建验证→T10）均有对应任务。XTS 用例标注为 XTS 仓节奏交付（T10 报告事项）。**发现并补充**：spec 未覆盖的客户端 6min 兜底超时已写入 T5（防 SA 崩溃导致调用方永久挂起），并在报告事项中注明。
2. **Placeholder scan**：T6 Step 1 中 `OpenUkeyAuthDialogNoContext` 内部为骨架注释——因其结构完全复刻本文件已有的 promise+tsfn 模式且 Step 3 有编译门槛验证，属可执行指引而非 TBD；其余任务代码块均为可直接落盘内容。T8 JSDoc 明确"逐字取自 spec §5.1"（spec 随计划执行，非占位）。
3. **Type consistency**：`CmOpenUkeyAuthDialog(const struct UkeyAuthRequest*, CmUkeyAuthDialogResultCallback, void*)` 与回调 typedef 在 T1/T5/T6/T7 一致；manager 三接口签名在 T2 定义、T3/T4 消费处一致；parcel 协议 T4（服务端读）与 T5（客户端写）字段顺序一致（uint32 size + buffer + remote object）；错误码三元组（-1016/-1017/-1018 ↔ 29700008/09/10）全任务统一。
