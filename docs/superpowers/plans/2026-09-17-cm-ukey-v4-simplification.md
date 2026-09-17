# CM UKey 弹框 v4 简化方案 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 按 spec v4 收敛 UKey Pin 弹框特性：删除 scene/无 context 重载/SA 默认弹框/UIAbility 直启路径，新增驱动自拉起接口 `openAuthDialogForUkeyDriver`（CRYPTO_EXTENSION_REGISTER + IPC token 包名 + BMS 预校验）。

**Architecture:** openUkeyAuthDialog(context) 只支持驱动注册的 UIExtensionAbility（Kit 查询门禁 + SA 复查；非 PC 回退 Kit 直启默认弹框）；openAuthDialogForUkeyDriver 经新 IPC 消息到 SA，从 IPC token 取调用方 bundle、BMS 校验 (bundle, abilityName) 为 UKEY_AUTH 类型扩展后经 systemui 弹窗服务拉起。两接口共享 SA 会话机制（单飞/超时/上报）。

**Tech Stack:** C/C++（innerkit/IPC/SA/NAPI/ANI），GN/Ninja，gtest；d.ts 在 interface_sdk-js 仓（ukey-auth 分支）；真机 rk3568。

**Spec:** `docs/superpowers/specs/2026-09-03-cm-ukey-pin-uiextension-design.md`（v4，含 D21–D26 与路由矩阵 §4.1——实施时以 spec 为准）

## Global Constraints

- 分支：certificate_manager 仓 `ukey-no-uiability`（**不推送远程**）；interface_sdk-js 仓 `ukey-auth`（**不推送远程**，除非用户明示）
- 构建（源码树根执行）：`./build.sh --product-name rk3568 --build-target certificate_manager --build-target cm_sdk_test --keep-ninja-going`
- 提交：`git commit -s`，小写前缀 `feat:`/`fix:`/`test:`/`docs:`；新文件带 Apache-2.0 头（复制邻文件）
- IPC 四件套约束（AGENTS.md）：消息码只能追加在 `CM_MSG_MAX` 前，`cert_manager_service_ipc_interface_code.h` 受 CODEOWNERS 审查——本计划新增 `CM_MSG_OPEN_UKEY_AUTH_DIALOG_FOR_DRIVER` 一次到位
- 日志用 `CM_LOG_*`（禁 printf/hilog 直调）；内存用 `CmMalloc/CmFree`（禁裸 malloc/free）；敏感数据（customData）只记长度不打内容
- IPC paramSet 参数必须一次性 `CmParamsToParamSet`（禁止事后 `CmAddParams` 追加——会覆写已序列化数据，v3 修复过的真实缺陷）
- SA 内对外部服务（BMS）查询前 `IPCSkeleton::ResetCallingIdentity()`、查完 `SetCallingIdentity` 还原
- 错误码：内部负值（-1019/-1020/-1021/-1014/-1011/-1017/-1018…），JS 侧经 `DIALOG_CODE_TO_JS_CODE_MAP` 映射；`openUkeyAuthDialog` 折叠 -1017→29700002、-1018→29700003；`openAuthDialogForUkeyDriver` 直通 29700009/29700010
- 真机部署特殊行为：hdc server 在 Windows 侧，`hdc file send` 源路径必须写 Windows 形式 `D:\hdc_push\xxx`（文件先拷到 `/mnt/d/hdc_push/`）；推 /system so 后需 `hdc shell reboot`；联调 `setenforce 0`
- 单测真机执行：`/data/local/tmp/cmtest`（`LD_LIBRARY_PATH=/data/local/tmp/cmtest:/system/lib`）

---

### Task 1: SA 管理器 OpenDriverDialog（BMS 校验 seam + 路由 + 单测）

**Files:**
- Modify: `services/cert_manager_standard/cert_manager_service/main/os_dependency/dialog/include/cm_ukey_auth_dialog_manager.h`
- Modify: `services/cert_manager_standard/cert_manager_service/main/os_dependency/dialog/cm_ukey_auth_dialog_manager.cpp`
- Modify: `services/cert_manager_standard/cert_manager_service/main/os_dependency/dialog/BUILD.gn`
- Test: `test/unittest/src/cm_ukey_auth_dialog_manager_test.cpp`

**Interfaces:**
- Produces（Task 2 的 IPC 处理器消费）:
  ```cpp
  using DriverAbilityChecker = std::function<bool(const std::string &bundleName,
      const std::string &abilityName)>;
  void SetDriverAbilityChecker(DriverAbilityChecker checker);   // 测试注入 seam
  int32_t OpenDriverDialog(const struct CmBlob *abilityName, uint32_t abilityType,
      const struct CmBlob *keyUri, uint32_t callerUid, const std::string &callerBundleName,
      uint32_t timeoutMs, const struct CmBlob *customData,
      const sptr<IRemoteObject> &clientCallback);
  // 返回值契约同 OpenDialog：CM_SUCCESS / -1014 / -1019 / -1020 / -1018 / CMR_DIALOG_ERROR_* / CMR_ERROR_*
  ```

- [ ] **Step 1: 写失败测试**（加到 `cm_ukey_auth_dialog_manager_test.cpp`，fixture 增加注入与包装器）

在 `CmUkeyAuthDialogManagerTest` fixture（ SetUp 末尾，约 line 82）增加：

```cpp
        driverChecker_ = [this](const std::string &, const std::string &) -> bool {
            return bmsOk_;
        };
        manager_->SetDriverAbilityChecker(driverChecker_);
```

fixture 成员（`pcMode_` 声明后）：

```cpp
    DriverAbilityChecker driverChecker_;
    bool bmsOk_ = true;
    std::string callerBundle_ = "com.example.ukeydriver";
    std::string driverAbilityName_ = "MyUkeyAuthExtensionAbility";
    /* convenience wrapper for OpenDriverDialog (spec v4 §4.1 ForDriver 路由) */
    int32_t OpenDriver(uint32_t abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION, uint32_t timeout = 0,
        const struct CmBlob *customData = nullptr)
    {
        struct CmBlob abilityName = { static_cast<uint32_t>(driverAbilityName_.size() + 1),
            reinterpret_cast<uint8_t *>(const_cast<char *>(driverAbilityName_.c_str())) };
        return manager_->OpenDriverDialog(&abilityName, abilityType, &keyUri_, 100,
            callerBundle_, timeout, customData, client_);
    }
```

新增测试用例（追加到 `TotalTimeoutPostFailRejectsOpen` 用例之后）：

```cpp
/* ---- OpenDriverDialog（spec v4 §4.1 ForDriver 路由，D23）---- */
HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDriverDialogWrongAbilityTypeRejected, testing::ext::TestSize.Level0)
{
    /* SA 侧 abilityType 防御：仅 UIExtension 放行，其余 -1014（29700006） */
    ASSERT_EQ(OpenDriver(CM_UKEY_ABILITY_TYPE_UIABILITY), CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED);
    ASSERT_EQ(OpenDriver(2), CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED);
    EXPECT_EQ(launcher_->connectCount_, 0);
    EXPECT_EQ(manager_->GetRequestIdForTest(), "");
}

HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDriverDialogBmsCheckFails, testing::ext::TestSize.Level0)
{
    /* BMS 预校验失败（ability 不存在/非 UKEY_AUTH 扩展）→ -1019（29700003，D23） */
    bmsOk_ = false;
    ASSERT_EQ(OpenDriver(), CMR_DIALOG_ERROR_NOT_REGISTERED);
    EXPECT_EQ(launcher_->connectCount_, 0);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDriverDialogPcGate, testing::ext::TestSize.Level0)
{
    /* ForDriver 无回退：非 PC → -1020（29700005，D25 v2） */
    pcMode_ = false;
    ASSERT_EQ(OpenDriver(), CMR_DIALOG_ERROR_NOT_PC_DEVICE);
    EXPECT_EQ(launcher_->connectCount_, 0);
    pcMode_ = true;
    ASSERT_EQ(OpenDriver(), CM_SUCCESS);
    manager_->OnReport(manager_->GetRequestIdForTest(), callerBundle_, 0); // cleanup
}

HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDriverDialogParamsAndOwner, testing::ext::TestSize.Level0)
{
    /* 成功路径：owner = 调用方 bundle（IPC token 来源），params JSON 无 scene、
     * 目标 = callerBundle/driverAbilityName（spec §6.2/D26） */
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
    EXPECT_EQ(params.find("\"scene\""), std::string::npos); /* v4 无 scene */
    /* 上报责任方 = 调用方 bundle；他人上报被拒 */
    std::string reqId = manager_->GetRequestIdForTest();
    ASSERT_EQ(manager_->OnReport(reqId, driverBundle_, 0), CMR_DIALOG_ERROR_INTERNAL);
    ASSERT_EQ(manager_->OnReport(reqId, callerBundle_, 0), CM_SUCCESS);
    EXPECT_EQ(client_->lastCode_, 0);
}

HWTEST_F(CmUkeyAuthDialogManagerTest, OpenDriverDialogSharesSingleFlight, testing::ext::TestSize.Level0)
{
    /* 两接口共享单飞（D26）：OpenDialog 占位后 ForDriver 拒 -1018，反之亦然 */
    ASSERT_EQ(Open(), CM_SUCCESS);
    ASSERT_EQ(OpenDriver(), CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS);
    manager_->OnReport(manager_->GetRequestIdForTest(), driverBundle_, 0); // cleanup
    ASSERT_EQ(OpenDriver(), CM_SUCCESS);
    ASSERT_EQ(Open(), CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS);
    manager_->OnReport(manager_->GetRequestIdForTest(), callerBundle_, 0); // cleanup
}
```

- [ ] **Step 2: 编译确认失败**

Run: `./build.sh --product-name rk3568 --build-target cm_sdk_test --keep-ninja-going 2>&1 | grep -E "OHOS ERROR|FAILED" | head -5`
Expected: FAIL（`SetDriverAbilityChecker`/`OpenDriverDialog`/`DriverAbilityChecker` 未定义；`CMR_DIALOG_ERROR_NOT_REGISTERED` 未定义）

- [ ] **Step 3: 实现 manager 头文件**

`cm_ukey_auth_dialog_manager.h`：

3a. `PcChecker` typedef 后新增：

```cpp
// 驱动弹框扩展 BMS 预校验注入点（spec v4 D23：ForDriver 路径消费；生产装配经
// BundleMgr 查询 (bundleName, abilityName) 存在且为 UKEY_AUTH 类型扩展）
using DriverAbilityChecker = std::function<bool(const std::string &bundleName,
    const std::string &abilityName)>;
```

3b. `SetPcChecker` 声明后新增：

```cpp
    void SetDriverAbilityChecker(DriverAbilityChecker checker);
```

3c. `OpenDialog` 声明后新增：

```cpp
    /* openAuthDialogForUkeyDriver 的 SA 入口（spec v4 §4.1/D23）：调用方 bundle 由
     * IPC 层从 IPC token 解出传入（客户端不可伪造）；abilityType 仅接受
     * CM_UKEY_ABILITY_TYPE_UIEXTENSION；BMS 校验经 driverAbilityChecker_。
     * 返回值契约同 OpenDialog。 */
    int32_t OpenDriverDialog(const struct CmBlob *abilityName, uint32_t abilityType,
        const struct CmBlob *keyUri, uint32_t callerUid, const std::string &callerBundleName,
        uint32_t timeoutMs, const struct CmBlob *customData,
        const sptr<IRemoteObject> &clientCallback);
```

3d. private 段（`PcChecker pcChecker_` 成员对应位置）新增成员与私有助手：

```cpp
    /* 从 OpenDialog/OpenDriverDialog 公共拉起序列抽出（bundle/ability 已定，
     * PC 门禁已过）：requestId→会话→连接→总超时。返回同步码。 */
    int32_t LaunchUiExtensionSessionLocked(const std::string &bundleName,
        const std::string &abilityName, const struct CmBlob *keyUri, uint32_t callerUid,
        uint32_t timeoutMs, const struct CmBlob *customData,
        const sptr<IRemoteObject> &clientCallback);
    uint32_t NormalizeTimeoutMsLocked(uint32_t timeoutMs);
    DriverAbilityChecker driverAbilityChecker_;  // 缺省视为校验失败（fail-closed）
```

- [ ] **Step 4: 实现 manager cpp**

`cm_ukey_auth_dialog_manager.cpp`：

4a. 文件头 include 区（`#include "ipc_skeleton.h"` 之后）新增：

```cpp
#include "bundle_mgr_interface.h"
#include "extension_ability_info.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
```

4b. 匿名 namespace 内（`QueryUkeyDriverAbility` 函数后）新增真实 BMS 校验：

```cpp
/* 驱动弹框扩展 BMS 预校验（生产装配，spec v4 D23）：(bundleName, abilityName)
 * 存在且类型为 UKEY_AUTH（ExtensionAbilityType=40）。以 SA 自身身份查询
 * （ResetCallingIdentity，避免线程上残留的 app token 影响 BMS 可见性判定）。 */
bool QueryDriverUkeyExtensionAbility(const std::string &bundleName,
    const std::string &abilityName)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        CM_LOG_E("get system ability manager failed");
        return false;
    }
    auto remote = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remote == nullptr) {
        CM_LOG_E("get bundle mgr service failed");
        return false;
    }
    auto bundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remote);
    if (bundleMgr == nullptr) {
        CM_LOG_E("cast bundle mgr proxy failed");
        return false;
    }
    int32_t userId = static_cast<int32_t>(IPCSkeleton::GetCallingUserId());
    AAFwk::Want want;
    want.SetElementName(bundleName, abilityName);
    std::vector<AppExecFwk::ExtensionAbilityInfo> infos;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    bool ok = bundleMgr->QueryExtensionAbilityInfos(want,
        AppExecFwk::ExtensionAbilityType::UKEY_AUTH, 0, userId, infos);
    IPCSkeleton::SetCallingIdentity(identity);
    if (!ok) {
        CM_LOG_E("query extension ability infos failed, bundle: %s, ability: %s",
            bundleName.c_str(), abilityName.c_str());
        return false;
    }
    for (const auto &info : infos) {
        if (info.bundleName == bundleName && info.name == abilityName) {
            return true;
        }
    }
    return false;
}
```

4c. `SetPcChecker` 实现后新增：

```cpp
void CmUkeyAuthDialogManager::SetDriverAbilityChecker(DriverAbilityChecker checker)
{
    std::lock_guard<std::mutex> lock(mutex_);
    AbortActiveSessionLocked();
    driverAbilityChecker_ = std::move(checker);
}
```

4d. 从 `OpenDialog` 中抽出两个助手（`GenerateRequestId` 之后的实现区）：把 OpenDialog 中「timeout 归一化」的 10 行搬入 `NormalizeTimeoutMsLocked`；把「launcher null 检查 → EnsureTimerHandlerLocked → 生成 requestId → 建 session → BuildUkeyDialogParams → connection → Connect → StartTimer → 入表 → 死亡监听/保活」整段搬入 `LaunchUiExtensionSessionLocked`（`session->ownerBundleName = bundleName`，入参）。**`BuildUkeyDialogParams` 在本 Task 内同步去掉 `uint32_t scene` 形参与 items/names 数组中的 scene 项**（抽取后的 helper 是其唯一调用方，驱动弹框 JSON 先行去 scene；`BuildDefaultDialogParams` 不动——默认弹框 JSON 仍含 scene，Task 6 删除）。OpenDialog 的 DEFAULT_DIALOG 分支保持原旧代码路径不迁移。

```cpp
uint32_t CmUkeyAuthDialogManager::NormalizeTimeoutMsLocked(uint32_t timeoutMs)
{
    /* timeoutDuration 归一化（spec D5 v2）：0（未传）取默认值；显式值 clamp */
    if (timeoutMs == 0) {
        return defaultTimeoutMs_;
    }
    if (timeoutMs < minTimeoutMs_) {
        CM_LOG_W("timeout %u below min, clamp to %u", timeoutMs, minTimeoutMs_);
        return minTimeoutMs_;
    }
    if (timeoutMs > maxTimeoutMs_) {
        CM_LOG_W("timeout %u exceeds max, clamp to %u", timeoutMs, maxTimeoutMs_);
        return maxTimeoutMs_;
    }
    return timeoutMs;
}
```

`LaunchUiExtensionSessionLocked` 实现体 = 现 OpenDialog 的 line 432–505 段（launcher 检查起）原样迁移，仅三处改动：`session->ownerBundleName = bundleName;`（入参）；`BuildUkeyDialogParams` 调用去 scene 实参（形参已按 4d 删除）；成功日志的 `kind` 打印改为固定 `"UIEXTENSION_DIALOG"`。

同时（既有测试适配 4d 的 scene 先行移除）：`ParamsJsonCarriesSceneAndCustomData` 用例删除 `EXPECT_NE(params.find("\"scene\":\"Custom\""), ...)` 断言行（保留 customData base64 断言；`OpenDialogAbilityQueryFail` 的默认弹框 `"scene":"Login"` 断言保留不动——`BuildDefaultDialogParams` 仍含 scene）。

4e. `OpenDialog` 末尾新增 ForDriver 入口：

```cpp
int32_t CmUkeyAuthDialogManager::OpenDriverDialog(const struct CmBlob *abilityName,
    uint32_t abilityType, const struct CmBlob *keyUri, uint32_t callerUid,
    const std::string &callerBundleName, uint32_t timeoutMs,
    const struct CmBlob *customData, const sptr<IRemoteObject> &clientCallback)
{
    if (abilityName == nullptr || abilityName->data == nullptr || abilityName->size == 0 ||
        abilityName->size > HAP_INFO_MAX_LENGTH || keyUri == nullptr || keyUri->data == nullptr ||
        keyUri->size == 0 || keyUri->size > MAX_LEN_URI || clientCallback == nullptr ||
        callerBundleName.empty()) {
        CM_LOG_E("invalid open driver dialog arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (customData != nullptr && customData->size > CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE) {
        CM_LOG_E("custom data too large: %u", customData->size);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t effectiveTimeoutMs = NormalizeTimeoutMsLocked(timeoutMs);
    if (session_ != nullptr) {
        CM_LOG_E("another ukey auth dialog session is in progress");
        return CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS;
    }
    if (abilityType != CM_UKEY_ABILITY_TYPE_UIEXTENSION) {
        CM_LOG_E("driver dialog only supports uiextension type, got: %u", abilityType);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    std::string ability(reinterpret_cast<char *>(abilityName->data), abilityName->size);
    if (ability.back() == '\0') { /* blob 可能带结尾 NUL */
        ability.pop_back();
    }
    if (driverAbilityChecker_ == nullptr || !driverAbilityChecker_(callerBundleName, ability)) {
        CM_LOG_E("driver ability check failed, bundle: %s, ability: %s",
            callerBundleName.c_str(), ability.c_str());
        return CMR_DIALOG_ERROR_NOT_REGISTERED;
    }
    if (pcChecker_ == nullptr || !pcChecker_()) {
        CM_LOG_E("ukey uiextension dialog requires pc device or pc mode");
        return CMR_DIALOG_ERROR_NOT_PC_DEVICE;
    }
    return LaunchUiExtensionSessionLocked(callerBundleName, ability, keyUri, callerUid,
        effectiveTimeoutMs, customData, clientCallback);
}
```

4f. `InitRealDependencies` 中 `pcChecker_` 装配后追加：

```cpp
    if (driverAbilityChecker_ == nullptr) {
        driverAbilityChecker_ = QueryDriverUkeyExtensionAbility; /* spec v4 D23 */
    }
```

4g. `cm_type.h` 中 `-1019` 枚举改名（本 Task 提前做，属纯改名无行为变化）：

```c
    CMR_DIALOG_ERROR_NOT_REGISTERED = -1019, /* 未注册驱动弹框，或 ForDriver 指定扩展不存在/类型不符（→29700003） */
```

（原 `CMR_DIALOG_ERROR_DEFAULT_NOT_SUPPORTED = -1019` 行替换；本 Task 内同步全仓改名引用：`interfaces/kits/common/include/cm_dialog_api_common.h` 的两张映射表条目、`interfaces/kits/napi/src/dialog/cm_napi_open_ukey_auth_dialog.cpp`、`interfaces/kits/ani/certificate_manager_dialog_ani/src/cm_dialog_ani.cpp` 的 `CMR_DIALOG_ERROR_DEFAULT_NOT_SUPPORTED` 引用、`test/unittest/src/cm_ukey_auth_dialog_real_ipc_test.cpp`。用 `grep -rn "CMR_DIALOG_ERROR_DEFAULT_NOT_SUPPORTED" --exclude-dir=out` 找全。）

- [ ] **Step 5: BUILD.gn 增 BMS 依赖**

`dialog/BUILD.gn` 的 `external_deps` 列表（`huks:libhukssdk` 之后）追加：

```gn
    "bundle_framework:appexecfwk_base",
    "bundle_framework:appexecfwk_core",
```

- [ ] **Step 6: 编译 + 跑单测（本地可编部分）**

Run: `./build.sh --product-name rk3568 --build-target certificate_manager --build-target cm_sdk_test --keep-ninja-going 2>&1 | grep -E "OHOS ERROR|FAILED|build  successful" | head -5`
Expected: `=====build  successful=====`
（单测执行在真机统一做，见 Task 8；本步只保证编译。）

- [ ] **Step 7: Commit**

```bash
git add -A && git commit -s -m "feat: add sa-side open driver dialog with bms precheck"
```

---

### Task 2: inner API + IPC 四件套（ForDriver 全链路到 SA）

**Files:**
- Modify: `interfaces/innerkits/cert_manager_standard/main/include/cm_type.h`（UkeyAuthDialogInfo 结构体）
- Modify: `interfaces/innerkits/cert_manager_standard/main/include/cert_manager_api.h`
- Modify: `interfaces/innerkits/cert_manager_standard/source/cert_manager_api.c`
- Modify: `frameworks/cert_manager_standard/main/common/include/cert_manager_service_ipc_interface_code.h`
- Modify: `frameworks/cert_manager_standard/main/os_dependency/cm_ipc/include/cm_ipc_client.h`
- Modify: `frameworks/cert_manager_standard/main/os_dependency/cm_ipc/src/cm_ipc_dialog_client.cpp`
- Modify: `services/cert_manager_standard/cert_manager_service/main/os_dependency/sa/cm_sa.cpp`
- Modify: `services/cert_manager_standard/cert_manager_service/main/os_dependency/idl/cm_ipc/cm_ukey_auth_dialog_ipc_service.h`
- Modify: `services/cert_manager_standard/cert_manager_service/main/os_dependency/idl/cm_ipc/cm_ukey_auth_dialog_ipc_service.cpp`
- Create: `test/fuzz_test/cmopenauthdialogforukeydriver_fuzzer/cmopenauthdialogforukeydriver_fuzzer.cpp`（+ `BUILD.gn` + `corpus/`，目录结构照抄 `cmopenukeyauthdialog_fuzzer`）
- Modify: `test/unittest/src/cm_test_common.cpp`（PERMISSION_LIST 增权限）
- Modify: `test/unittest/src/cm_ukey_auth_dialog_real_ipc_test.cpp`（ForDriver 探针）
- Modify: `test/fuzz_test/cmopenukeyauthdialog_fuzzer/BUILD.gn`（如新 fuzzer 复用其配置则改本文件注册，否则照抄目录）

**Interfaces:**
- Consumes: Task 1 的 `CmUkeyAuthDialogManager::OpenDriverDialog`
- Produces（Task 3/4 Kit 层消费）:
  ```c
  struct UkeyAuthDialogInfo {
      struct CmBlob abilityName; /* 驱动弹框扩展名，非空，≤128 字节（含 NUL） */
      uint32_t abilityType;      /* 仅 CM_UKEY_ABILITY_TYPE_UIEXTENSION(1) */
  };
  CM_API_EXPORT int32_t CmOpenUkeyAuthDialogForDriver(const struct UkeyAuthDialogInfo *dialogInfo,
      const struct UkeyAuthRequest *ukeyAuthRequest, CmUkeyAuthDialogResultCallback callback,
      void *userData);
  ```

- [ ] **Step 1: cm_type.h 增结构体**

`struct UkeyAuthRequest` 定义之后新增：

```c
/* UKey 驱动弹框扩展信息（对齐 d.ts UkeyAuthDialogInfo，spec v4 D24）：
 * openAuthDialogForUkeyDriver 入参，bundle 由服务端从 IPC token 解出（不可声明） */
struct UkeyAuthDialogInfo {
    struct CmBlob abilityName; /* 驱动弹框扩展名，非空，最大 128 字节，NUL 结尾 */
    uint32_t abilityType;      /* enum 值，仅 CM_UKEY_ABILITY_TYPE_UIEXTENSION */
};
```

- [ ] **Step 2: 消息码**

`cert_manager_service_ipc_interface_code.h` 的 `CM_MSG_REPORT_UKEY_AUTH_RESULT,` 之后、`/* new cmd type must be added before CM_MSG_MAX */` 之前追加：

```c
    CM_MSG_OPEN_UKEY_AUTH_DIALOG_FOR_DRIVER,
```

- [ ] **Step 3: inner API**

3a. `cert_manager_api.h`：`CmOpenUkeyAuthDialog` 声明块之后新增：

```c
/**
 * Open the ukey driver's own pin auth dialog (UIExtensionAbility only). The driver
 * bundle is resolved from the caller identity on the service side. Returns sync
 * validation result; final dialog result is delivered via callback exactly once.
 */
CM_API_EXPORT int32_t CmOpenUkeyAuthDialogForDriver(const struct UkeyAuthDialogInfo *dialogInfo,
    const struct UkeyAuthRequest *ukeyAuthRequest, CmUkeyAuthDialogResultCallback callback,
    void *userData);
```

3b. `cert_manager_api.c`：`CmOpenUkeyAuthDialog` 实现之后新增（模式照抄，含 inner API 直调方纵深防御）：

```c
CM_API_EXPORT int32_t CmOpenUkeyAuthDialogForDriver(const struct UkeyAuthDialogInfo *dialogInfo,
    const struct UkeyAuthRequest *ukeyAuthRequest, CmUkeyAuthDialogResultCallback callback,
    void *userData)
{
    CM_LOG_I("enter open auth dialog for ukey driver");
    if (dialogInfo == NULL || ukeyAuthRequest == NULL || callback == NULL ||
        dialogInfo->abilityName.data == NULL || dialogInfo->abilityName.size == 0 ||
        ukeyAuthRequest->keyUri.data == NULL || ukeyAuthRequest->keyUri.size == 0) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (dialogInfo->abilityType != CM_UKEY_ABILITY_TYPE_UIEXTENSION) {
        CM_LOG_E("invalid driver dialog ability type: %u", dialogInfo->abilityType);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    if (ukeyAuthRequest->customData.size > CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE) {
        CM_LOG_E("custom data too large: %u", ukeyAuthRequest->customData.size);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }

    int32_t ret = CmClientOpenUkeyAuthDialogForDriver(dialogInfo, ukeyAuthRequest, callback,
        userData);
    CM_LOG_I("leave open auth dialog for ukey driver, result = %d", ret);
    return ret;
}
```

（`cert_manager_api.c` 已 include `cm_ipc_client.h` 与 `cm_ukey_ability_type.h` 的传递链若断则补 include。）

- [ ] **Step 4: IPC 客户端**

4a. `cm_ipc_client.h`（`CmClientOpenUkeyAuthDialog` 声明后）：

```c
int32_t CmClientOpenUkeyAuthDialogForDriver(const struct UkeyAuthDialogInfo *dialogInfo,
    const struct UkeyAuthRequest *ukeyAuthRequest, CmUkeyAuthDialogResultCallback callback,
    void *userData);
```

4b. `cm_ipc_dialog_client.cpp`：文件末尾（`CmClientReportUkeyAuthResult` 之前）新增。回调 stub/兜底计时器全部复用现有类，仅组包与消息码不同（五参数一次性序列化，spec §8.2）：

```cpp
int32_t CmClientOpenUkeyAuthDialogForDriver(const struct UkeyAuthDialogInfo *dialogInfo,
    const struct UkeyAuthRequest *ukeyAuthRequest, CmUkeyAuthDialogResultCallback callback,
    void *userData)
{
    if (dialogInfo == nullptr || ukeyAuthRequest == nullptr || callback == nullptr ||
        CmCheckBlob(&dialogInfo->abilityName) != CM_SUCCESS ||
        CmCheckBlob(&ukeyAuthRequest->keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid open auth dialog for ukey driver arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (dialogInfo->abilityType != CM_UKEY_ABILITY_TYPE_UIEXTENSION) {
        CM_LOG_E("invalid driver dialog ability type: %u", dialogInfo->abilityType);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    if (ukeyAuthRequest->customData.size > CM_UKEY_AUTH_CUSTOM_DATA_MAX_SIZE) {
        CM_LOG_E("custom data too large: %u", ukeyAuthRequest->customData.size);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }

    sptr<CmDialogCallbackStub> stub = new (std::nothrow) CmDialogCallbackStub(callback, userData);
    if (stub == nullptr) {
        CM_LOG_E("create ukey dialog callback stub failed");
        return CMR_ERROR_MALLOC_FAIL;
    }

    /* 五参数一次性序列化（spec v4 §8.2）：禁止事后 CmAddParams 追加 */
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = dialogInfo->abilityName },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = dialogInfo->abilityType },
        { .tag = CM_TAG_PARAM2_BUFFER, .blob = ukeyAuthRequest->keyUri },
        { .tag = CM_TAG_PARAM3_UINT32, .uint32Param = ukeyAuthRequest->timeoutDuration },
        { .tag = CM_TAG_PARAM4_BUFFER, .blob = ukeyAuthRequest->customData },
    };

    struct CmParamSet *sendParamSet = nullptr;
    int32_t ret = CmParamsToParamSet(params, CM_ARRAY_SIZE(params), &sendParamSet);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("open driver dialog pack params failed, ret = %d", ret);
        CmFreeParamSet(&sendParamSet);
        return ret;
    }
    struct CmBlob parcelBlob = { sendParamSet->paramSetSize, reinterpret_cast<uint8_t *>(sendParamSet) };

    do {
        if (!stub->StartFallbackTimer()) {
            CM_LOG_E("arm ukey dialog fallback timer failed");
            ret = CMR_DIALOG_ERROR_INTERNAL;
            break;
        }
        int32_t replyCode = CM_FAILURE;
        ret = OHOS::SendRequestWithRemote(CM_MSG_OPEN_UKEY_AUTH_DIALOG_FOR_DRIVER, &parcelBlob,
            stub, &replyCode);
        if (ret != CM_SUCCESS || replyCode != CM_SUCCESS) {
            CM_LOG_E("open driver dialog request failed, ret = %d, reply = %d", ret, replyCode);
            stub->Cancel();
            ret = (ret != CM_SUCCESS) ? ret : replyCode;
            break;
        }
        stub->HoldSelf();
        CM_LOG_I("open driver dialog request accepted");
    } while (0);

    CmFreeParamSet(&sendParamSet);
    return ret;
}
```

注意：本文件需能看见 `CM_UKEY_ABILITY_TYPE_UIEXTENSION`——`cm_ukey_ability_type.h` 经 `cm_type.h`→`cm_ukey_dialog_common.h` 链可达则不补，否则文件头补 `#include "cm_ukey_ability_type.h"`。

- [ ] **Step 5: SA 分发**

`cm_sa.cpp` OnRemoteRequest 中 OPEN 特判改为两码共用（`[size][remote][buffer]` 布局一致）：

```cpp
    if (code == static_cast<uint32_t>(CM_MSG_OPEN_UKEY_AUTH_DIALOG) ||
        code == static_cast<uint32_t>(CM_MSG_OPEN_UKEY_AUTH_DIALOG_FOR_DRIVER)) {
```

分支体内解析段保持不变，末尾分发改为：

```cpp
        if (code == static_cast<uint32_t>(CM_MSG_OPEN_UKEY_AUTH_DIALOG_FOR_DRIVER)) {
            CmIpcServiceOpenUkeyAuthDialogForDriver(code, &openSrcData,
                reinterpret_cast<const struct CmContext *>(&reply), remoteCallback);
        } else {
            CmIpcServiceOpenUkeyAuthDialog(code, &openSrcData,
                reinterpret_cast<const struct CmContext *>(&reply), remoteCallback);
        }
```

同时把上文 `outSize` 跳过列表（`code != ...` 条件链）追加 `code != static_cast<uint32_t>(CM_MSG_OPEN_UKEY_AUTH_DIALOG_FOR_DRIVER) &&`。

- [ ] **Step 6: SA IPC 处理器**

6a. `cm_ukey_auth_dialog_ipc_service.h` 增声明：

```cpp
void CmIpcServiceOpenUkeyAuthDialogForDriver(uint32_t code, const struct CmBlob *paramSetBlob,
    const struct CmContext *context, const sptr<IRemoteObject> &clientCallback);
```

6b. `cm_ukey_auth_dialog_ipc_service.cpp`（`CmIpcServiceOpenUkeyAuthDialog` 之后）：

```cpp
void CmIpcServiceOpenUkeyAuthDialogForDriver(uint32_t code, const struct CmBlob *paramSetBlob,
    const struct CmContext *context, const sptr<IRemoteObject> &clientCallback)
{
    (void)code;
    struct CmParamSet *paramSet = nullptr;
    struct CmBlob abilityName = { 0, nullptr };
    uint32_t abilityType = CM_UKEY_ABILITY_TYPE_UIABILITY;
    struct CmBlob keyUri = { 0, nullptr };
    uint32_t timeoutMs = 0;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &abilityName },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = &abilityType },
        { .tag = CM_TAG_PARAM2_BUFFER, .blob = &keyUri },
        { .tag = CM_TAG_PARAM3_UINT32, .uint32Param = &timeoutMs },
    };
    int32_t ret = CmGetParamSet(reinterpret_cast<struct CmParamSet *>(paramSetBlob->data),
        paramSetBlob->size, &paramSet);
    if (ret == CM_SUCCESS) {
        ret = CmParamSetToParams(paramSet, params, CM_ARRAY_SIZE(params));
    }
    struct CmBlob customData = { 0, nullptr };
    if (ret == CM_SUCCESS) {
        struct CmParam *customDataParam = nullptr;
        if (CmGetParam(paramSet, CM_TAG_PARAM4_BUFFER, &customDataParam) == CM_SUCCESS) {
            customData = customDataParam->blob;
        }
    }
    if (ret != CM_SUCCESS) {
        CM_LOG_E("open driver dialog get params failed, ret = %d", ret);
        CmFreeParamSet(&paramSet);
        CmSendResponse(context, CMR_ERROR_INVALID_ARGUMENT, NULL);
        return;
    }

    /* 服务端权限校验（spec v4 D23：NAPI 预检之外的纵深防御） */
    if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(),
        "ohos.permission.CRYPTO_EXTENSION_REGISTER") != PERMISSION_GRANTED) {
        CM_LOG_E("open driver dialog permission denied");
        CmFreeParamSet(&paramSet);
        CmSendResponse(context, CMR_DIALOG_ERROR_PERMISSION_DENIED, NULL);
        return;
    }
    /* 调用方包名：仅 HAP token 放行（bundle 只能来自 IPC token，客户端不可声明，D20/D23） */
    HapTokenInfo hapInfo;
    if (AccessTokenKit::GetHapTokenInfo(IPCSkeleton::GetCallingTokenID(), hapInfo) != ERR_OK) {
        CM_LOG_E("open driver dialog caller is not hap token, callingUid = %d",
            static_cast<int32_t>(IPCSkeleton::GetCallingUid()));
        CmFreeParamSet(&paramSet);
        CmSendResponse(context, CMR_DIALOG_ERROR_INTERNAL, NULL);
        return;
    }

    CmUkeyAuthDialogManager::GetInstance().InitRealDependencies();
    /* abilityName/keyUri/customData 指向 paramSet 缓冲，OpenDriverDialog 同步消费后不再引用 */
    ret = CmUkeyAuthDialogManager::GetInstance().OpenDriverDialog(&abilityName, abilityType,
        &keyUri, static_cast<uint32_t>(IPCSkeleton::GetCallingUid()), hapInfo.bundleName,
        timeoutMs, &customData, clientCallback);
    CmFreeParamSet(&paramSet);
    CmSendResponse(context, ret, NULL);
}
```

（文件头补 `#include "cm_ukey_ability_type.h"` 若经 include 链不可达。）

- [ ] **Step 7: 单测 token 权限 + ForDriver 探针**

7a. `cm_test_common.cpp` PERMISSION_LIST（line 74-79）追加一项：

```cpp
    "ohos.permission.CRYPTO_EXTENSION_REGISTER"
```

7b. `cm_ukey_auth_dialog_real_ipc_test.cpp` 新增探针（沿用本文件既有 MockNativeToken/探针写法；无权限路径用不 mock 的 shell 身份）：

```cpp
/* ForDriver：持有 CRYPTO_EXTENSION_REGISTER 的 nativetoken 到达 SA——
 * 真实 BMS 校验（cmtest 进程的 bundle 无该扩展）→ 同步 -1019 */
HWTEST_F(CmUkeyDialogRealIpcTest, OpenDriverDialogRealIpcProbe, testing::ext::TestSize.Level0)
{
    CmTestCommon::MockNativeToken mockToken("cert_manager_service"); /* 授 CRYPTO_EXTENSION_REGISTER */
    const char *abilityName = "MyUkeyAuthExtensionAbility";
    struct UkeyAuthDialogInfo dialogInfo = {
        .abilityName = { strlen(abilityName) + 1,
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(abilityName)) },
        .abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION,
    };
    struct UkeyAuthRequest request = {};
    const char *uri = "ukey://test/for-driver";
    request.keyUri = { strlen(uri), const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(uri)) };
    int32_t ret = CmOpenUkeyAuthDialogForDriver(&dialogInfo, &request,
        [](int32_t code, void *data) {
            auto *fired = static_cast<std::atomic<int32_t> *>(data);
            fired->store(code);
        }, &g_driverProbeFired);
    EXPECT_TRUE(ret == CMR_DIALOG_ERROR_NOT_REGISTERED || ret == CMR_DIALOG_ERROR_NOT_PC_DEVICE)
        << "ret = " << ret; /* rk3568 非 PC 时 -1020 先于 BMS 命中，两者皆证明链路通 */
}

/* ForDriver：无权限身份 → 同步 -1011（201） */
HWTEST_F(CmUkeyDialogRealIpcTest, OpenDriverDialogNoPermissionProbe, testing::ext::TestSize.Level0)
{
    /* 不 mock token：shell 身份无 CRYPTO_EXTENSION_REGISTER */
    const char *abilityName = "MyUkeyAuthExtensionAbility";
    struct UkeyAuthDialogInfo dialogInfo = {
        .abilityName = { strlen(abilityName) + 1,
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(abilityName)) },
        .abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION,
    };
    struct UkeyAuthRequest request = {};
    const char *uri = "ukey://test/for-driver-noperm";
    request.keyUri = { strlen(uri), const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(uri)) };
    int32_t ret = CmOpenUkeyAuthDialogForDriver(&dialogInfo, &request, nullptr, nullptr);
    EXPECT_EQ(ret, CMR_DIALOG_ERROR_PERMISSION_DENIED);
}
```

（`g_driverProbeFired` 为文件级 `static std::atomic<int32_t>`；两个用例的写法对齐文件内既有探针的 lambda/callback 风格——若既有探针用独立静态函数则照其风格调整，语义不变。注意 mock token 的 process 名参数按文件内既有用法填写。）

- [ ] **Step 8: 新 fuzzer**

照抄 `test/fuzz_test/cmopenukeyauthdialog_fuzzer/` 目录（`cmopenauthdialogforukeydriver_fuzzer.cpp` + `BUILD.gn` + 空 `corpus/`），fuzz 布局改为：

```cpp
        /* fuzz layout: [4B abilityType][4B timeout][rest: abilityName + keyUri + customData bytes] */
        uint32_t abilityType = 0;
        uint32_t timeout = 0;
        // …（照抄既有 fuzzer 的 memcpy_s 模式解出前 8 字节）
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
        (void)CmOpenUkeyAuthDialogForDriver(&dialogInfo, &ukeyAuthRequest, DummyCallback, nullptr);
```

（`DummyCallback` 照抄既有 fuzzer 的空回调；abilityNameSize/keyUriSize 用模糊前缀切分，同既有 keyUri/customData 切分逻辑。）

- [ ] **Step 9: 编译**

Run: `./build.sh --product-name rk3568 --build-target certificate_manager --build-target cm_sdk_test --keep-ninja-going 2>&1 | grep -E "OHOS ERROR|FAILED|build  successful" | head -5`
Expected: `=====build  successful=====`

- [ ] **Step 10: Commit**

```bash
git add -A && git commit -s -m "feat: add openauthdialogforukeydriver inner api and ipc channel"
```

---

### Task 3: NAPI openAuthDialogForUkeyDriver

**Files:**
- Modify: `interfaces/kits/napi/include/dialog/cm_napi_open_ukey_auth_dialog.h`
- Modify: `interfaces/kits/napi/src/dialog/cm_napi_open_ukey_auth_dialog.cpp`
- Modify: `interfaces/kits/napi/src/dialog/cm_napi_dialog.cpp`（注册表 line ~114）

**Interfaces:**
- Consumes: Task 2 的 `CmOpenUkeyAuthDialogForDriver`；既有 `GetUkeyAuthRequest`（request 解析，过渡期容忍 scene 字段被忽略，Task 6 删除）
- Produces: JS `openAuthDialogForUkeyDriver(dialogInfo: UkeyAuthDialogInfo, ukeyAuthRequest: UkeyAuthRequest): Promise<void>`

- [ ] **Step 1: 头文件声明**

`cm_napi_open_ukey_auth_dialog.h`：

```cpp
napi_value CMNapiOpenAuthDialogForUkeyDriver(napi_env env, napi_callback_info info);
```

- [ ] **Step 2: 实现**

`cm_napi_open_ukey_auth_dialog.cpp` 末尾新增（权限预检模式照抄 `cm_napi_dialog_common.cpp` 的 `CheckBasicPermission`；权限常量与 401/201 语义见 spec D23）：

```cpp
/* CRYPTO_EXTENSION_REGISTER 进程内预检（spec v4 D23：失败同步 201） */
static bool CheckUkeyDriverPermission(void)
{
    AccessTokenID tokenId = OHOS::IPCSkeleton::GetCallingTokenID();
    return OHOS::Security::AccessToken::AccessTokenKit::VerifyAccessToken(
        tokenId, "ohos.permission.CRYPTO_EXTENSION_REGISTER") == 0 /* PERMISSION_GRANTED */;
}

/* ForDriver 的 SA 路径 promise 包装：错误码不折叠（29700009/29700010 直通，D8 v4） */
static napi_value OpenAuthDialogForUkeyDriverViaSa(
    std::shared_ptr<CmUIExtensionRequestContext> asyncContext,
    OHOS::Security::CertManager::CmMetricsReport &&report, std::string abilityName,
    uint32_t abilityType)
{
    napi_env env = asyncContext->env;
    napi_value result = nullptr;
    napi_deferred deferred = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &result));

    auto resultContext = new (std::nothrow) CmUkeyAuthResultContext();
    if (resultContext == nullptr) {
        CM_LOG_E("alloc ukey auth result context failed");
        napi_value error = GenerateBusinessError(env, DIALOG_ERROR_GENERIC, &report);
        NAPI_CALL(env, napi_reject_deferred(env, deferred, error));
        return result;
    }
    resultContext->env = env;
    resultContext->deferred = deferred;
    resultContext->legacyOverload = false; /* ForDriver：专属码直通 */
    resultContext->metricsReport =
        std::make_shared<OHOS::Security::CertManager::CmMetricsReport>(std::move(report));

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, "CmUkeyAuthDialogResult", NAPI_AUTO_LENGTH,
        &resourceName));
    napi_status status = napi_create_threadsafe_function(env, nullptr, nullptr, resourceName, 0, 1,
        resultContext, UvTsfnFinalize, resultContext, UvTsfnCallback, &resultContext->tsfn);
    if (status != napi_ok) {
        CM_LOG_E("create threadsafe function failed, status = %d", static_cast<int32_t>(status));
        napi_value error = GenerateBusinessError(env, DIALOG_ERROR_GENERIC,
            resultContext->metricsReport.get());
        NAPI_CALL(env, napi_reject_deferred(env, deferred, error));
        delete resultContext;
        return result;
    }

    struct UkeyAuthDialogInfo dialogInfo = {};
    dialogInfo.abilityName.size = static_cast<uint32_t>(abilityName.size() + 1); /* 含 NUL */
    dialogInfo.abilityName.data = reinterpret_cast<uint8_t *>(const_cast<char *>(abilityName.c_str()));
    dialogInfo.abilityType = abilityType;
    struct UkeyAuthRequest ukeyAuthRequest = {};
    ukeyAuthRequest.keyUri.size = asyncContext->certUri->size;
    ukeyAuthRequest.keyUri.data = asyncContext->certUri->data;
    ukeyAuthRequest.timeoutDuration = asyncContext->authTimeoutMs;
    if (asyncContext->authCustomData != nullptr) {
        ukeyAuthRequest.customData.size = asyncContext->authCustomData->size;
        ukeyAuthRequest.customData.data = asyncContext->authCustomData->data;
    }
    int32_t ret = CmOpenUkeyAuthDialogForDriver(&dialogInfo, &ukeyAuthRequest,
        UkeyAuthDialogResultCallback, resultContext);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("open auth dialog for ukey driver failed, ret = %d", ret);
        napi_value error = GenerateBusinessError(env, ret, resultContext->metricsReport.get());
        NAPI_CALL(env, napi_reject_deferred(env, deferred, error));
        napi_release_threadsafe_function(resultContext->tsfn, napi_tsfn_release);
        return result;
    }
    return result;
}

/* UkeyAuthDialogInfo 解析（spec v4 D23/D24）：abilityType 必为 1（否则 401），
 * abilityName 非空字符串 ≤128 字节（否则 29700006） */
static bool GetUkeyDialogInfo(napi_env env, napi_value arg, uint32_t &abilityType,
    std::string &abilityName)
{
    napi_valuetype type = napi_undefined;
    if (napi_typeof(env, arg, &type) != napi_ok || type != napi_object) {
        return false;
    }
    napi_value abilityTypeValue = nullptr;
    if (napi_get_named_property(env, arg, "abilityType", &abilityTypeValue) != napi_ok ||
        abilityTypeValue == nullptr) {
        return false;
    }
    napi_valuetype abilityTypeType = napi_undefined;
    if (napi_typeof(env, abilityTypeValue, &abilityTypeType) != napi_ok ||
        abilityTypeType != napi_number) {
        return false;
    }
    double abilityTypeDouble = 0;
    if (napi_get_value_double(env, abilityTypeValue, &abilityTypeDouble) != napi_ok ||
        abilityTypeDouble != CM_UKEY_ABILITY_TYPE_UIEXTENSION) { /* 枚举唯一合法值 = 1 */
        return false;
    }
    abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION;

    napi_value abilityNameValue = nullptr;
    if (napi_get_named_property(env, arg, "abilityName", &abilityNameValue) != napi_ok ||
        abilityNameValue == nullptr) {
        return false;
    }
    napi_valuetype abilityNameType = napi_undefined;
    if (napi_typeof(env, abilityNameValue, &abilityNameType) != napi_ok ||
        abilityNameType != napi_string) {
        return false;
    }
    char nameBuf[CM_UKEY_ABILITY_NAME_MAX_LEN + 1] = { 0 };
    size_t copied = 0;
    if (napi_get_value_string_utf8(env, abilityNameValue, nameBuf, sizeof(nameBuf), &copied)
        != napi_ok || copied == 0) {
        return false;
    }
    abilityName.assign(nameBuf, copied);
    return true;
}

napi_value CMNapiOpenAuthDialogForUkeyDriver(napi_env env, napi_callback_info info)
{
    CM_LOG_I("cert open auth dialog for ukey driver enter");
    OHOS::Security::CertManager::CmMetricsReport report("openAuthDialogForUkeyDriver",
        OHOS::Security::CertManager::CmMetricsKind::DIALOG);
    report.Start();
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    if (CheckSyscapReturnVoid(env, &result) != CM_SUCCESS) {
        report.Finish(DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED);
        return result;
    }
    size_t argc = PARAM_SIZE_TWO;
    napi_value argv[PARAM_SIZE_TWO] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != PARAM_SIZE_TWO) {
        ThrowError(env, PARAM_ERROR, "Parameter Error. Params number mismatch, need 2", &report);
        return result;
    }
    uint32_t abilityType = 0;
    std::string abilityName;
    if (!GetUkeyDialogInfo(env, argv[0], abilityType, abilityName)) {
        CM_LOG_E("parse UkeyAuthDialogInfo failed");
        ThrowError(env, PARAM_ERROR, "parse UkeyAuthDialogInfo failed", &report);
        return result;
    }
    auto asyncContext = std::make_shared<CmUIExtensionRequestContext>(env);
    if (IsParamNull(env, argv[1])) {
        ThrowError(env, PARAM_ERROR, "UkeyAuthRequest is null", &report);
        return result;
    }
    if (GetUkeyAuthRequest(asyncContext, argv[1]) == nullptr) {
        CM_LOG_E("parse UkeyAuthRequest failed");
        ThrowError(env, DIALOG_ERROR_PARAMETER_VALIDATION_FAILED, "parse UkeyAuthRequest failed",
            &report);
        return result;
    }
    if (!CheckUkeyDriverPermission()) {
        CM_LOG_E("caller has no CRYPTO_EXTENSION_REGISTER permission");
        ThrowError(env, HAS_NO_PERMISSION, DIALOG_NO_PERMISSION_MSG, &report);
        return result;
    }
    return OpenAuthDialogForUkeyDriverViaSa(asyncContext, std::move(report),
        std::move(abilityName), abilityType);
}
```

配套：
- 文件头 include 增加 `#include "accesstoken_kit.h"`（若 `cm_napi_dialog_common.h` 未传递）；
- `CM_UKEY_ABILITY_NAME_MAX_LEN` 常量：加到 `frameworks/cert_manager_standard/main/common/include/cm_ukey_dialog_common.h`（PC 参数区块附近）：`constexpr uint32_t CM_UKEY_ABILITY_NAME_MAX_LEN = 128;`
- `ThrowError` / `IsParamNull` / `CheckSyscapReturnVoid` / `GenerateBusinessError` / `UvTsfn*` / `UkeyAuthDialogResultCallback` / `CmUkeyAuthResultContext` 均为本文件或 `cm_napi_dialog_common` 既有符号，直接复用。

- [ ] **Step 3: 注册**

`cm_napi_dialog.cpp` 注册表（line ~114 `openUkeyAuthDialog` 条目之后）：

```cpp
        DECLARE_NAPI_FUNCTION("openAuthDialogForUkeyDriver", CMNapiOpenAuthDialogForUkeyDriver),
```

（同时确认该文件头部已 include `cm_napi_open_ukey_auth_dialog.h`，新声明在其中可见。）

- [ ] **Step 4: 编译**

Run: `./build.sh --product-name rk3568 --build-target certmanager --build-target certificate_manager --keep-ninja-going 2>&1 | grep -E "OHOS ERROR|FAILED|build  successful" | head -5`
Expected: `=====build  successful=====`

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -s -m "feat: add napi openauthdialogforukeydriver"
```

---

### Task 4: ANI openAuthDialogForUkeyDriver

**Files:**
- Create: `interfaces/kits/ani/certificate_manager_dialog_ani/include/cm_open_auth_dialog_for_ukey_driver.h`
- Create: `interfaces/kits/ani/certificate_manager_dialog_ani/src/cm_open_auth_dialog_for_ukey_driver.cpp`
- Modify: `interfaces/kits/ani/certificate_manager_dialog_ani/src/cm_dialog_ani.cpp`
- Modify: `interfaces/kits/ani/certificate_manager_dialog_ani/BUILD.gn`（sources 列表）
- Modify: `interfaces/kits/ani/certificate_manager_dialog_ani/ets/@ohos.security.certManagerDialog.ets`

**Interfaces:**
- Consumes: Task 2 的 `CmOpenUkeyAuthDialogForDriver`；ANI 基建 `CertManagerAsyncImpl`/`AniUtils`
- Produces: native `openAuthDialogForUkeyDriverNative`（ets 声明与注册）

- [ ] **Step 1: 新类头文件**（`cm_open_auth_dialog_for_ukey_driver.h`，类骨架照抄 `cm_open_ukey_auth_dialog_no_context.h`，去 scene 增 abilityName/abilityType）：

```cpp
#ifndef CM_OPEN_AUTH_DIALOG_FOR_UKEY_DRIVER_H
#define CM_OPEN_AUTH_DIALOG_FOR_UKEY_DRIVER_H
/* Apache-2.0 头（复制 cm_open_ukey_auth_dialog_no_context.h） */
#include "cm_ani_utils.h"
#include "cm_ani_common.h"
#include "cm_ukey_dialog_common.h"

namespace OHOS::Security::CertManager::Ani {
class CmOpenAuthDialogForUkeyDriver : public CertManagerAsyncImpl {
public:
    CmOpenAuthDialogForUkeyDriver(ani_env *env, ani_string aniAbilityName, ani_double aniAbilityType,
        ani_string aniKeyUri, ani_double aniTimeout, ani_object aniCustomData, ani_object callback);
    ~CmOpenAuthDialogForUkeyDriver() override = default;
private:
    int32_t GetParamsFromEnv() override;
    int32_t InvokeAsyncWork() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
    ani_string aniAbilityName = nullptr;
    ani_double aniAbilityType = 0;
    ani_string aniKeyUri = nullptr;
    ani_double aniTimeout = 0;
    ani_object aniCustomData = nullptr;
    CmBlob abilityName = { 0, nullptr };
    uint32_t abilityType = 0;
    CmBlob keyUri = { 0, nullptr };
    uint32_t timeoutMs = 0;
    CmBlob customData = { 0, nullptr };
};
} // namespace OHOS::Security::CertManager::Ani
#endif
```

（基类构造与虚函数签名以 `cm_open_ukey_auth_dialog_no_context.h` 实际为准逐字对齐；`CertManagerAsyncImpl` 若为共有继承 + override 形式则照抄其声明结构。）

- [ ] **Step 2: 新类实现**（`cm_open_auth_dialog_for_ukey_driver.cpp`，主体照抄 `cm_open_ukey_auth_dialog_no_context.cpp`，差异点如下）：

```cpp
CmOpenAuthDialogForUkeyDriver::CmOpenAuthDialogForUkeyDriver(ani_env *env,
    ani_string aniAbilityName, ani_double aniAbilityType, ani_string aniKeyUri,
    ani_double aniTimeout, ani_object aniCustomData, ani_object callback)
    : CertManagerAsyncImpl(env, nullptr, callback, "openAuthDialogForUkeyDriver")
{
    this->aniAbilityName = aniAbilityName;
    this->aniAbilityType = aniAbilityType;
    this->aniKeyUri = aniKeyUri;
    this->aniTimeout = aniTimeout;
    this->aniCustomData = aniCustomData;
}

int32_t CmOpenAuthDialogForUkeyDriver::GetParamsFromEnv()
{
    /* abilityName：非空、≤128 字节（blob 含结尾 NUL，size 1 视为空） */
    int32_t ret = AniUtils::ParseString(env, this->aniAbilityName, this->abilityName);
    if (ret != CM_SUCCESS || this->abilityName.size <= 1 ||
        this->abilityName.size > CM_UKEY_ABILITY_NAME_MAX_LEN + 1) {
        CM_LOG_E("invalid driver dialog ability name, ret = %d", ret);
        CM_FREE_BLOB(this->abilityName);
        return CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED;
    }
    /* abilityType：枚举唯一合法值 = 1（UKEY_AUTH_EXTENSION_ABILITY），其余 401 语义 */
    if (this->aniAbilityType != CM_UKEY_ABILITY_TYPE_UIEXTENSION) {
        CM_LOG_E("invalid driver dialog ability type");
        return CMR_DIALOG_ERROR_PARAM_INVALID;
    }
    this->abilityType = CM_UKEY_ABILITY_TYPE_UIEXTENSION;
    /* keyUri / timeout / customData / globalCallback：逐段照抄 no_context 的
     * GetParamsFromEnv 对应校验（keyUri 空/超长、timeout 负值/超界、customData
     * Uint8Array ≤2048、GlobalReference_Create），仅去掉 scene 段 */
    /* ……（照抄，见 cm_open_ukey_auth_dialog_no_context.cpp:85-150 的 keyUri/timeout/
     *      customData/globalCallback 四段） */
    return CM_SUCCESS;
}

int32_t CmOpenAuthDialogForUkeyDriver::InvokeAsyncWork()
{
    /* 照抄 no_context 的 InvokeAsyncWork（resultContext 分配 + tsfn 回调桥），
     * 差异：legacyOverload 固定 false；组包改为 */
    struct UkeyAuthDialogInfo dialogInfo = {};
    dialogInfo.abilityName = this->abilityName;
    dialogInfo.abilityType = this->abilityType;
    struct UkeyAuthRequest ukeyAuthRequest = {};
    ukeyAuthRequest.keyUri.data = this->keyUri.data;
    ukeyAuthRequest.keyUri.size = this->keyUri.size;
    ukeyAuthRequest.timeoutDuration = this->timeoutMs;
    ukeyAuthRequest.customData = this->customData;
    int32_t ret = CmOpenUkeyAuthDialogForDriver(&dialogInfo, &ukeyAuthRequest,
        UkeyAuthDialogResultCallback, resultContext);
    /* 失败路径照抄（delete resultContext + return ret） */
}

int32_t CmOpenAuthDialogForUkeyDriver::UnpackResult()
{
    return CM_SUCCESS;
}

void CmOpenAuthDialogForUkeyDriver::OnFinish()
{
    /* 照抄 no_context 的 OnFinish（keyUri/customData 释放 + customData memset_s），增加 */
    CM_FREE_BLOB(this->abilityName);
}
```

（文件内 `UkeyAuthDialogResultCallback` C 回调函数：照抄 no_context 版本，但去掉 `IsLegacyFoldCode`/`TransformLegacyFoldCode` 的 legacy 分支——ForDriver 恒走 `GetDialogAniErrorResult(env, resultCode)` 直通路径。）

- [ ] **Step 3: native 注册**

`cm_dialog_ani.cpp`：

3a. include 区去掉 `#include "cm_open_ukey_auth_dialog_no_context.h"`？**保留**（Task 6 前仍被 with-context 路由引用）；追加：

```cpp
#include "cm_open_auth_dialog_for_ukey_driver.h"
```

3b. `openUkeyAuthDialogNoContextNative` 函数之后新增：

```cpp
ani_object openAuthDialogForUkeyDriverNative(ani_env *env, ani_string abilityName,
    ani_double abilityType, ani_string keyUri, ani_double timeout, ani_object customData,
    ani_object callback)
{
    if (env == nullptr) {
        CM_LOG_E("check env is nullptr.");
        return nullptr;
    }
    if (!IsSupportDialogSyscap()) {
        CM_LOG_E("check syscap is not supported.");
        return InvokeCallbackVoid(env, callback);
    }
    auto impl = std::make_shared<CmOpenAuthDialogForUkeyDriver>(env, abilityName, abilityType,
        keyUri, timeout, customData, callback);
    return impl->Invoke();
}
```

3c. `ANI_Constructor` 的 methods 数组（`openUkeyAuthDialogNoContextNative` 条目后）追加：

```cpp
        ani_native_function {"openAuthDialogForUkeyDriverNative", nullptr,
            reinterpret_cast<void *>(OHOS::Security::CertManager::Ani::openAuthDialogForUkeyDriverNative)},
```

- [ ] **Step 4: BUILD.gn + ets**

4a. ani 模块 `BUILD.gn` sources 列表追加 `"src/cm_open_auth_dialog_for_ukey_driver.cpp",`。

4b. ets（`@ohos.security.certManagerDialog.ets`）：native 声明区（`openUkeyAuthDialogNoContextNative` 之后）：

```ts
native function openAuthDialogForUkeyDriverNative(
  abilityName: string,
  abilityType: number,
  keyUri: string,
  timeout: number,
  customData: Uint8Array,
  callback: AsyncCallbackWrapper<void>
): NativeResult<void>;
```

namespace 导出区（`openUkeyAuthDialog` 无 context 重载之后、`supportsCACertDialog` 之前）：

```ts
  export function openAuthDialogForUkeyDriver(dialogInfo: UkeyAuthDialogInfo,
    ukeyAuthRequest: UkeyAuthRequest): Promise<void> {
    return new Promise<void>((resolve, reject: (error: BusinessError) => void) => {
        let callback = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
            if (err?.code !== 0) {
                reject(err as BusinessError);
            } else {
                resolve(undefined);
            }
        });

        let abilityName: string = dialogInfo.abilityName;
        let abilityType: number = dialogInfo.abilityType;
        if (abilityName === undefined || abilityName === '' || abilityType === undefined) {
            let error = new BusinessError();
            error.code = 401;
            error.message = 'the input parameters is invalid.';
            throw error;
        }
        let keyUri: string = ukeyAuthRequest.keyUri;
        if (keyUri === undefined || keyUri === '') {
            let error = new BusinessError();
            error.code = 401;
            error.message = 'the input parameters is invalid.';
            throw error;
        }
        let timeout: number = ukeyAuthRequest.timeoutDuration ?? 0; /* 0 = server default 300s */
        let customData: Uint8Array = ukeyAuthRequest.customData ?? new Uint8Array(0);
        let result: NativeResult<void> = openAuthDialogForUkeyDriverNative(abilityName,
            abilityType, keyUri, timeout, customData, callback);
        if (result.code !== 0) {
            let err = new BusinessError();
            err.code = result.code;
            err.message = result.message;
            reject(err);
        }
    });
  }
```

同文件枚举/接口声明区（`UkeyAuthScene` 枚举之后）新增（Task 6 会删 UkeyAuthScene，二者无依赖冲突）：

```ts
  export enum AbilityType {
    UKEY_AUTH_EXTENSION_ABILITY = 1
  }

  export interface UkeyAuthDialogInfo {
    abilityType: AbilityType;
    abilityName: string;
  }
```

（ts2ets 侧 number/enum 兼容性：native 形参为 number，ets 传 `AbilityType` 枚举值可隐式转 number；若编译器报类型错，则包装处显式 `let abilityType: number = dialogInfo.abilityType as number;`。）

- [ ] **Step 5: 编译**

Run: `./build.sh --product-name rk3568 --build-target certmanager_dialog_ani --keep-ninja-going 2>&1 | grep -E "OHOS ERROR|FAILED|build  successful" | head -5`
Expected: `=====build  successful=====`

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -s -m "feat: add ani openauthdialogforukeydriver"
```

---

### Task 5: d.ts en/zh 新增（interface_sdk-js 仓）

**Files:**
- Modify: `interface/sdk-js/api/@ohos.security.certManagerDialog.d.ts`
- Modify: `interface/sdk-js/zh-cn/api/@ohos.security.certManagerDialog.d.ts`

**Interfaces:** Produces: 公开面 `AbilityType` / `UkeyAuthDialogInfo` / `openAuthDialogForUkeyDriver`（en/zh 语义一致）

- [ ] **Step 1: en 侧新增**

在 `UkeyAuthRequest` interface 之后、`supportsCACertDialog` 之前插入（en）：

```ts
  /**
   * Enumerates the types of the UKey PIN dialog ability. Currently only the
   * UIExtensionAbility type is supported.
   *
   * @syscap SystemCapability.Security.CertificateManagerDialog
   * @stagemodelonly
   * @since 26.0.0 dynamic&static
   */
  export enum AbilityType {
    /**
     * UKey PIN dialog extension ability (UIExtensionAbility, ukeyAuth type).
     *
     * @syscap SystemCapability.Security.CertificateManagerDialog
     * @stagemodelonly
     * @since 26.0.0 dynamic&static
     */
    UKEY_AUTH_EXTENSION_ABILITY = 1
  }

  /**
   * Defines the information of the UKey driver's own PIN dialog ability to launch.
   *
   * @syscap SystemCapability.Security.CertificateManagerDialog
   * @stagemodelonly
   * @since 26.0.0 dynamic&static
   */
  export interface UkeyAuthDialogInfo {
    /**
     * Type of the PIN dialog ability. Only
     * **AbilityType.UKEY_AUTH_EXTENSION_ABILITY** is supported; other values
     * result in error 401.
     *
     * @syscap SystemCapability.Security.CertificateManagerDialog
     * @stagemodelonly
     * @since 26.0.0 dynamic&static
     */
    abilityType: AbilityType;

    /**
     * Ability name of the driver's own UKey PIN dialog UIExtensionAbility. The
     * bundle is resolved from the caller identity on the service side, so the
     * ability must be declared within the caller's own bundle. Non-empty, up to
     * 128 bytes.
     *
     * @syscap SystemCapability.Security.CertificateManagerDialog
     * @stagemodelonly
     * @since 26.0.0 dynamic&static
     */
    abilityName: string;
  }

  /**
   * Opens the UKey driver's own PIN authentication dialog (UIExtensionAbility).
   * Only the UKey driver application holding the required permission can call
   * this API; the dialog ability is resolved within the caller's own bundle and
   * verified by the service before being displayed as a modal system dialog
   * (PC or PC mode only). This API uses a promise to return the result.
   *
   * @permission ohos.permission.CRYPTO_EXTENSION_REGISTER
   * @param { UkeyAuthDialogInfo } dialogInfo - Information of the dialog ability to launch.
   * @param { UkeyAuthRequest } ukeyAuthRequest - Authentication request information.
   * @returns { Promise<void> } Promise that returns no value.
   * @throws { BusinessError } 201 - Permission verification failed. The application does not
   *     have the permission required to call the API.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters
   *     are left unspecified; 2. Incorrect parameter types; 3. **abilityType** is not
   *     **AbilityType.UKEY_AUTH_EXTENSION_ABILITY**.
   * @throws { BusinessError } 29700001 - Internal error. Possible causes: 1. IPC communication
   *     failed; 2. Memory operation error; 3. File operation error.
   * @throws { BusinessError } 29700002 - The user cancels the authentication operation.
   * @throws { BusinessError } 29700003 - The authentication operation failed, such as the
   *     specified ability does not exist in the caller's bundle or is not a UKey PIN dialog
   *     extension, or another UKey PIN authentication dialog is already in progress.
   * @throws { BusinessError } 29700005 - The operation does not comply with the device
   *     security policy, such as the API is called on a device that is neither a PC nor
   *     in PC mode.
   * @throws { BusinessError } 29700006 - Indicates that the input parameters validation failed.
   * @throws { BusinessError } 29700009 - The UKey driver's PIN dialog did not report the
   *     authentication result within the timeout.
   * @throws { BusinessError } 29700010 - Another UKey PIN authentication dialog is already
   *     in progress.
   * @syscap SystemCapability.Security.CertificateManagerDialog
   * @stagemodelonly
   * @since 26.0.0 dynamic&static
   */
  function openAuthDialogForUkeyDriver(dialogInfo: UkeyAuthDialogInfo,
    ukeyAuthRequest: UkeyAuthRequest): Promise<void>;
```

- [ ] **Step 2: zh-cn 侧同步**

`zh-cn/api/` 同文件做逐段中文镜像（文案风格照抄该文件既有中文注释；29700009/29700010 等错误描述措辞与文件内既有条目保持一致）。

- [ ] **Step 3: Commit**（interface_sdk-js 仓）

```bash
git add api/@ohos.security.certManagerDialog.d.ts zh-cn/api/@ohos.security.certManagerDialog.d.ts && git commit -s -m "feat: add openauthdialogforukeydriver declaration"
```

---

### Task 6: v4 收敛原子重构（CM 仓，一次提交保持编译绿）

> scene 字段删除牵动 innerkit/IPC/SA/NAPI/ANI/tests 全链路，必须原子完成。本 Task 每个 Step 是一个文件的修改，Step 末统一编译。

**Files:**
- Modify: `interfaces/innerkits/cert_manager_standard/main/include/cm_type.h`
- Modify: `frameworks/cert_manager_standard/main/common/include/cm_ukey_dialog_common.h`
- Modify: `frameworks/cert_manager_standard/main/common/include/cm_ukey_ability_type.h`（注释刷新）
- Modify: `frameworks/cert_manager_standard/main/os_dependency/cm_ipc/src/cm_ipc_dialog_client.cpp`
- Modify: `services/.../idl/cm_ipc/cm_ukey_auth_dialog_ipc_service.cpp`
- Modify: `services/.../os_dependency/dialog/cm_ukey_auth_dialog_manager.h` 与 `.cpp`
- Modify: `interfaces/kits/common/include/cm_dialog_api_common.h` 与 `../src/cm_dialog_api_common.cpp`
- Modify: `interfaces/kits/napi/src/dialog/cm_napi_open_ukey_auth_dialog.cpp`（+ `cm_napi_dialog_common.*` 的 context 字段）
- Modify/Rename: `interfaces/kits/ani/certificate_manager_dialog_ani/{include,src}/cm_open_ukey_auth_dialog_no_context.*` → `cm_open_ukey_auth_dialog_sa_session.*`
- Modify: `interfaces/kits/ani/certificate_manager_dialog_ani/src/cm_open_ukey_auth_dialog.cpp`、`cm_dialog_ani.cpp`、`BUILD.gn`、`ets/@ohos.security.certManagerDialog.ets`
- Modify: `test/unittest/src/cm_ukey_auth_dialog_manager_test.cpp`、`cm_ukey_auth_dialog_real_ipc_test.cpp`
- Modify: `test/fuzz_test/cmopenukeyauthdialog_fuzzer/cmopenukeyauthdialog_fuzzer.cpp`、`test/fuzz_test/cmopenauthdialogforukeydriver_fuzzer/cmopenauthdialogforukeydriver_fuzzer.cpp`

- [ ] **Step 1: 类型与共享常量清理**

1a. `cm_type.h`：删除 `enum CmUkeyAuthScene` 整块（line ~570-575）与 `struct UkeyAuthRequest` 的 `uint32_t scene;` 字段行及其注释。

1b. `cm_ukey_dialog_common.h`：
- 删除「场景」区块（`CM_UKEY_SCENE_LOGIN_STR`/`CM_UKEY_SCENE_CUSTOM_STR`/`CmUkeySceneToString`/`CmUkeySceneIsValid`）与 `CM_UKEY_DIALOG_PARAM_SCENE`；
- 删除「系统默认弹框身份」区块（`CM_UKEY_DEFAULT_DIALOG_BUNDLE`/`CM_UKEY_DEFAULT_DIALOG_ABILITY``/CM_UKEY_DEFAULT_DIALOG_EXT_TYPE`）——SA 不再拉默认弹框（D22）；
- 保留 `CM_UKEY_DIALOG_PARAM_CUSTOM_DATA`、PC 判定、`CmBase64Encode`、`CM_UKEY_ABILITY_NAME_MAX_LEN`。

1c. `cm_ukey_ability_type.h`：注释改为「对齐 HUKS HksAbilityInfo.abilityType：0=UIAbility，1=UIExtensionAbility；v4 起 openUkeyAuthDialog 仅放行 1」。

- [ ] **Step 2: IPC 链路去 scene**

2a. `cm_ipc_dialog_client.cpp` `CmClientOpenUkeyAuthDialog`：删 scene 校验块（line ~196-201）与 params 中 `PARAM2_UINT32 scene` 条目，customData 改 `CM_TAG_PARAM2_BUFFER`：

```cpp
    struct CmParam params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = ukeyAuthRequest->keyUri },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = ukeyAuthRequest->timeoutDuration },
        { .tag = CM_TAG_PARAM2_BUFFER, .blob = ukeyAuthRequest->customData },
    };
```

（注释同步：customData 缺省由 NULL-blob 标记转换处理，SA 侧按 PARAM2 缺失解析。）

2b. `cm_ukey_auth_dialog_ipc_service.cpp` OPEN 处理器：params 数组删 scene 条目，customData 改 `CM_TAG_PARAM2_BUFFER`；`OpenDialog` 调用去掉 scene 实参。

- [ ] **Step 3: SA 管理器路由收窄**

`cm_ukey_auth_dialog_manager.cpp`：

3a. 删除 `BuildDefaultDialogParams` 整个函数与 `UkeyAuthSession` 的 `DialogKind` 枚举、`kind`、`scene` 字段（`cm_ukey_auth_dialog_manager.h` 同步）。

3b. `BuildUkeyDialogParams` 签名去 `uint32_t scene`，items/names 数组删 scene 项（`cJSON_CreateString(CmUkeySceneToString(scene))` 与 `CM_UKEY_DIALOG_PARAM_SCENE`）。

3c. `OpenDialog` 签名改 `int32_t OpenDialog(const struct CmBlob *keyUri, uint32_t callerUid, uint32_t timeoutMs, const struct CmBlob *customData, const sptr<IRemoteObject> &clientCallback)`（头文件同步），路由段替换为：

```cpp
    std::string bundleName;
    std::string abilityName;
    uint32_t abilityType = CM_UKEY_ABILITY_TYPE_UIABILITY;
    int32_t queryRet = (querier_ == nullptr) ? CM_FAILURE : querier_(keyUri, bundleName, abilityName, abilityType);
    if (queryRet != CM_SUCCESS) {
        CM_LOG_E("no ukey driver pin dialog registered for the key uri");
        return CMR_DIALOG_ERROR_NOT_REGISTERED;
    }
    if (abilityType == CM_UKEY_ABILITY_TYPE_UIABILITY) {
        CM_LOG_E("ukey driver ability type is UIAbility, not supported");
        return CMR_DIALOG_ERROR_UIABILITY_NOT_SUPPORTED;
    }
    if (abilityType != CM_UKEY_ABILITY_TYPE_UIEXTENSION) {
        CM_LOG_E("unknown ukey ability type: %u", abilityType);
        return CMR_DIALOG_ERROR_INTERNAL;
    }
    /* PC 门禁为竞态防御：Kit 已前置判定，模式翻转时 fail-closed（D25 v2） */
    if (pcChecker_ == nullptr || !pcChecker_()) {
        CM_LOG_E("ukey uiextension dialog requires pc device or pc mode");
        return CMR_DIALOG_ERROR_NOT_PC_DEVICE;
    }
    return LaunchUiExtensionSessionLocked(bundleName, abilityName, keyUri, callerUid,
        effectiveTimeoutMs, customData, clientCallback);
```

（`LaunchUiExtensionSessionLocked` 内 `BuildUkeyDialogParams` 调用去 scene 实参。）

3d. `cm_ukey_auth_dialog_manager.h` 的 `OpenDialog` 注释更新（同步返回值列表去掉 -1019 场景描述差异——-1019 仍在列表，语义为未注册）。

- [ ] **Step 4: kits/common**

`cm_dialog_api_common.h`：

- 删 `UKEY_DEFAULT_NOT_SUPPORTED_MSG`，新增 `UKEY_NOT_REGISTERED_MSG`（"the authentication operation failed: no ukey driver pin dialog is registered for the key uri."）；
- `UKEY_UIABILITY_NOT_SUPPORTED_MSG` 文案改为 "the authentication operation failed: the ukey driver's pin dialog ability is of UIAbility type, which is not supported."（去 no-context 措辞）；
- 两张映射表：`{ CMR_DIALOG_ERROR_NOT_REGISTERED, DIALOG_ERROR_INSTALL_FAILED }` 与 msg 表对应条目（-1019 改名已在 Task 1 完成，此处只换文案）；
- `GetCustomerAuthCertWant` 声明替换为：

```cpp
/* 组装系统默认 UKey Pin 弹框 want（Kit 直启回退路径，spec v4 D22/D25 v2）：
 * com.ohos.certmanager/CertPickerUIExtAbility（sys/commonUI，pageType=7）。
 * customData 不下发（默认弹框无消费方，D18 语义）；调用方记日志丢弃。 */
int32_t GetDefaultUkeyAuthCertWant(const CmBlob *keyUri, OHOS::AAFwk::Want &want);
```

`cm_dialog_api_common.cpp`：

- 删 `GetCustomerAuthCertWant` 整函数与 `QueryAbilityInfo` 的对外暴露（`QueryAbilityInfo` 保留为 `GetUkeyAbilityInfo` 的内部实现）；
- 静态 `GetDefaultAuthCertWant` 提升为公开 `GetDefaultUkeyAuthCertWant`，去 scene 参数与 `SetParam(CM_UKEY_DIALOG_PARAM_SCENE, ...)` 行：

```cpp
int32_t GetDefaultUkeyAuthCertWant(const CmBlob *keyUri, OHOS::AAFwk::Want &want)
{
    want.SetElementName(CERT_MANAGER_BUNDLENAME, CERT_MANAGER_ABILITYNAME);
    want.SetParam(CERT_MANAGER_CALLER_UID, static_cast<int32_t>(getuid()));
    want.SetParam(PARAM_UI_EXTENSION_TYPE, SYS_COMMON_UI);
    want.SetParam(CERT_MANAGER_PAGE_TYPE, static_cast<int32_t>(CmDialogPageType::PAGE_UKEY_PIN_AUTHORIZE));
    std::string uriStr(reinterpret_cast<char *>(keyUri->data), keyUri->size);
    want.SetParam(CERT_MANAGER_CERT_KEY_URI, uriStr);
    return CM_SUCCESS;
}
```

- [ ] **Step 5: NAPI**

`cm_napi_open_ukey_auth_dialog.cpp`：

5a. `CheckUkeyAuthDialogArgc` 只接受 `argc == PARAM_SIZE_TWO`（错误消息改 "need 2"）；主函数删 `argc == PARAM_SIZE_ONE` 分支与 `OpenUkeyAuthDialogNoContext` 的对外双入口语义。

5b. `GetUkeyAuthRequest`：整段删除 scene 解析块（line ~109-142）。

5c. `CmUIExtensionRequestContext`（定义在 `cm_napi_dialog_common.*`）：删 `authScene` 成员；所有引用点删除。

5d. 路由段（原 line ~429-451）替换为：

```cpp
    // argc == PARAM_SIZE_TWO (the only overload, spec v4 D21/D22): branch by the
    // registered ability type — UIExtensionAbility + PC goes to the SA session
    // path; UIExtensionAbility + non-PC falls back to the system default dialog
    // (D25 v2); query failure / UIAbility reject synchronously (29700003).
    {
        std::string driverBundle;
        std::string driverAbility;
        uint32_t abilityType = CM_UKEY_ABILITY_TYPE_UIABILITY;
        int32_t queryRet = GetUkeyAbilityInfo(asyncContext->certUri, driverBundle, driverAbility,
            abilityType);
        if (queryRet != CM_SUCCESS) {
            CM_LOG_E("no ukey driver pin dialog registered");
            ThrowError(env, DIALOG_ERROR_INSTALL_FAILED, UKEY_NOT_REGISTERED_MSG, &report);
            return nullptr;
        }
        if (abilityType == CM_UKEY_ABILITY_TYPE_UIABILITY) {
            CM_LOG_E("ukey driver ability type is UIAbility, not supported");
            ThrowError(env, DIALOG_ERROR_INSTALL_FAILED, UKEY_UIABILITY_NOT_SUPPORTED_MSG, &report);
            return nullptr;
        }
        if (!CmUkeyIsPcOrPcMode()) {
            /* D25 v2：非 PC 回退系统默认弹框（Kit 直启，customData 静默丢弃） */
            CM_LOG_I("non-pc device, fall back to the system default ukey pin dialog");
            if (asyncContext->authCustomData != nullptr && asyncContext->authCustomData->size > 0) {
                CM_LOG_I("custom data dropped for default dialog, size: %u",
                    asyncContext->authCustomData->size);
            }
            NAPI_CALL(env, napi_create_promise(env, &asyncContext->deferred, &result));
            auto reportHolder = std::make_shared<OHOS::Security::CertManager::CmMetricsReport>(std::move(report));
            asyncContext->metricsReport = reportHolder;
            auto uiExtCallback = std::make_shared<CmUIExtensionVoidCallback>(asyncContext);
            OHOS::AAFwk::Want want{};
            if (GetDefaultUkeyAuthCertWant(asyncContext->certUri, want) != CM_SUCCESS) {
                ThrowError(env, DIALOG_ERROR_GENERIC, "get default ukey auth cert want failed.",
                    reportHolder.get());
                return nullptr;
            }
            StartUIExtensionAbility(asyncContext, want, uiExtCallback);
            return result;
        }
        return OpenUkeyAuthDialogNoContext(asyncContext, std::move(report), true);
    }
```

（`OpenUkeyAuthDialogNoContext` 本 Task 保留原名与 `legacyOverload=true` 语义——唯一调用方即老接口，折叠恒生效；其内部 `ukeyAuthRequest.scene = ...` 行删除。`StartUkeyPinAbility` 与 `StartUIAbility` 调用点删除——want 恒无 action，直接 `StartUIExtensionAbility`。）

5e. 删除文件内 `using OHOS::Security::CertManager::CM_UKEY_SCENE_LOGIN_STR;` 等 scene using 声明。

- [ ] **Step 6: ANI**

6a. 重命名 `cm_open_ukey_auth_dialog_no_context.{h,cpp}` → `cm_open_ukey_auth_dialog_sa_session.{h,cpp}`（`git mv`），类名 `CmOpenUkeyAuthDialogNoContext` → `CmOpenUkeyAuthDialogSaSession`；构造去 `aniScene` 形参；`GetParamsFromEnv` 删 scene 段；`InvokeAsyncWork` 删 `ukeyAuthRequest.scene` 行与 `SetLegacyOverload`（`legacyOverload` 恒 true 折叠）；BUILD.gn sources 改名。

6b. `cm_open_ukey_auth_dialog.cpp`（with-context 直启实现）：构造与 `GetParamsFromEnv` 删 scene 段；`InvokeAsyncWork` 的 `GetCustomerAuthCertWant(certUri, scene, customData, want)` 改为 `GetDefaultUkeyAuthCertWant(certUri, want)`（customData 无消费方，仅记日志长度）；启动调用删 `StartUIAbility` 分支、恒 `StartUIExtensionAbility`。

6c. `cm_dialog_ani.cpp`：
- `openUkeyAuthDialogNative` 签名去 `ani_string scene` 形参；删 `IsUkeySceneCustom` helper；
- 路由段替换为（对齐 NAPI 5d）：

```cpp
    {
        CmBlob keyUriBlob = { 0, nullptr };
        if (AniUtils::ParseString(env, keyUri, keyUriBlob) == CM_SUCCESS) {
            std::string driverBundle;
            std::string driverAbility;
            uint32_t abilityType = CM_UKEY_ABILITY_TYPE_UIABILITY;
            int32_t queryRet = GetUkeyAbilityInfo(&keyUriBlob, driverBundle, driverAbility, abilityType);
            CM_FREE_BLOB(keyUriBlob);
            if (queryRet != CM_SUCCESS) {
                return GenerateResult(env, CMR_DIALOG_ERROR_NOT_REGISTERED,
                    UKEY_NOT_REGISTERED_MSG.c_str());
            }
            if (abilityType == CM_UKEY_ABILITY_TYPE_UIABILITY) {
                return GenerateResult(env, CMR_DIALOG_ERROR_UIABILITY_NOT_SUPPORTED,
                    UKEY_UIABILITY_NOT_SUPPORTED_MSG.c_str());
            }
            if (CmUkeyIsPcOrPcMode()) {
                auto saSessionImpl = std::make_shared<CmOpenUkeyAuthDialogSaSession>(env, keyUri,
                    timeout, customData, callback);
                return saSessionImpl->Invoke();
            }
            /* 非 PC：回退默认弹框直启（走下方 context 直启实现） */
        }
    }
    auto openUkeyAuthDialogImpl = std::make_shared<CmOpenUkeyAuthDialog>(env, context, keyUri,
        customData, callback);
    return openUkeyAuthDialogImpl->Invoke();
```

- 删除 `openUkeyAuthDialogNoContextNative` 函数与 methods 数组对应条目（`openAuthDialogForUkeyDriverNative` 条目保留）。

6d. ets：
- 删 `UkeyAuthScene` 枚举、`UkeyAuthRequest.scene` 字段、无 context 重载整块、`openUkeyAuthDialogNoContextNative` native 声明；
- `openUkeyAuthDialogNative` 声明去 `scene: string` 形参；with-context 包装器去 `let scene: ...` 行与实参。

- [ ] **Step 7: 测试与 fuzz**

7a. `cm_ukey_auth_dialog_manager_test.cpp`：
- fixture `Open` 包装器去 scene 形参（`Open(uint32_t timeout = 0, const struct CmBlob *customData = nullptr)`，调 `OpenDialog(&keyUri_, 100, timeout, customData, client_)`）；
- `OpenDialogAbilityQueryFail` 重写：`querierRet_ = -51; ASSERT_EQ(Open(), CMR_DIALOG_ERROR_NOT_REGISTERED); EXPECT_EQ(launcher_->connectCount_, 0);`（不再断言默认弹框）；
- `CustomSceneWithoutCustomDialogRejected` 删除；`ParamsJsonCarriesSceneAndCustomData` 改名 `ParamsJsonCarriesCustomData`（scene 断言已在 Task 1 删除，保留 base64 断言）；
- `SceneAndCustomDataValidated` 改名 `CustomDataValidated`，只留 customData 超限断言；
- `OpenDialogWrongAbilityType`/`PcGateBlocksUiExtensionWhenNotPc` 的 `Open(0, CM_UKEY_AUTH_SCENE_...)` 调用改 `Open()`；
- 全文件 `CMR_DIALOG_ERROR_DEFAULT_NOT_SUPPORTED` 残留引用清零（Task 1 已改名）。

7b. `cm_ukey_auth_dialog_real_ipc_test.cpp`：
- `OpenDialogSceneCustomProbe` 删除；
- `OpenDialogRealIpcProbe` 预期改：无驱动注册 → **同步 -1019**（`EXPECT_EQ(ret, CMR_DIALOG_ERROR_NOT_REGISTERED)`，无异步回调断言）；
- `OpenDialogUiAbilityRejectedProbe` 保持 -1021 断言，`UkeyAuthRequest` 组包去 scene。

7c. 两个 fuzzer：`cmopenukeyauthdialog_fuzzer` 布局改 `[4B timeout][rest: keyUri+customData]`（删 scene 4 字节）；`cmopenauthdialogforukeydriver_fuzzer` 删 `.scene` 行。

- [ ] **Step 8: 全量编译**

Run: `./build.sh --product-name rk3568 --build-target certificate_manager --build-target cm_sdk_test --keep-ninja-going 2>&1 | grep -E "OHOS ERROR|FAILED|build  successful" | head -5`
Expected: `=====build  successful=====`

- [ ] **Step 9: Commit**

```bash
git add -A && git commit -s -m "feat!: drop scene and no-context overload, uiextension-only routing"
```

---

### Task 7: d.ts en/zh 删除项与文档改写（interface_sdk-js 仓）

**Files:**
- Modify: `interface/sdk-js/api/@ohos.security.certManagerDialog.d.ts`
- Modify: `interface/sdk-js/zh-cn/api/@ohos.security.certManagerDialog.d.ts`

- [ ] **Step 1: 删除项**（en/zh 同步）

- 删 `export enum UkeyAuthScene` 整块；
- 删 `function openUkeyAuthDialog(ukeyAuthRequest: UkeyAuthRequest): Promise<void>;` 整块（含 JSDoc）；
- 删 `UkeyAuthRequest.scene` 字段及其注释；
- `UkeyAuthRequest.customData` 注释改写：交付驱动的自定义弹框（UIExtensionAbility）base64 串；**非 PC 设备回退系统默认弹框时不携带（静默丢弃）**；
- `UkeyAuthRequest.timeoutDuration` 注释补一句：仅对经系统弹窗服务拉起的驱动弹框生效（回退默认弹框路径无超时机制）。

- [ ] **Step 2: openUkeyAuthDialog(context) JSDoc 改写**（en/zh 同步）

主描述改为（en 版）：

```
   * Opens the PIN authentication dialog box of the USB Key credential. The UKey
   * driver's registered UIExtensionAbility PIN dialog is displayed as a modal
   * system dialog (PC or PC mode only); on other devices the system default PIN
   * dialog is displayed instead. If no driver dialog is registered or the
   * registered ability is of UIAbility type, the call fails with 29700003.
   * …（其余既有 Promise/解锁描述保留）
```

throws 面调整：29700003 描述补 "no UKey driver PIN dialog is registered / the registered dialog is of UIAbility type"；**删除 29700005 条目**（正常路径不再抛，D25 v2）。

- [ ] **Step 3: Commit**（interface_sdk-js 仓）

```bash
git add api/@ohos.security.certManagerDialog.d.ts zh-cn/api/@ohos.security.certManagerDialog.d.ts && git commit -s -m "feat!: drop ukey auth scene and no-context overload"
```

---

### Task 8: 全量构建 + 真机验证

> 执行顺序说明：Step 1-2（部署 + 单测）先行；**Step 3-4（E2E）依赖 Task 9 的 demo 改造完成后再执行**；Step 5 收尾。

**Files:** 无新改动（验证任务；产出验证记录）

- [ ] **Step 1: 部署**

```bash
OUT=/home/wanghaixiang/ohos_master/out/rk3568
cp $OUT/security/certificate_manager/libcert_manager_service.z.so \
   $OUT/security/certificate_manager/libcert_manager_sdk.z.so \
   $OUT/security/certificate_manager/libcertmanagerdialog.z.so \
   $OUT/tests/unittest/certificate_manager/certificate_manager/cm_sdk_test /mnt/d/hdc_push/
HDC=/home/wanghaixiang/command-line-tools/sdk/default/openharmony/toolchains/hdc
$HDC target mount && \
$HDC file send 'D:\hdc_push\libcert_manager_service.z.so' system/lib/libcert_manager_service.z.so && \
$HDC file send 'D:\hdc_push\libcert_manager_sdk.z.so' system/lib/libcert_manager_sdk.z.so && \
$HDC file send 'D:\hdc_push\libcertmanagerdialog.z.so' system/lib/module/security/libcertmanagerdialog.z.so && \
$HDC file send 'D:\hdc_push\cm_sdk_test' data/local/tmp/cmtest/cm_sdk_test && \
$HDC shell reboot
```

- [ ] **Step 2: 单测全绿**（重启等待就绪后）

```bash
$HDC shell "setenforce 0; cd /data/local/tmp/cmtest && chmod +x cm_sdk_test && \
  LD_LIBRARY_PATH=/data/local/tmp/cmtest:/system/lib timeout 300 ./cm_sdk_test \
  --gtest_filter='CmUkeyAuthDialogManagerTest.*:CmUkeyDialogRealIpcTest.*' 2>&1 | tail -3"
```
Expected: `PASSED`（用例数 = 原 28 − 删除 2 + 新增 6（Task 1）+ 新增 2（Task 2 探针）；以实际输出为准全绿）

- [ ] **Step 3: ForDriver E2E（PC 模式）**

```bash
$HDC shell "param set persist.sceneboard.ispcmode true"
```
demo（Task 9 改造后）调用 `openAuthDialogForUkeyDriver({abilityType: 1, abilityName: 'MyUkeyAuthExtensionAbility'}, {keyUri: '...'})`：
- 期望：SA BMS 校验通过 → systemui 拉起 demo 扩展（弹框显示）→ demo 扩展上报 → promise resolve；
- 负例：`abilityName: 'NotExistAbility'` → 29700003；`param set persist.sceneboard.ispcmode false` 后调用 → 29700005。

- [ ] **Step 4: 非 PC 回退 E2E**

```bash
$HDC shell "param set persist.sceneboard.ispcmode false"
```
测试应用调 `openUkeyAuthDialog(context, {keyUri: '...'})`（keyUri 需 HUKS 注册了 UIExtension 类型驱动——**依赖 R12：HUKS 侧填充 abilityType=1，联调时需 HUKS 临时配合**）：
- 期望：Kit 查询 UIExtension + 非 PC → 直启 certmanager 默认弹框（CertPickerUIExtAbility 模态），无 29700005。

- [ ] **Step 5: 验证记录**

将各步输出摘要（单测计数、E2E 错误码）追加到 spec §17「v4 实现状态」，`git commit -s -m "docs: record v4 on-device verification"`。

---

### Task 9: demo 应用改造（Windows 侧工程，E2E 前置）

**Files:**
- Modify: `/mnt/d/workspace/UkeyAuthAbility2/entry/src/main/module.json`（**注意：改源码目录的 module.json，非 build 中间产物**）
- Modify: demo 内拉起弹框的页面/逻辑（`/mnt/d/workspace/UkeyAuthAbility2/entry/src/main/ets/...`）

- [ ] **Step 1: 权限声明**

`module.json` 的 `module` 顶层（`requestPermissions` 数组新增/创建）：

```json
"requestPermissions": [
  {
    "name": "ohos.permission.CRYPTO_EXTENSION_REGISTER",
    "reason": "$string:crypto_ext_reason",
    "usedScene": { "abilities": ["EntryAbility"], "when": "inuse" }
  }
]
```

（`string.json` 补 `crypto_ext_reason`；**签名 profile 需含该 ACL 权限**——RK3568 调试证书的 ACL allowed-permissions 列表须加 `ohos.permission.CRYPTO_EXTENSION_REGISTER`，否则安装/运行时报 201，见 spec R14。）

- [ ] **Step 2: 调用切换**

demo 中原 `openUkeyAuthDialog(request)`（无 context）调用点改为：

```ts
import { certificateManagerDialog } from '@kit.DeviceCertificateKit';

certificateManagerDialog.openAuthDialogForUkeyDriver(
  { abilityType: certificateManagerDialog.AbilityType.UKEY_AUTH_EXTENSION_ABILITY,
    abilityName: 'MyUkeyAuthExtensionAbility' },
  { keyUri: this.keyUri, timeoutDuration: 300000, customData: this.customData }
).then(() => { /* 上报成功后的处理 */ })
  .catch((err: BusinessError) => { /* err.code 断言点 */ });
```

demo 扩展侧（`MyUkeyAuthExtensionAbility` 及其页面）删除 `scene` 参数读取（v4 parameters JSON 不再携带）；`customData` 读取保留（base64 解码）。

- [ ] **Step 3: 重编安装**

用户侧重编（DevEco/命令行）+ ACL 签名 + `hdc install`；与 Task 8 Step 3 联动验证。

---

## Self-Review 记录

- **Spec 覆盖**：D21（删 scene/无 context：T6/T7）、D22（openUkeyAuthDialog 收窄 + 非 PC 回退：T6 Step 3/5/6 + T7）、D23（ForDriver 校验链：T1-T4）、D24（类型面：T3/T4/T5）、D25 v2（PC 分叉：T1 Step 4e / T6 Step 5d）、D26（单飞共享：T1 测试）、D8 v4 折叠归属（T3 不折叠 / T6 Step 5d 老接口折叠）、§7 inner API（T2）、§8 IPC（T2）、§13 测试（T1/T2/T6/T8）、§16 交付物逐项有任务对应。
- **占位符**：T4 Step 2 的"照抄"引用均指向具体文件行号段（no_context 既有实现），非抽象指示；T2 Step 7 探针写法注明对齐文件内既有风格的具体调整点。
- **类型一致性**：`CmOpenUkeyAuthDialogForDriver` 四处签名（api.h/api.c/client.h/client.cpp）一致；`UkeyAuthDialogInfo` C 结构体（cm_type.h）与 NAPI/ANI 组包字段一致；`CM_UKEY_ABILITY_NAME_MAX_LEN` 由 T3 定义于共享头、T4 复用；`GetDefaultUkeyAuthCertWant` 声明（T6 Step 4）与调用（T6 Step 5d/6b）一致。
