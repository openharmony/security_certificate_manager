# openUkeyAuthDialog 支持 UKey 驱动自定义 UIExtensionAbility Pin 码认证弹框 — 详细设计

- 日期：2026-09-03
- 状态：已实现（待真机联调）
- 需求来源：`cm_ukey_pin_design.txt`（工作区根目录）
- 涉及仓库：`base/security/certificate_manager`（主交付）、`interface/sdk-js`（SDK d.ts）；`base/security/huks`、`applications/standard/systemui` 为外部依赖，**不在本次交付范围**

## 1. 背景与目标

证书管理已提供 `openUkeyAuthDialog(context, ukeyAuthRequest)` 接口拉起 UKey Pin 码认证弹框：

- 该接口必须传入应用 context；
- 自定义弹框场景下只支持拉起 UKey 驱动注册的 **UIAbility**。

现调用方可能没有 context（如 SA / 无 UI 上下文的系统组件），且需要支持驱动注册
**UIExtensionAbility** 类型的自定义 Pin 码弹框。因此需要：

1. 新增无 context 的 `openUkeyAuthDialog(ukeyAuthRequest)` 重载；
2. 打通"无 context 拉起驱动自定义 UIExtensionAbility"链路：证书管理 SA 经由系统弹窗
   服务（`com.ohos.systemui.dialog`）以模态系统弹窗方式承载驱动的 UIExtensionAbility；
3. 异步等待认证结果后响应客户端，带超时机制。

## 2. 术语

| 术语 | 含义 |
|---|---|
| CM / 证书管理 SA | CertManagerService，SA ID 3512（`SA_ID_KEYSTORE_SERVICE`，注册见 services/.../sa/cm_sa.cpp:188） |
| 系统弹窗服务 | `com.ohos.systemui` / `com.ohos.systemui.dialog`（ServiceExtensionAbility），创建系统浮窗并以 `UIExtensionComponent` 承载目标 UIExtensionAbility |
| 驱动应用 | 通过 HUKS `registerProvider` 注册 Pin 码弹框能力的 UKey 厂商 HAP 应用 |
| 老接口 | `openUkeyAuthDialog(context, ukeyAuthRequest)`（argc==2） |
| 新接口 | `openUkeyAuthDialog(ukeyAuthRequest)`（argc==1，本次新增） |
| 会话 | 一次新链路弹框请求在 SA 侧的完整生命周期（requestId 标识） |

## 3. 设计决策记录

| # | 决策点 | 结论 | 理由 |
|---|---|---|---|
| D1 | 弹框承载方式 | SA 连接系统弹窗服务拉起驱动 UIExtensionAbility（参考 useriam `widget_context.cpp`） | 调用方无 context，无法走 `CreateModalUIExtension` / `StartAbilityForResult`；系统弹窗服务是既有的无 context 模态弹窗通道 |
| D2 | 结果回传通道 | **方案 C：驱动弹框主动上报**。SA 生成 requestId 随弹框参数下发；驱动完成认证后调用新增公开 API `reportUkeyAuthResult(requestId, resultCode)` 上报；SA 校验身份后回调客户端 | 方案 A（systemui 转发 onTerminated）被否：systemui 仓不允许修改；方案 B（断连 + PIN 状态轮询推导）被否：不采用轮询，且结果粒度粗。方案 C 结果精确、协议与现有 UIAbility 错误码契约一致 |
| D3 | HUKS 范围 | **不依赖 HUKS 新增改动**（用户裁定 2026-09-09）：ability 类型不经 HUKS 查询——老接口固定默认 UIAbility（原路径），新接口固定按 UIExtensionAbility 处理；仅消费现有 `HksQueryAbilityInfo`（bundle/ability 名，本树已存在） | HUKS 上游与本源码树均无 abilityType 字段，为解除阻塞删除该依赖；新接口的注册契约（驱动注册的 ability 须为 UIExtensionAbility）由 HUKS 驱动文档约束 |
| D4 | systemui 范围 | 系统弹窗服务**只读复用**现有 `COMMAND_START_DIALOG` 协议，仓零改动 | 需求边界明确 |
| D5 | 超时参数 | 总超时 **5 分钟**（暂定）；断连后上报宽限期 **10 秒** | 评审暂定值，常量化便于调整 |
| D6 | 并发约束 | SA 侧全局单飞：同一时刻仅允许一个挂起会话 | 系统弹窗 remote object 按连接方（pid+tokenId）维度共享，多会话无法区分；模态全屏弹窗本身互斥（与 USB 弹窗单弹框约束一致） |
| D7 | report API 权限 | 不加权限，安全由 requestId 随机性 + 调用者 bundleName 双重校验保障 | 驱动为三方 HAP，通常不持有 `ACCESS_CERT_MANAGER` |
| D8 | 错误码细分 | 提供方超时未上报（总超时 5min 到期）→ 新增 **29700009**；已有挂起会话（单飞拒绝）→ 新增 **29700010**；断连宽限超时仍归 29700002（窗口已销毁，语义为取消路径） | 专属错误码便于调用方与驱动商定位问题，不再折叠为笼统的 29700001 |

## 4. 总体架构与调用链

```
应用(JS/ArkTS)   Kit(NAPI/ANI)        证书管理SA(3512)             系统弹窗服务(不改)      驱动UIExtAbility
 │ openUkeyAuthDialog(req)              │                            │                      │
 ├───────────────>│ IPC(keyUri+回调stub) │                            │                      │
 │                ├─────────────────────>│ 权限/单飞校验               │                      │
 │                │                      │ HksQueryAbilityInfo(keyUri)│                      │
 │                │                      │  → bundle/ability 名       │                      │
 │                │                      │  → 查询为空:               │                      │
 │                │<─ 同步回执(-1016) ────│    同步回错,流程终止        │                      │
 │                │<─ 同步回执(0) ───────┤ 生成 requestId,建会话       │                      │
 │                │                      │ ConnectServiceExtensionAbility ─────────────────> │
 │                │                      │<───────── OnAbilityConnectDone ───────────────── │
 │                │                      │ SendRequest(COMMAND_START_DIALOG,                 │
 │                │                      │  {bundleName=驱动, abilityName=驱动ability,       │
 │                │                      │   parameters={keyUri,appUid,requestId,action}})   │
 │                │                      │                            │── UIExtensionComponent 装载 →│
 │                │                      │                            │                  (用户输入PIN)│
 │                │                      │                            │                  驱动完成认证 │
 │                │                      │<══ CM_MSG_REPORT_UKEY_AUTH_RESULT ════════════════│
 │                │                      │  {requestId, resultCode}   reportUkeyAuthResult() │
 │                │                      │ 校验 requestId + 上报者bundle == 驱动bundle        │
 │                │                      │ → 完成会话(停定时器/断连)   │  (随后 terminateSelf)│
 │                │<─ SendRequest(1,{code}) ─ 回调stub(TF_ASYNC)      │                      │
 │<─ resolve/reject │                    │                            │                      │
 │                │                      │ [兜底] 断连→10s宽限→取消(29700002)；总超时5min→未上报超时(29700009)│
```

要点：

- **老接口（argc==2）恒走原路径**（自定义 UIAbility / 统一弹窗），不做类型分叉（D3）；
- **同步应答**仅承载即时校验结果（参数/权限/单飞/ability 查询失败）。同步回错时**不**触发异步回调。
- **异步结果**经客户端回调 stub 回传，保证恰好一次（成功、取消、失败、超时四选一）。
- 驱动 ability 的 `terminateSelfWithResult` 返回码**不被观测**（系统弹窗服务不转发结果），
  结果以驱动主动上报为准（D2）。

## 5. SDK 接口变更

### 5.1 `interface/sdk-js/api/@ohos.security.certManagerDialog.d.ts`

新增重载（放在现有 `openUkeyAuthDialog(context, ukeyAuthRequest)` 之后）：

```ts
/**
 * Opens the PIN authentication dialog box of the USB Key credential without requiring an
 * application context. The dialog is provided by the USB Key driver's custom
 * UIExtensionAbility and displayed as a modal system dialog. ...
 * @permission ohos.permission.ACCESS_CERT_MANAGER
 * @param { UkeyAuthRequest } ukeyAuthRequest - Authentication request information.
 * @returns { Promise<void> } Promise that returns no value.
 * @throws { BusinessError } 201 / 401 / 801
 * @throws { BusinessError } 29700001 - Internal error (e.g. failed to launch the dialog).
 * @throws { BusinessError } 29700002 - The user cancels the authentication operation.
 * @throws { BusinessError } 29700003 - The authentication operation failed.
 * @throws { BusinessError } 29700006 - The input parameters validation failed.
 * @throws { BusinessError } 29700008 - The UKey driver has not registered a custom PIN
 *     dialog of the UIExtensionAbility type.
 * @throws { BusinessError } 29700009 - The USB Key driver's PIN dialog did not report
 *     the authentication result within the timeout.
 * @throws { BusinessError } 29700010 - Another UKey PIN authentication dialog is
 *     already in progress.
 * @syscap SystemCapability.Security.CertificateManagerDialog
 * @stagemodelonly
 * @since 26.0.0 dynamic&static   // 以 API 治理结论为准
 */
function openUkeyAuthDialog(ukeyAuthRequest: UkeyAuthRequest): Promise<void>;
```

新增上报接口：

```ts
/**
 * Reports the result of the USB Key PIN authentication. Called by the USB Key driver's
 * custom UIExtensionAbility after the authentication flow ends. Must be called before
 * terminateSelf. The requestId is obtained from want.parameters of the launched dialog.
 * @param { string } requestId - Dialog session identifier (from want.parameters).
 * @param { number } resultCode - 0: success; 29700002: user canceled; 29700003: operation
 *     failed; 29700006: parameter validation failed; 29700001: other failures.
 * @returns { Promise<void> } Promise that returns no value.
 * @throws { BusinessError } 401 - Parameter error.
 * @throws { BusinessError } 29700001 - Session does not exist or has ended, caller
 *     verification failed, or internal error.
 * @syscap SystemCapability.Security.CertificateManagerDialog
 * @stagemodelonly
 * @since 26.0.0 dynamic&static   // 以 API 治理结论为准
 */
function reportUkeyAuthResult(requestId: string, resultCode: number): Promise<void>;
```

`CertificateDialogErrorCode` 枚举追加：

```ts
ERROR_UKEY_ABILITY_NOT_SUPPORTED = 29700008   /* UKey 驱动未注册 UIExtensionAbility 类型的自定义 Pin 弹框 */
ERROR_UKEY_AUTH_REPORT_TIMEOUT = 29700009     /* 提供方超时未上报认证结果（总超时到期） */
ERROR_UKEY_DIALOG_IN_PROGRESS = 29700010      /* 已有一个 UKey Pin 码认证弹框会话挂起 */
```

同步更新中文镜像 interface/sdk-js/zh-cn/api/@ohos.security.certManagerDialog.d.ts 与 ANI 声明
`interfaces/kits/ani/certificate_manager_dialog_ani/ets/@ohos.security.certManagerDialog.ets`。

### 5.2 ANI 侧

- `.ets` 新增 `openUkeyAuthDialog(ukeyAuthRequest)` 重载与 `reportUkeyAuthResult(requestId, resultCode)`；
- `src/cm_dialog_ani.cpp` 注册两个新 native 函数；
- `src/`/`include/` 新增实现类 `CmOpenUkeyAuthDialogNoContext`、`CmReportUkeyAuthResult`
  （复用同一 inner API，不依赖 abilityContext）。

## 6. 外部依赖契约（非本次交付）

### 6.1 HUKS（仅消费现有接口，无新增依赖）

- 仅使用现有 `HksQueryAbilityInfo(resourceId, &abilityInfo)`（hks_api.h:133）获取驱动注册弹框的
  `bundleName` / `abilityName`（hks_type.h:78），**不读取 ability 类型**；
- 类型判定策略（D3）：老接口（argc==2）固定默认 UIAbility 走原路径；新接口（argc==1）
  固定按 UIExtensionAbility 处理，SA 仅以查询结果非空为门槛（空 → -1016/29700008）；
- 新接口的注册契约（驱动经 `registerProvider` 为 Pin 弹框注册的 ability 须为
  UIExtensionAbility 类型）由 HUKS 驱动文档约束（§6.3 对齐项）。

### 6.2 系统弹窗服务（只读复用）

- 既有 IPC 协议：连接成功后向服务 stub `SendRequest(IAbilityConnection::ON_ABILITY_CONNECT_DONE,
  {int32 size=3, ("bundleName", 驱动bundle), ("abilityName", 驱动ability),
  ("parameters", JSON字符串)}, TF_ASYNC)`；
  服务侧创建浮窗并以 `UIExtensionComponent({bundleName, abilityName, parameters})` 装载
  （ExtAbility.ts:34-127、ExtIndex.ets:109）。
- 本设计**不发送** `COMMAND_SEND_REMOTE_OBJECT(2)`，不依赖其回传。
- `parameters` JSON 内容（驱动 ability 在 `want.parameters` 中收到）：

```json
{
  "keyUri": "<UKey 凭证唯一标识>",
  "appUid": <发起方应用 uid（原客户端 IPC 调用者，非 SA 自身）>,
  "requestId": "<32 字符 hex 会话标识>",
  "action": "UkeyPINAuth"
}
```

  说明：action 置于 parameters 内（UIExtensionComponent 通道不透传顶层 want.action），
  keyUri/appUid 语义与现有 UIAbility 流程 want 契约一致（见 HUKS 文档
  js-apis-huksExternalCrypto.md:100-104），驱动侧读取逻辑可复用。

### 6.3 驱动 UIExtensionAbility 契约（HUKS 仓文档对齐项）

1. 认证流程结束后**先** `await reportUkeyAuthResult(requestId, resultCode)`，**再**
   `terminateSelf()`（10s 宽限即为此顺序契约的竞态兜底）；
2. 错误码协议与 UIAbility 场景完全一致：0 成功 / 29700002 取消 / 29700003 失败 /
   29700006 参数错误 / 其余 29700001。

## 7. inner API（interfaces/innerkits/cert_manager_standard/main/include）

### 7.1 `cm_type.h`

```c
/* UKey Pin 码认证请求 */
struct UkeyAuthRequest {
    struct CmBlob keyUri;   /* UKey 凭证唯一标识，最大 256 字节 */
};

/* 对话框内部错误码段追加（现有最大 -1015） */
CMR_DIALOG_ERROR_UKEY_ABILITY_NOT_SUPPORTED = -1016  /* 查询为空或类型非 UIExtensionAbility */
CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT = -1017         /* 提供方超时未上报认证结果（总超时到期） */
CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS = -1018     /* 已有挂起的 UKey 认证弹框会话（单飞拒绝） */
```

### 7.2 `cert_manager_api.h`

```c
typedef void (*CmUkeyAuthDialogResultCallback)(int32_t resultCode, void *userData);

/* 打开 UKey Pin 码认证弹框（驱动自定义 UIExtensionAbility 场景）。
 * 同步返回值：即时校验结果（参数/权限/单飞/ability 校验失败等，此时不触发 callback）。
 * 弹框最终结果（0/取消/错误码/超时）经 callback 异步回传，恰好一次。 */
CM_API_EXPORT int32_t CmOpenUkeyAuthDialog(const struct UkeyAuthRequest *ukeyAuthRequest,
    CmUkeyAuthDialogResultCallback callback, void *userData);

/* 驱动 UIExtensionAbility 上报认证结果。同步返回校验结果。 */
CM_API_EXPORT int32_t CmReportUkeyAuthResult(const struct CmBlob *requestId, int32_t resultCode);
```

导出符号需同步追加到 inner API 版本脚本（如有）。

## 8. IPC 协议（frameworks ↔ SA，CM 自有通道）

### 8.1 消息码

`frameworks/.../cert_manager_service_ipc_interface_code.h` 的 `CM_MSG_MAX` 前追加：

```c
CM_MSG_OPEN_UKEY_AUTH_DIALOG,     /* 打开 UKey 认证弹框（新链路） */
CM_MSG_REPORT_UKEY_AUTH_RESULT,   /* 驱动上报认证结果 */
```

### 8.2 parcel 布局

| 消息 | 请求 parcel | 同步应答 |
|---|---|---|
| OPEN | `[interfaceToken][uint32 size][paramSet blob（CM_TAG_PARAM0_BUFFER: keyUri）][remote object（客户端回调 stub）]` | `[int32 同步校验码]` |
| REPORT | `[interfaceToken][uint32 size][paramSet blob（CM_TAG_PARAM0_BUFFER: requestId, CM_TAG_PARAM1_UINT32: resultCode）]` | `[int32 校验码]` |

两码均**跳过 outSize 读取**（与 `CM_MSG_GET_UKEY_CERTIFICATE*` 同模式，
cm_sa.cpp:278-281 跳过列表需追加）。

### 8.3 客户端（frameworks/.../os_dependency/cm_ipc/）

- `CmClientOpenUkeyAuthDialog(keyUri, callback, userData)`：组包（paramSet + 回调 stub
  remote object），同步发送；
- `CmClientReportUkeyAuthResult(requestId, resultCode)`：组包同步发送；
- 新增 C++ 回调 stub（`IRemoteStub`）：接收 SA 的
  `SendRequest(cmd=CM_UKEY_DIALOG_CALLBACK_CMD=1, [int32 code], TF_ASYNC)`，
  查注册表触发 C 函数指针（线程安全注册/注销，供 inner API 封装使用）。

### 8.4 SA 侧路由

- `cm_sa.cpp OnRemoteRequest`：新码入 outSize 跳过列表；OPEN 在 `GetSrcData` 后
  `data.ReadRemoteObject()` 取回调对象，转调新处理器；
- `idl/cm_ipc/cm_ipc_service.{h,c}` 新增：

```c
void CmIpcServiceOpenUkeyAuthDialog(uint32_t code, const struct CmBlob *paramSetBlob,
    const struct CmContext *context, const void *remoteCallback);
void CmIpcServiceReportUkeyAuthResult(uint32_t code, const struct CmBlob *paramSetBlob,
    const struct CmContext *context);
```

  处理器内做权限校验（`ACCESS_CERT_MANAGER`，OPEN）与参数解析，转调 §9 会话管理器；
  结果经 `CmSendResponse` 写同步应答。

## 9. SA 侧详细设计

新增目录 `services/cert_manager_standard/cert_manager_service/main/os_dependency/dialog/`：

### 9.1 模块构成

| 文件 | 职责 |
|---|---|
| `cm_ukey_auth_dialog_manager.h/.cpp` | 单例会话管理器：requestId 生成、会话表、单飞、状态机、定时器（总超时/宽限）、上报校验、结果分发、清理、客户端死亡监听、SA 保活续期 |
| `cm_system_dialog_connection.h/.cpp` | `IAbilityConnection` 实现：`OnAbilityConnectDone` → 向弹窗服务发 START_DIALOG 命令；`OnAbilityDisconnectDone` → 通知 manager 进入宽限期 |

### 9.2 会话结构与状态机

```cpp
struct UkeyAuthSession {
    std::string requestId;                 // 32 字符 hex（/dev/urandom 16 字节）
    std::string driverBundleName;          // 来自 HksQueryAbilityInfo，上报身份校验用
    uint32_t callerUid;                    // 原客户端 uid（弹框参数 appUid 用）
    sptr<IRemoteObject> clientCallback;    // 客户端回调 stub
    sptr<CmSystemDialogConnection> connection;
    sptr<IRemoteObject::DeathRecipient> clientDeathRecipient;
    std::shared_ptr<AppExecFwk::EventHandler> timer;   // "cm_ukey_dialog" 专用线程
    enum State { LAUNCHING, WAITING_REPORT, GRACE_WAITING, DONE } state;
};
```

```
LAUNCHING ──连接失败/发命令失败──> DONE(29700001)
    │ 连接成功且 START_DIALOG 已发送
    v
WAITING_REPORT ──合法上报──> DONE(上报码)          [启动 5min 总超时]
    │ 总超时(5min)到期 ──────────────> DONE(29700009 提供方超时未上报)
    │ OnAbilityDisconnectDone
    v
GRACE_WAITING ──宽限内合法上报──> DONE(上报码)      [启动 10s 宽限定时]
    │ 宽限超时
    v
DONE(29700002 取消)
```

- 任意路径进入 DONE 后，迟到的上报/断连/超时一律忽略（report 返回"会话不存在"）；
- 总超时触发：DONE(-1017/29700009 提供方超时未上报)，并向弹窗服务发
  `ON_REMOTE_STATE_CHANGED` 请求释放窗口后 `DisconnectAbility`；
- 结果分发：经 clientCallback
  `SendRequest(1, [int32 code], TF_ASYNC)`，随后清理（停定时器 → 断连（忽略已断连错误）
  → 删会话 → 注销死亡通知）。

### 9.3 上报校验（安全设计，D7）

`CM_MSG_REPORT_UKEY_AUTH_RESULT` 到达时依次校验：

1. requestId 在会话表中且会话未终态，否则拒绝（29700001）；
2. `AccessTokenKit::GetHapTokenInfo(callingTokenId)` 取 callingBundleName（非 HAP
   token 直接拒绝），必须等于会话记录的 `driverBundleName`，否则拒绝并记录安全日志；
3. resultCode 白名单 `{0, 29700001, 29700002, 29700003, 29700006}`，未知值折叠为
   29700001。

仅持有 requestId 的第三方进程无法通过第 2 层校验。

### 9.4 其他横切关注点

- **单飞（D6）**：已有挂起会话时，第二个 OPEN 同步回
  `CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS`（映射 29700010）；
- **客户端死亡**：在回调 stub 上注册 `DeathRecipient`，客户端进程死亡 → 中止会话并清理
  （不回调）；
- **SA 保活**：会话挂起期间周期性续期 `DelayUnload`（复用 cm_sa.cpp 既有卸载延迟机制，
  需向 dialog 模块暴露续期入口），防止 SA 空闲卸载丢失连接与回调；
- **线程模型**：会话表与状态机由 `std::mutex` 保护；定时器跑在专用 EventHandler
  （"cm_ukey_dialog"），回调分发不阻塞 IPC 线程；
- **SA 身份拉起**：连接系统弹窗服务前 `IPCSkeleton::ResetCallingIdentity()`，以 SA
  身份 `ConnectServiceExtensionAbility`，完成后恢复（对齐 useriam
  widget_context.cpp:552-558）。

### 9.5 SA 构建依赖

`os_dependency/sa/BUILD.gn`（及 idl/BUILD.gn）追加源文件与：

```
ability_runtime:extension_manager_client
ability_base:want
access_token:libaccesstoken_sdk
eventhandler:libeventhandler
```

## 10. Kit 层（NAPI/ANI）改造

### 10.1 `cm_dialog_api_common`（kits/common）

- `GetCustomerAuthCertWant` 行为不变（仅继续服务老接口路径）；
- `DIALOG_CODE_TO_JS_CODE_MAP` / `DIALOG_CODE_TO_MSG_MAP` 追加三个新码映射：
  `{CMR_DIALOG_ERROR_UKEY_ABILITY_NOT_SUPPORTED, 29700008}`、
  `{CMR_DIALOG_ERROR_UKEY_REPORT_TIMEOUT, 29700009}`、
  `{CMR_DIALOG_ERROR_UKEY_DIALOG_IN_PROGRESS, 29700010}` 及对应文案。

### 10.2 NAPI `cm_napi_open_ukey_auth_dialog.cpp`

`CMNapiOpenUkeyAuthorizeDialog` 重构为 argc 分叉：

```
argc == 1（新接口）：
    解析 UkeyAuthRequest（keyUri，复用 GetUkeyAuthRequest）
    → 创建 promise → CmOpenUkeyAuthDialog
    → C 回调经 napi_threadsafe_function 回 JS 线程：
        code == 0 → resolve(undefined)
        否则 → reject(GenerateBusinessError(code))

argc == 2（老接口，行为兼容）：
    原有流程零改动（GetCustomerAuthCertWant + StartUkeyPinAbility），
    不做类型分叉（D3：恒按默认 UIAbility 处理）
```

- argc 校验放宽为 1 或 2，其余报 401（沿用 `CheckUkeyAuthDialogArgc` 模式）；
- metrics 上报沿现有 `CmMetricsReport("openUkeyAuthDialog", DIALOG)` 覆盖新分支。

新增 `cm_napi_report_ukey_auth_result.cpp`：

```
CMNapiReportUkeyAuthResult(env, info)：
    argc==2：requestId(string, 非空, ≤64) + resultCode(number)
    → CmReportUkeyAuthResult → resolve / reject(29700001)
    参数类型错误 → ThrowError(401)
```

`cm_napi_dialog.cpp` 属性表注册 `reportUkeyAuthResult`（对齐 :114 现有注册方式）。

## 11. 错误码汇总

| 场景 | 内部码 | JS 码 |
|---|---|---|
| ability 查询为空（新接口；未注册自定义 Pin 弹框） | -1016（新） | 29700008（新） |
| 提供方超时未上报（总超时 5min 到期） | -1017（新） | 29700009（新） |
| 已有挂起会话（单飞拒绝） | -1018（新） | 29700010（新） |
| 连接失败 / 发命令失败 / 上报校验失败 / 未知上报码 | CMR_DIALOG_ERROR_INTERNAL | 29700001 |
| 断连宽限（10s）超时（判定为用户取消） | CMR_DIALOG_ERROR_OPERATION_CANCELS | 29700002 |
| 驱动上报透传 | 29700003 / 29700006 | 29700003 / 29700006 |
| 参数校验失败 | 401 / CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED | 401 / 29700006 |
| 无权限 | CMR_DIALOG_ERROR_PERMISSION_DENIED | 201 |

## 12. 兼容性

- 老接口行为零变化（恒走原路径，不做类型分叉，D3）；
- 新 IPC 码为枚举尾部追加，不挤占既有码值；`cm_sa.cpp` 对未知码仍走
  `IPCObjectStub::OnRemoteRequest` 兜底；
- inner API 新增符号属增量；`.map` 版本脚本仅追加，不改变既有符号可见性；
- 老接口调用方若驱动注册了 UIExtensionAbility 类型，并发第二次调用将收到 29700010
  （原 modal 流程可并发）——模态全屏弹窗场景下可接受（D6）。

## 13. 测试与验证

- **单元测试**（`test/unittest/`，SA manager 为重点）：
  - 状态机全路径：LAUNCHING 失败 / 正常上报 / 断连→宽限内上报 / 宽限超时→取消(29700002) /
    总超时→未上报超时(29700009) / 终态防重入（迟到上报、迟到断连）；
  - 安全：requestId 不存在、非 HAP token、bundleName 不匹配、未知 resultCode 折叠；
  - requestId 随机性与格式；单飞互斥（29700010）；客户端死亡清理；回调 stub 序列化。
- **Fuzz**（`test/fuzz_test/`，仿 `cmgetukeycertlist_fuzzer`）：OPEN/REPORT 两个 IPC 入口、
  两个 NAPI 函数（argc/类型混乱）。
- **XTS**：新重载（成功/取消/29700008/29700009/29700010/401/201）、
  `reportUkeyAuthResult`（401/会话不存在）、老接口类型分叉回归。
- **构建验证**：
  - `./build.sh --product-name rk3568 --build-only-gn`（BUILD.gn 变更校验）
  - `./build.sh --product-name rk3568 --build-target certificate_manager`
- **真机联调**：驱动 demo 注册 UIExtensionAbility 类型；成功/取消/失败三场景；
  伪造上报安全用例；断连先于上报的竞态用例；老接口驱动（UIAbility）回归。

## 14. 风险与遗留事项

| # | 风险/事项 | 缓解 |
|---|---|---|
| R1 | `reportUkeyAuthResult` 为新增公开 API，签名/无权限设计需通过 API 评审 | 评审材料引用本设计 §5.1、§9.3 |
| R2 | 驱动不遵守"先上报后终止"契约且超 10s 宽限 → 结果折叠为取消 | HUKS 驱动文档明确契约（§6.3，对齐项） |
| R3 | ~~HUKS ability 类型字段形态未定~~ 已解除（D3 用户裁定：类型不经 HUKS 查询，依赖移除） | — |
| R4 | SA 保活续期与既有按需卸载策略的交互需确认 | 实现阶段与 SA 框架对齐 DelayUnload 暴露方式 |
| R5 | `appUid` 为应用隔离字段，多用户/多应用并发弹框语义依赖驱动侧实现 | 契约随 §6.2 交由 HUKS 文档明确 |

## 15. 参考实现索引

| 参考点 | 位置 |
|---|---|
| 现有 openUkeyAuthDialog NAPI 流程 | base/security/certificate_manager/interfaces/kits/napi/src/dialog/cm_napi_open_ukey_auth_dialog.cpp:84 |
| ability 查询与默认弹框 Want 构造 | base/security/certificate_manager/interfaces/kits/common/src/cm_dialog_api_common.cpp:98,129 |
| 有 context 的两种拉起方式 | base/security/certificate_manager/interfaces/kits/napi/src/dialog/cm_napi_dialog_common.cpp:65,121 |
| SA OnRemoteRequest / outSize 跳过 / ProcessMessage | base/security/certificate_manager/services/.../os_dependency/sa/cm_sa.cpp:258,278,148 |
| IPC 消息码枚举 | base/security/certificate_manager/frameworks/.../cert_manager_service_ipc_interface_code.h:24 |
| 连接系统弹窗服务 + SA 身份处理 | base/useriam/user_auth_framework/services/context/src/widget_context.cpp:538,666,704 |
| START_DIALOG SendRequest 报文格式 | base/useriam/user_auth_framework/services/context/src/ui_extension_ability_connection.cpp:32 |
| 系统弹窗服务 stub 协议（1=START, 2=SEND_REMOTE_OBJECT） | applications/standard/systemui/product/default/dialog/src/main/ets/ServiceExtAbility/ExtAbility.ts:34；common/Constants.ts:23 |
| UIExtensionComponent 装载 | applications/standard/systemui/product/default/dialog/src/main/ets/pages/ExtIndex.ets:109 |
| 驱动 want 契约与错误码协议（UIAbility 场景） | docs/zh-cn/application-dev/reference/apis-universal-keystore-kit/js-apis-huksExternalCrypto.md:94 |
| ANI 现有 openUkeyAuthDialog | base/security/certificate_manager/interfaces/kits/ani/certificate_manager_dialog_ani/ets/@ohos.security.certManagerDialog.ets:359 |

## 16. 交付物清单（file-level change list）

**本次交付（certificate_manager + interface/sdk-js）**

| 模块 | 文件 | 变更 |
|---|---|---|
| SDK | interface/sdk-js/api/@ohos.security.certManagerDialog.d.ts（及中文镜像） | 新重载、reportUkeyAuthResult、29700008/29700009/29700010 |
| ANI | interfaces/kits/ani/certificate_manager_dialog_ani/（ets + src + include） | 两个新 API 及 native 实现 |
| inner API | interfaces/innerkits/.../cm_type.h、cert_manager_api.h | UkeyAuthRequest、-1016、两个新函数、回调类型 |
| IPC 码 | frameworks/.../cert_manager_service_ipc_interface_code.h | 2 个新码 |
| IPC 客户端 | frameworks/.../cm_ipc/（新文件 + cm_ipc_client.h） | 组包、回调 stub |
| SA | services/.../os_dependency/dialog/（新目录） | manager + connection |
| SA 路由 | services/.../sa/cm_sa.cpp、idl/cm_ipc/cm_ipc_service.{h,c} | 新码路由、outSize 跳过、ReadRemoteObject、2 个处理器 |
| SA 构建 | services/.../sa/BUILD.gn、idl/BUILD.gn | 源文件与新 external_deps |
| kits/common | cm_dialog_api_common.{h,cpp} | 类型出参、错误码映射追加 |
| NAPI | cm_napi_open_ukey_auth_dialog.cpp、新增 cm_napi_report_ukey_auth_result.cpp、cm_napi_dialog.cpp、cm_napi_dialog_common.h | argc 分叉、新函数、注册 |
| 测试 | test/unittest、test/fuzz_test、XTS 用例 | 见 §13 |

**外部对齐项（非本次交付）**：HUKS ability 类型查询与驱动文档（§6.1、§6.3）。

## 17. 实现状态

- **代码分支**：`cm-ukey-pin-impl`（`base/security/certificate_manager`，T1–T7/T9 共
  10 个提交：16f38da → cc34116 → a9504a3 → f0a62d0 → 579be08 → af8d0d9 → 62b7562 →
  cb669ce → 305bbbd → 4bc5e53）。
- **SDK d.ts**：`interface/sdk-js` @ `ukey-auth` 分支（9048c49ac，基于既有的
  UkeyAuthUIExtensionAbility 基类 / CONNECT_UKEY_AUTH_EXTENSION 权限提交 8061d1cab）。
- **待真机联调清单**（对应 §13）：
  - 驱动 demo 注册 UkeyAuthUIExtensionAbility 类型 ability；
  - 成功 / 取消 / 失败 / 超时四场景 + 伪造上报（requestId/bundleName 不匹配）安全用例；
  - 断连先于上报的竞态用例；
  - 老接口（UIAbility 类型驱动）回归；
  - R9 关注点：systemui `UIExtensionComponent` 装载 UkeyAuthUIExtensionAbility 类型
    extension 的兼容性；`CONNECT_UKEY_AUTH_EXTENSION` 权限校验方确认。
- **XTS 用例**：随 XTS 仓节奏单独交付（本仓不含）。
