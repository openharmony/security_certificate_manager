# openUkeyAuthDialog / openAuthDialogForUkeyDriver UKey 驱动 Pin 码认证弹框 — 详细设计

- 日期：2026-09-03（v4 修订：2026-09-17）
- 状态：v1–v3 已实现并真机验证（§17）；**v4 简化方案待实现**（删除 scene/无 context 重载/默认弹框/UIAbility 路径，新增 openAuthDialogForUkeyDriver）
- 需求来源：`cm_ukey_pin_design.txt`（基线）；2026-09-15 场景路由指示（v3，**已被 v4 大幅取代**）；
  2026-09-17 简化方案指示（v4）
- 涉及仓库：`base/security/certificate_manager`（主交付）、`interface/sdk-js`（SDK d.ts）；
  `base/security/huks`（abilityType 填充，外部依赖）、`applications/standard/systemui`（只读复用）。
  ~~`applications/standard/user_certificate_manager`（默认弹框，v4 后不可达）~~

## 修订记录

| 版本 | 日期 | 内容 |
|---|---|---|
| v1 | 2026-09-03 | 基线设计（无 context 重载 + UIExtensionAbility 经系统弹窗服务） |
| v2 | 2026-09-11 | D3 修订（abilityType 方案）、D2 修订（公开 report API 收窄为 inner）、超时参数、requestId CSPRNG fail-closed |
| v3 | 2026-09-15 | 场景路由（D9–D19）：`scene`/`customData` 字段；三分路由（默认/UIAbility/UIExtension）；PC 门禁；删除 29700008 |
| v4 | 2026-09-17 | **简化方案（D21–D26）**：删 `scene` 字段与 `UkeyAuthScene`；删无 context 重载；`openUkeyAuthDialog(context)` 收窄为仅驱动 UIExtensionAbility（查询失败/UIAbility → 29700003）；默认弹框与 UIAbility 拉起路径整体删除；新增 `openAuthDialogForUkeyDriver(dialogInfo, ukeyAuthRequest)`（CRYPTO_EXTENSION_REGISTER + IPC token 取包名 + BMS 预校验）；新增 `AbilityType`/`UkeyAuthDialogInfo`；D8 折叠逻辑重新归属（专属码 29700009/29700010 移至新接口）。**同日增补（D25 v2）**：非 PC/非 PC 模式 + UIExtension 时，openUkeyAuthDialog 在 **Kit 侧回退直启默认弹框**（since-22 既有机制），ForDriver 维持 29700005 |
| v4.1 | 2026-09-17 | 用户裁定修正：abilityType 枚举值非法→29700006（仅类型错 401）；abilityName 上限 256 字节；BMS userId 改经 CmGetProcessInfoForIPC |

## 1. 背景与目标

证书管理提供 `openUkeyAuthDialog(context, ukeyAuthRequest)`（@since 22）拉起 UKey Pin 码认证
弹框。v1–v3 逐步交付了 SA 会话机制（requestId/单飞/超时/上报）、场景路由（默认弹框/
UIAbility/UIExtension 三分）与 customData 透传。

**v4 简化方案**（2026-09-17 指示）：整个特性收敛为**单一弹框形态——驱动 UIExtensionAbility**：

1. `UkeyAuthRequest` **删除 `scene` 字段**（`UkeyAuthScene` 枚举整体删除），`customData` 保留；
2. `openUkeyAuthDialog` **只保留带 context 重载**：Kit 侧查询 `HksQueryAbilityInfo`，
   **仅 abilityType == UIExtensionAbility(1) 时走 SA 拉起**；查询失败与 UIAbility 均拒绝
   （29700003）。SA 侧同样只拉起 UIExtensionAbility——**默认弹框与 UIAbility 均不经 SA 拉起**；
   但**非 PC/非 PC 模式 + UIExtension 时，Kit 侧回退直启系统默认弹框**（D25 v2）；
3. 新增 `openAuthDialogForUkeyDriver(dialogInfo: UkeyAuthDialogInfo, ukeyAuthRequest)`：
   供 **UKey 驱动应用自己拉起自己的弹框扩展**。不经 HUKS 查询；SA 从 **IPC token** 取调用方
   包名（只能拉起自己 bundle 内的扩展）；校验调用方持有
   `ohos.permission.CRYPTO_EXTENSION_REGISTER`；该接口也仅支持 UIExtensionAbility。

## 2. 术语

| 术语 | 含义 |
|---|---|
| CM / 证书管理 SA | CertManagerService，SA ID 3512 |
| 系统弹窗服务 | `com.ohos.systemui` / `com.ohos.systemui.dialog`（ServiceExtensionAbility），创建系统浮窗并以 `UIExtensionComponent` 承载目标 UIExtensionAbility |
| 驱动应用 | 通过 HUKS `registerProvider`（`CRYPTO_EXTENSION_REGISTER` 权限）注册 UKey 能力的厂商 HAP 应用 |
| openUkeyAuthDialog | `openUkeyAuthDialog(context, ukeyAuthRequest)`（@since 22，v4 后唯一重载）——普通应用（依赖方）入口 |
| openAuthDialogForUkeyDriver | v4 新增（@since 26）——驱动应用自拉起入口 |
| 会话 | 一次弹框请求在 SA 侧的完整生命周期（requestId 标识），两接口共享单飞 |
| 自定义数据 | `customData`，调用方原始字节（≤2048），base64 后写入弹框 parameters |
| PC/PC 模式 | `const.product.devicetype == "2in1"`，或 `persist.sceneboard.ispcmode == true`（D15） |
| ~~场景 / 默认弹框 / UIAbility 路径~~ | **v4 删除**（D21/D22） |

## 3. 设计决策记录

v1–v3 决策（D1–D20）保留作轨迹；v4 覆盖项在行内标注，新决策 D21 起追加。

| # | 决策点 | 结论 | 理由 |
|---|---|---|---|
| D1 | 弹框承载方式 | SA 连接系统弹窗服务拉起 UIExtensionAbility（参考 useriam `widget_context.cpp`） | 调用方无 context 或需系统身份拉起；系统弹窗服务是既有的无 context 模态弹窗通道 |
| D2 | 结果回传通道 | 驱动弹框主动上报——SA 生成 requestId 随弹框参数下发，提供方调用 inner API `CmReportUkeyAuthResult(requestId, resultCode)` 上报，SA 校验后回调客户端。公开 report 面不暴露 | v2 裁定，v4 不变（UIExtension 形态经框架 `UkeyAuthExtensionContext.terminateSelf*` 自动上报） |
| D3 | HUKS 范围 | SA 与 Kit 侧均消费 `HksQueryAbilityInfo` 返回的 `abilityType`（0=UIAbility，1=UIExtensionAbility）；`HksAbilityInfo` 已增字段（huks 仓 `9b396d3b3`），**HUKS 查询实现尚未填充**（零初始化=0） | v4 下 abilityType 成为 openUkeyAuthDialog 的**门禁**（仅 1 放行），HUKS 填充是该接口 E2E 的前置（R12） |
| D4 | systemui 范围 | 系统弹窗服务**只读复用**现有 `COMMAND_START_DIALOG` 协议，仓零改动 | 不变 |
| D5 | 超时参数 | `timeoutDuration`（ms）0=默认 300s，显式值 clamp [3min, 10min]；断连宽限 10s | v3 定值，v4 不变 |
| D6 | 并发约束 | SA 全局单飞（两接口共享同一会话位） | 不变 |
| D7 | report 权限 | 不加权限：requestId CSPRNG + 上报者 bundleName == 会话 owner 双重校验 | 不变 |
| D8 | 错误码折叠 | **v4 修订（2026-09-17）**：专属码 **29700009（超时未上报）/ 29700010（单飞）归属 `openAuthDialogForUkeyDriver`**（26 新接口可携带）；`openUkeyAuthDialog`（since-22 已发布）折叠 **-1017→29700002、-1018→29700003**（消息注明原因）。原 v3 "argc==1 无 context 重载携带专属码" 随该重载删除而失效 | API 治理：已发布接口 throws 面不新增成员；新接口可携带 |
| D9 | ~~请求字段面~~ | ~~`scene`/`customData`~~ → **v4：`UkeyAuthRequest = { keyUri, timeoutDuration?, customData? }`，`scene` 字段与 `UkeyAuthScene` 枚举全链路删除**（D21） | v4 简化方案 |
| D10 | ~~rule 3/6 错误码~~ | **v4：rule 3（Custom 未注册）随 scene 删除而消失**；rule 6（非 PC 拉 UIExtension → 29700005）**按接口分叉（D25 v2）**：ForDriver 拒 29700005，openUkeyAuthDialog 改为 Kit 回退默认弹框 | — |
| D11 | 非法参数错误码 | request 解析失败 → 29700006；`abilityType` 非枚举值 → **401**（D23）；argc 不匹配 → 401 | 与既有 NAPI 约定一致 |
| D12 | 29700008 处置 | 已删除（v3），维持 | — |
| D13 | ~~scene 校验时机~~ | **v4 失效**（scene 删除） | — |
| D14 | ~~默认弹框结果回传~~ | **v4 废止（D22）**：默认弹框路径整体删除；`com.ohos.certmanager/UkeyAuthExtensionAbility`（user_certificate_manager ukey-auth 分支）变为不可达死代码，分支保留不动、不随 v4 交付 | 简化方案裁定 SA 不再拉默认弹框 |
| D15 | PC 判定口径 | `GetDeviceType()=="2in1"` **或** `GetBoolParameter("persist.sceneboard.ispcmode", false)`，实时读，SA 侧可注入 seam | 不变 |
| D16 | ~~联调桩~~ | 已移除（v3） | — |
| D17 | ~~sceneType 中间形态~~ | 被 D19 替代 → 又被 D21 删除 | — |
| D18 | ~~customData×默认弹框~~ | **v4 失效**：customData 一律送达弹框（唯一形态即驱动自定义弹框） | — |
| D19 | customData 限额 | 原始字节 ≤ 2048，超限 29700006 | 不变 |
| D20 | 路由权威 | SA 自行查询 ability 信息决定拉起目标，不信任客户端声明。**v4 补充**：`openAuthDialogForUkeyDriver` 的拉起目标由 **IPC token 包名 + 入参 abilityName** 构成（bundle 不可伪造），BMS 校验兜底（D23） | Kit 上传任意 bundle/ability = 提权风险 |
| D21 | v4 接口面收敛 | **删除**：无 context 重载 `openUkeyAuthDialog(ukeyAuthRequest)`（26 未发布，干净删除）、`UkeyAuthScene` 枚举、`UkeyAuthRequest.scene`、d.ts 老接口中 Custom/默认弹框相关 throws 描述 | 简化方案第 1、2 条 |
| D22 | openUkeyAuthDialog 语义收窄 | **仅支持驱动注册的 UIExtensionAbility（PC/PC 模式）**：Kit 查询失败（未注册）→ 同步 29700003（-1019 改名 `NOT_REGISTERED`）；type=UIAbility(0) → 同步 29700003（-1021，文案去掉 no-context 措辞）；type=UIExtension(1) 且 PC → 走 SA；**type=UIExtension(1) 且非 PC → Kit 直启默认弹框（D25 v2）**。SA 复查同矩阵（纵深防御，-1020 保留为竞态防御）。**SA 侧默认弹框拉起与 Kit 侧 UIAbility 直启代码删除；Kit 侧默认弹框直启（GetDefaultAuthCertWant + StartUIExtensionAbility，since-22 既有机制）保留专用于非 PC 回退** | 简化方案第 2 条 + 2026-09-17 非 PC 回退增补 |
| D23 | 新增 openAuthDialogForUkeyDriver | 签名 `openAuthDialogForUkeyDriver(dialogInfo: UkeyAuthDialogInfo, ukeyAuthRequest: UkeyAuthRequest): Promise<void>`。校验链：① NAPI 解析（dialogInfo 两字段必填；abilityType 类型错（非 number）→ **401 同步**，number 但非有效枚举值 → **29700006**（v4.1 用户裁定）；abilityName 非空 ≤256B）② NAPI 预检 `CRYPTO_EXTENSION_REGISTER`（进程内 AccessTokenKit）→ 失败 **201 同步** ③ SA：IPC token 取调用方 bundleName（`GetHapTokenInfo`，模式同 Report）+ 复检权限（纵深防御）④ **BMS 预校验**（用户裁定）：`(bundleName, abilityName)` 存在且类型为 UIExtensionAbility，否则 29700003——坏 abilityName 立即报错而非等 5 分钟总超时；BMS 查询 userId 经 `CmGetProcessInfoForIPC` 获取（IPC 层解析传入）⑤ PC 门禁 ⑥ systemui 拉起。SA 侧 abilityType 防御拒绝用 -1014（29700006） | 简化方案第 3、4 条 + BMS 裁定（2026-09-17）+ v4.1 裁定修正 |
| D24 | 新增类型面 | `enum AbilityType { UKEY_AUTH_EXTENSION_ABILITY = 1 }`（用户裁定取 1，对齐 HUKS 内部 0=UIAbility/1=UIExtension，免映射）；`interface UkeyAuthDialogInfo { abilityType: AbilityType; abilityName: string }`（abilityType 在前，用户指定）；inner API 镜像 C 结构体 `UkeyAuthDialogInfo { CmBlob abilityName; uint32_t abilityType; }` | 用户裁定（2026-09-17） |
| D25 | PC 门禁适用范围 | **v2（2026-09-17 增补）按接口分叉**：`openUkeyAuthDialog` + UIExtension + **非 PC/非 PC 模式 → Kit 侧回退直启默认弹框**（`CmUkeyIsPcOrPcMode` 共享头函数，Kit 查询后判定；不走 SA、无 29700005；SA 侧 -1020 保留为竞态防御）；`openAuthDialogForUkeyDriver` **任何非 PC/非 PC 模式 → -1020 → 29700005**（驱动自拉起无回退）。v1 的"两接口统一 -1020"作废 | 非 PC 设备上普通应用的认证流程仍需可用（默认弹框兜底）；驱动自拉起场景明确要求 PC 形态 |
| D26 | 单飞/会话机制共享 | 两接口共用 SA 会话位与全部会话机制（超时/宽限/上报/死亡监听）；`-1018` 在 openUkeyAuthDialog 折叠 29700003、在 openAuthDialogForUkeyDriver 回 29700010（D8 v4） | 不变机制，归属调整 |

## 4. 总体架构与路由矩阵

### 4.1 路由矩阵（v4）

**openUkeyAuthDialog(context, ukeyAuthRequest)**（Kit 侧执行 `HksQueryAbilityInfo` + PC 判定）：

| 查询结果 | PC / PC 模式 | 非 PC 且非 PC 模式 |
|---|---|---|
| 查询失败（未注册） | **同步拒 29700003**（-1019，无 IPC 消耗） | 同左 |
| type = UIAbility (0) | **同步拒 29700003**（-1021，无 IPC 消耗） | 同左 |
| type = UIExtension (1) | 走 SA → SA 复查（含 -1020 竞态防御）→ systemui 拉起驱动扩展 | **Kit 直启系统默认弹框**（D25 v2：`GetDefaultAuthCertWant` → `com.ohos.certmanager/CertPickerUIExtAbility`（sys/commonUI，pageType=7）→ `StartUIExtensionAbility` 模态拉起；customData 静默丢弃（无消费方，D18 语义）；timeoutDuration 不生效（since-22 直启路径无会话机制）；结果经既有 UIExtension 回调回传 promise） |

SA 侧复查矩阵（收到 IPC 时 Kit 已确认 PC）：查询失败 → -1019；UIAbility → -1021；
UIExtension → -1020 防御（PC 模式竞态翻转的兜底）→ systemui 拉起。

**openAuthDialogForUkeyDriver(dialogInfo, ukeyAuthRequest)**（不经 HUKS 查询）：

```
NAPI/ANI: 解析(dialogInfo, request) → abilityType≠1 → 401 同步
         → CRYPTO_EXTENSION_REGISTER 预检失败 → 201 同步
         → IPC(OPEN_FOR_DRIVER: abilityName, abilityType, keyUri, timeout, customData, 回调stub)
SA:      GetCallingTokenID → GetHapTokenInfo → bundleName（仅 HAP token 放行）
         → CRYPTO_EXTENSION_REGISTER 复检 → 失败 -1011（201）
         → abilityType ≠ UIExtension → -1014（29700006，防御）
         → BMS: (bundleName, abilityName) 存在且 UIExtensionAbility？否 → 29700003
         → PC 门禁（-1020 / 29700005）→ 单飞 → systemui 拉起调用方扩展
```

要点：

- 同步应答仅承载即时校验结果（参数/权限/单飞/路由/BMS 拒绝）；同步回错不触发异步回调；
- 异步结果经客户端回调 stub 回传，恰好一次（成功/取消/失败/超时四选一）；
- 错误码折叠按接口（D8 v4）：openUkeyAuthDialog 折叠 -1017→29700002、-1018→29700003；
  openAuthDialogForUkeyDriver 回 29700009/29700010；
- 上报责任方：openUkeyAuthDialog 会话 owner = HUKS 查询所得驱动 bundle；
  openAuthDialogForUkeyDriver 会话 owner = **IPC token 调用方 bundle**。

### 4.2 SA 链路时序

```
应用(JS/ArkTS)   Kit(NAPI/ANI)        证书管理SA(3512)             系统弹窗服务(不改)      弹框提供方(驱动)
  │ openUkeyAuthDialog(ctx, req)         │                            │                    │
  ├───────────────>│ HksQueryAbilityInfo │                            │                    │
  │                │  ├─失败/UIAbility → 同步 29700003（无 IPC）      │                    │
  │                │  └─UIExtension: 非PC → Kit 直启默认弹框(D25 v2)  │                    │
  │                │     PC → IPC(OPEN: keyUri,timeout,customData,   │                    │
  │                │        回调stub)                                 │                    │
  │                ├─────────────────────>│ 权限/参数/单飞校验         │                    │
  │                │                      │ HksQueryAbilityInfo 复查  │                    │
  │                │                      │  ├─失败 → -1019；UIAbility → -1021             │
  │                │                      │  └─UIExtension: PC? 否→-1020                  │
  │                │                      │    生成 requestId,建会话,总超时                 │
  │                │                      │ ConnectServiceExtensionAbility(systemui)       │
  │                │                      │<─ 同步回执(0) ────────────┤ SendRequest(       │
  │                │                      │                            │  START_DIALOG,    │
  │                │                      │                            │  {bundle,ability, │
  │                │                      │                            │   params JSON})   │
  │                │                      │                            │──UIExtensionComponent→│
  │                │                      │                            │              (用户输入PIN)
  │                │                      │<══ CM_MSG_REPORT_UKEY_AUTH_RESULT ═════════════│
  │                │                      │ 校验 requestId + 上报者bundle == 会话 owner     │
  │                │<─ SendRequest(1,{code}) ─ 回调stub(TF_ASYNC)     │                    │
  │<─ resolve/reject │                    │                            │                    │
  │                │                      │ [兜底] 断连→10s宽限→取消；总超时→-1017          │

  openAuthDialogForUkeyDriver(dialogInfo, req)：同上 SA 段，仅查询段替换为
  「IPC token bundle + CRYPTO_EXTENSION_REGISTER 复检 + BMS 校验」，其余会话机制一致。
```

## 5. SDK 接口变更

### 5.1 `interface/sdk-js/api/@ohos.security.certManagerDialog.d.ts`（含中文镜像）

**删除**（D21，26.0.0 未发布，无兼容包袱）：

- `function openUkeyAuthDialog(ukeyAuthRequest: UkeyAuthRequest): Promise<void>` 整块；
- `export enum UkeyAuthScene` 整块；
- `UkeyAuthRequest.scene` 字段及注释。

**新增**（`@since 26.0.0 dynamic&static`）：

```ts
/**
 * Enumerates the types of the UKey PIN dialog ability.
 * Currently only the UIExtensionAbility type is supported.
 */
export enum AbilityType {
    /** UKey PIN dialog extension ability (UIExtensionAbility). */
    UKEY_AUTH_EXTENSION_ABILITY = 1,
}

/**
 * Information of the UKey driver's PIN dialog ability to launch.
 */
export interface UkeyAuthDialogInfo {
    /** Type of the PIN dialog ability. Only AbilityType.UKEY_AUTH_EXTENSION_ABILITY
     *  is supported; other values cause 29700006. */
    abilityType: AbilityType;
    /** Ability name of the driver's own UIExtensionAbility, within the caller's
     *  bundle (the bundle is resolved from the caller identity, not from this
     *  parameter). Non-empty, up to 256 bytes. */
    abilityName: string;
}

/**
 * Opens the UKey driver's own PIN authentication dialog (UIExtensionAbility).
 * Only the driver application holding this permission can call this API; the
 * dialog ability is resolved within the caller's own bundle.
 *
 * @permission ohos.permission.CRYPTO_EXTENSION_REGISTER
 * @param { UkeyAuthDialogInfo } dialogInfo - Information of the dialog ability.
 * @param { UkeyAuthRequest } ukeyAuthRequest - Authentication request information.
 * @returns { Promise<void> } Promise that returns no value.
 * @throws { BusinessError } 201 / 401 / 29700001 / 29700002 / 29700003 /
 *     29700005 / 29700006 / 29700009 / 29700010
 */
function openAuthDialogForUkeyDriver(dialogInfo: UkeyAuthDialogInfo,
    ukeyAuthRequest: UkeyAuthRequest): Promise<void>;
```

**修订**：`UkeyAuthRequest` 保留 `{ keyUri, timeoutDuration?, customData? }`（customData
注释改写：回退默认弹框时静默丢弃；timeoutDuration 注释注明仅对经系统弹窗服务拉起的
驱动弹框生效）；`openUkeyAuthDialog(context, ...)` JSDoc 语义改写为"拉起驱动注册的
UIExtensionAbility 弹框（PC/PC 模式）；非 PC 设备回退系统默认弹框；未注册或 UIAbility
类型时 29700003"——**其 29700005 throws 描述删除**（正常路径不再抛，-1020 仅存于 SA
竞态防御；26 未发布的描述变更）；`CertificateDialogErrorCode` 的 29700009/29700010 枚举
保留（归属新接口 throws 面）。

解析约定（NAPI/ANI 各实现，语义严格一致）：

| 字段 | 缺省 | 非法值 |
|---|---|---|
| `dialogInfo.abilityType` | 必填 | 非 number → **401**；number ≠ 1 → **29700006**（v4.1） |
| `dialogInfo.abilityName` | 必填 | 非字符串 / 空串 / > 256 字节 → 29700006 |
| `keyUri` | 必填 | 既有约定（≤256B） |
| `timeoutDuration` | 0（服务端默认） | 非 number → 29700006（既有） |
| `customData` | 无 | 非 Uint8Array / > 2048 → 29700006 |
| argc 不匹配（openUkeyAuthDialog ≠ 2 / ForDriver ≠ 2） | — | 401 |

### 5.2 ANI 侧

- `.ets` 声明（`interfaces/kits/ani/certificate_manager_dialog_ani/ets/`）同步：删无 context
  重载与 `UkeyAuthScene`/`scene`；增 `AbilityType`/`UkeyAuthDialogInfo`/
  `openAuthDialogForUkeyDriver`；
- **删除** `src/cm_open_ukey_auth_dialog_no_context.cpp`；
- `cm_dialog_ani.cpp`：openUkeyAuthDialog 路由简化（查询门禁）；新增 ForDriver 注册与解析。

## 6. 外部依赖契约（非本次交付）

### 6.1 HUKS（D3）

- `HksQueryAbilityInfo(resourceId, &abilityInfo)`：消费 `bundleName`/`abilityName`/
  `abilityType`（0=UIAbility / 1=UIExtensionAbility）；
- `HksAbilityInfo` 已增字段（huks `9b396d3b3`），**查询实现尚未填充**——未填充时保持 0，
  openUkeyAuthDialog 将全部被 -1021 拒绝（R12，该接口 E2E 的前置）；
- `openAuthDialogForUkeyDriver` **不依赖** HUKS 查询，可独立 E2E。

### 6.2 系统弹窗服务（只读复用，D4）

- 协议不变：连接成功后 `SendRequest(ON_ABILITY_CONNECT_DONE, {int32 size=3,
  ("bundleName", bundle), ("abilityName", ability), ("parameters", JSON)}, TF_ASYNC)`；
- **弹框 parameters JSON（v4）**（scene 字段删除）：

```json
{
  "keyUri": "<UKey 凭证唯一标识>",
  "appUid": <发起方应用 uid>,
  "requestId": "<32 字符 hex 会话标识>",
  "action": "UkeyPINAuth",
  "ability.want.params.uiExtensionType": "ukeyAuth",
  "timeout": <ms，归一化后实际超时>,
  "customData": "<base64，仅携带时存在>"
}
```

- ~~默认弹框 parameters JSON~~（D22 删除）。

### 6.3 弹框提供方契约

1. 认证流程结束后**先**上报（`CmReportUkeyAuthResult`；UIExtension 形态经框架
   `UkeyAuthExtensionContext.terminateSelf*` 自动完成），**再** terminateSelf；
2. 错误码协议：0 成功 / 29700002 取消 / 29700003 失败 / 29700006 参数错误 / 其余 29700001；
3. `customData`：want 参数键 `customData`，值为 base64 字符串，驱动自行解码；
   ~~scene 参数~~（v4 删除，demo 扩展侧同步移除读取）。

## 7. inner API（interfaces/innerkits/cert_manager_standard/main/include）

### 7.1 `cm_type.h`

```c
/* UKey 驱动弹框扩展信息（对齐 d.ts UkeyAuthDialogInfo，D24） */
struct UkeyAuthDialogInfo {
    struct CmBlob abilityName;   /* 驱动弹框扩展名，非空，≤256 字节，NUL 结尾 */
    uint32_t abilityType;        /* enum CmUkeyAbilityType，仅 CM_UKEY_ABILITY_TYPE_UIEXTENSION */
};

/* UKey Pin 码认证请求（v4：删 scene 字段） */
struct UkeyAuthRequest {
    struct CmBlob keyUri;        /* UKey 凭证唯一标识，最大 256 字节 */
    uint32_t timeoutDuration;    /* ms，0=服务端默认 300s，clamp [3min,10min] */
    struct CmBlob customData;    /* 原始字节，≤2048，可为空 */
};

/* 错误码段：-1019 语义改名（值不变） */
CMR_DIALOG_ERROR_NOT_REGISTERED = -1019        /* 未注册驱动弹框，或 ForDriver 指定扩展不存在/类型不符（→29700003） */
CMR_DIALOG_ERROR_NOT_PC_DEVICE = -1020         /* 非 PC 且非 PC 模式（→29700005） */
CMR_DIALOG_ERROR_UIABILITY_NOT_SUPPORTED = -1021 /* abilityType=UIAbility（→29700003） */
```

- **删除** `enum CmUkeyAuthScene` 与 `UkeyAuthRequest.scene`；
- `CmUkeyAbilityType` 常量（`cm_ukey_ability_type.h`）保留。

### 7.2 `cert_manager_api.h`

```c
/* 既有（v4：结构体少一个字段，签名不变） */
CM_API_EXPORT int32_t CmOpenUkeyAuthDialog(const struct UkeyAuthRequest *ukeyAuthRequest,
    CmUkeyDialogResultCallback callback, void *userData);

/* 新增（D23/D24） */
CM_API_EXPORT int32_t CmOpenUkeyAuthDialogForDriver(const struct UkeyAuthDialogInfo *dialogInfo,
    const struct UkeyAuthRequest *ukeyAuthRequest, CmUkeyDialogResultCallback callback,
    void *userData);

CM_API_EXPORT int32_t CmReportUkeyAuthResult(const struct CmBlob *requestId, int32_t resultCode);
```

## 8. IPC 协议（frameworks ↔ SA，CM 自有通道）

### 8.1 消息码

`CertManagerInterfaceCode` **追加**（`CM_MSG_MAX` 前，CODEOWNERS `@leonchan5` 审查）：

```c
CM_MSG_OPEN_UKEY_AUTH_DIALOG_FOR_DRIVER,
```

既有 `CM_MSG_OPEN_UKEY_AUTH_DIALOG` / `CM_MSG_REPORT_UKEY_AUTH_RESULT` 保留。

### 8.2 parcel 布局

| 消息 | 请求 paramSet | 同步应答 |
|---|---|---|
| OPEN（v4 去 scene，tag 重排） | `PARAM0_BUFFER keyUri` + `PARAM1_UINT32 timeoutDuration` + `PARAM2_BUFFER customData`（可选） | `[int32 同步校验码]` |
| **OPEN_FOR_DRIVER（新）** | `PARAM0_BUFFER abilityName` + `PARAM1_UINT32 abilityType` + `PARAM2_BUFFER keyUri` + `PARAM3_UINT32 timeoutDuration` + `PARAM4_BUFFER customData`（可选） | `[int32 同步校验码]` |
| REPORT | 不变 | 不变 |

回调 stub（`CM_UKEY_DIALOG_CALLBACK_CMD`，bare int32）与 29201 冷启动重试不变。

### 8.3 客户端（frameworks/.../os_dependency/cm_ipc/）

- `CmClientOpenUkeyAuthDialog`：组包去 scene，customData 改 P2；
- **新增** `CmClientOpenUkeyAuthDialogForDriver`（五参数一次性 `CmParamsToParamSet`，
  沿用 v3 缺陷修复结论——禁止追加式 AddParams 覆写已序列化数据）；
- base64 单一实现（frameworks/common）不变。

## 9. SA 侧详细设计

`services/cert_manager_standard/cert_manager_service/main/os_dependency/dialog/`。

### 9.1 模块构成

| 文件 | 职责（v4 增量） |
|---|---|
| `cm_ukey_auth_dialog_manager.h/.cpp` | 路由收敛为单一 UIExtension 拉起；`OpenDialog` 去 scene；**新增 `OpenDriverDialog`**（token bundle 由 IPC 层传入 + BMS 校验 seam + abilityType 防御）；PC 门禁两路共用；会话机制不变 |
| `cm_system_dialog_connection.h/.cpp` | 不变 |
| `cm_ukey_auth_dialog_ipc_service.cpp` | OPEN 处理器去 scene；**新增 OPEN_FOR_DRIVER 处理器**（权限复检 + `GetHapTokenInfo` 取 bundle + 转 manager） |
| `BUILD.gn` | **新增 bundleMgr 依赖**（BMS 预校验，R13） |

### 9.2 路由与拉起策略

```
OpenDialog(keyUri, callerUid, timeoutMs, customData, clientCallback):     /* openUkeyAuthDialog */
    参数校验（keyUri/customData ≤2048）→ 单飞（-1018）
    querier(keyUri) → {bundle, ability, type}:
      查询失败      → return -1019
      type==UIABILITY → return -1021
      type==UIEXTENSION → pcChecker()==false → return -1020
    → CommonLaunch(driver bundle/ability, params{§6.2 JSON, 无 scene})

OpenDriverDialog(abilityName, abilityType, keyUri, callerUid, callerBundle,
                 timeoutMs, customData, clientCallback):            /* ForDriver */
    参数校验 → 单飞（-1018）
    abilityType ≠ UIEXTENSION → return -1014
    abilityChecker(callerBundle, abilityName) == false → return -1019   /* BMS 拒绝，语义并入 NOT_REGISTERED */
      （BMS：QueryExtensionAbilityInfos(bundle, ability) 存在且类型 UIExtension；
        seam 注入 SetDriverAbilityChecker 供单测）
    pcChecker()==false → return -1020
    → CommonLaunch(callerBundle/abilityName, params{§6.2 JSON})

CommonLaunch: requestId(CSPRNG fail-closed) → 建会话(state=LAUNCHING, owner=bundle)
    → ConnectServiceExtensionAbility(systemui) → START_DIALOG → 总超时 → WAITING_REPORT
```

- `UkeyAuthSession`：**删 `scene` 与 `DialogKind` 字段**（唯一形态，不再需要分型）；
  `ownerBundleName` 两路分别为 HUKS 查询 bundle / IPC token bundle；其余机制不变；
- 上报校验（D7）：reporter HAP bundle == session.owner + requestId 在会话 + resultCode 白名单；
- 总超时/单飞/保活/死亡监听/宽限机制对两接口通用。

### 9.3 其他横切关注点

- customData 原始字节仅参数构造期持有，不持久化不打内容日志，释放前 memset_s（R10）；
- SA 保活/专用 EventHandler/ResetCallingIdentity 沿用；
- SELinux：systemui 路径既有项（联调 setenforce 0，固化遗留）；**v4 删除 StartAbility 路径
  后 R9 的 ability_mgr 规则需求随之消失**；
- `cert_manager_service.cfg`：v4 分支已删 `START_ABILITIES_FROM_BACKGROUND`，维持。

## 10. Kit 层（NAPI/ANI）改造

### 10.1 `cm_dialog_api_common`（kits/common）

- **删除**：`GetCustomerAuthCertWant` 的 **UIAbility 直启 want 分支**（查询成功分支）与
  scene 形参、`CM_UKEY_SCENE_*`/`CmUkeySceneToString`/`CmUkeySceneIsValid`（含
  `cm_ukey_dialog_common.h` 共享常量同步清理）；
- **保留**：`GetDefaultAuthCertWant` 默认弹框 want 构造（去 scene；D25 v2 回退路径消费）
  与 `GetUkeyAbilityInfo`（查询门禁用）；
- 错误码映射：`-1019 → 29700003`（语义改名 NOT_REGISTERED，涵盖"未注册"与"ForDriver
  指定扩展不存在/类型不符"）、`-1021 → 29700003`（文案去 no-context 措辞）、
  `-1020 → 29700005` 不变（ForDriver 正常路径 + openUkeyAuthDialog SA 竞态防御）。

### 10.2 NAPI `cm_napi_open_ukey_auth_dialog.cpp`（+ 新增 ForDriver 注册）

```
CMNapiOpenUkeyAuthorizeDialog:                      /* openUkeyAuthDialog */
    argc 校验（==2，否则 401）
    解析 UkeyAuthRequest（keyUri/timeoutDuration/customData）
    ACCESS_CERT_MANAGER 预检（既有）
    GetUkeyAbilityInfo(keyUri):
      失败       → 同步 reject 29700003（-1019 映射，无 IPC）
      UIAbility  → 同步 reject 29700003（-1021 映射，无 IPC）
      UIExtension:
        CmUkeyIsPcOrPcMode() == true  → CmOpenUkeyAuthDialog → IPC → SA
        CmUkeyIsPcOrPcMode() == false → 默认弹框直启（D25 v2）：GetDefaultAuthCertWant
                                        → StartUIExtensionAbility → 既有回调回 promise
                                        （customData 丢弃；无 SA 会话/超时机制）
    结果回调（SA 路径）：-1017→29700002、-1018→29700003（D8 v4 折叠，消息注明原因）

CMNapiOpenAuthDialogForUkeyDriver:                  /* 新增，cm_napi.cpp 注册表登记 */
    argc 校验（==2）→ 解析 UkeyAuthDialogInfo + UkeyAuthRequest
    abilityType ≠ UKEY_AUTH_EXTENSION_ABILITY → 401 同步
    CRYPTO_EXTENSION_REGISTER 预检（AccessTokenKit，进程内）→ 失败 201 同步
    → CmOpenUkeyAuthDialogForDriver → IPC → SA（非 PC → -1020 → 29700005，无回退）
    结果回调：29700009/29700010 专属码直通
```

- metrics：`openUkeyAuthDialog`（既有）+ `openAuthDialogForUkeyDriver`（新增）；
- ANI 两实现与 NAPI 语义严格一致（含折叠归属）。

## 11. 错误码汇总（v4）

| 场景 | 内部码 | openUkeyAuthDialog | openAuthDialogForUkeyDriver |
|---|---|---|---|
| 未注册驱动弹框（查询失败） | -1019 | 29700003（Kit 同步） | —（不经 HUKS） |
| abilityType=UIAbility | -1021 | 29700003（Kit 同步；SA 复查） | — |
| BMS 校验失败（ability 不存在/非 UIExtension） | -1019 | — | 29700003 |
| SA 侧 abilityType 防御拒绝 | -1014 | 29700006 | 29700006 |
| 非 PC 且非 PC 模式 | -1020 | 仅 SA 竞态防御可达（正常路径 Kit 回退默认弹框，不报错） | 29700005（无回退） |
| 无 CRYPTO_EXTENSION_REGISTER | -1011 | — | **201**（NAPI 同步 + SA 复检） |
| 提供方超时未上报 | -1017 | 折叠 29700002（消息注明） | **29700009** |
| 单飞拒绝 | -1018 | 折叠 29700003（消息注明） | **29700010** |
| 断连宽限超时 | -1001 | 29700002 | 29700002 |
| 连接/命令/CSPRNG/上报校验失败 | -1000 | 29700001 | 29700001 |
| 提供方上报透传 | — | 29700003/29700006 | 29700003/29700006 |
| request 解析失败 / abilityName 非法 | -1014 | 29700006 | 29700006 |
| abilityType 类型错（非 number）/ argc 不匹配 | — | 401 | **401** |
| abilityType 枚举值非法（number ≠ 1，v4.1） | — | — | **29700006** |

## 12. 兼容性

- `openUkeyAuthDialog(context, ...)`（since-22）：**行为变化**——未注册驱动从"默认弹框/
  直启"变为同步 29700003；UIAbility 驱动从"直启"变为 29700003。此为简化方案有意为之
  （产品裁定），26 版本发布说明需记录；参数面仅少一个可选 `scene`（26 未发布）；
- 无 context 重载、`UkeyAuthScene`、29700008 均为 26 未发布面，删除无兼容包袱；
- inner `UkeyAuthRequest` 删 `scene` 字段：随源码树整体编译，源码级兼容；
- IPC：OPEN paramSet tag 重排 + 新增消息码——同版本配套发布，无新旧互通场景；
- 29700009/29700010 从（已删除的）无 context 重载 throws 面转移至 ForDriver throws 面
  （均 26 未发布）。

## 13. 测试与验证

- **单元测试**（`cm_ukey_auth_dialog_manager_test` 重排 + 新增）：
  - OpenDialog 路由：查询失败→-1019、UIAbility→-1021、UIExtension+PC true/false、
    customData 参数、单飞；
  - OpenDriverDialog 新组：abilityType≠UIEXTENSION→-1014、BMS checker 注入
    false→29700003 映射、PC 门禁、单飞与 OpenDialog 互斥共享、owner=caller bundle
    的上报校验（HUKS bundle 上报被拒）、params JSON 无 scene 断言；
  - 会话机制回归：超时/宽限/死亡监听/保活/requestId CSPRNG；
  - NAPI/ANI 解析：abilityType 0/1/2/非 number、abilityName 空/257B、customData 边界。
- **real-IPC 探针**（`cm_ukey_auth_dialog_real_ipc_test`）：老探针预期更新
  （无驱动注册 → **同步 -1019**，不再有默认弹框会话）；新增 ForDriver 探针
  （nativetoken 授 `CRYPTO_EXTENSION_REGISTER`）。
- **构建验证**：`--build-target certificate_manager --build-target cm_sdk_test`
  （部件级全量）+ d.ts/ets 变更目视核对。
- **真机 E2E**（rk3568，`setenforce 0`；`param set persist.sceneboard.ispcmode true/false`）：
  - ForDriver 全链路（**不依赖 HUKS 填充，优先验证**）：demo 改调
    `openAuthDialogForUkeyDriver({abilityType:1, abilityName:'MyUkeyAuthExtensionAbility'}, req)`
    → SA → BMS 校验 → systemui 拉起 → demo 扩展上报 → 回调 resolve；非 PC → 29700005；
    坏 abilityName → 29700003；无权限（卸 ACL 签名）→ 201；
  - openUkeyAuthDialog：依赖 HUKS 填充 abilityType=1（R12），联调时 HUKS 侧临时配合；
    PC 模式 → SA → systemui 拉起驱动扩展；**非 PC 模式 → Kit 直启默认弹框**
    （CertPickerUIExtAbility 模态，customData 不携带，结果经既有回调回 promise）；
    未注册 → 同步 29700003；
  - 单测真机回归（目标全绿）。

## 14. 风险与遗留事项

| # | 风险/事项 | 缓解 |
|---|---|---|
| ~~R1~~ | UIAbility-no-context 上报通道 | **v4 解决（路径删除）**：UIAbility 形态全面不支持 |
| R2 | 提供方"先上报后终止"契约 | 10s 宽限兜底；契约 §6.3 |
| ~~R7/R8~~ | 默认弹框 systemui 拉起/上报桥 | **v4 失效（SA 侧默认弹框拉起删除）**；Kit 直启默认弹框（CertPickerUIExtAbility，since-22 既有）随 D25 v2 恢复使用；user_certificate_manager ukey-auth 分支的 UkeyAuthExtensionAbility 留作死代码 |
| ~~R9~~ | StartAbility SELinux/cfg | **v4 失效（路径删除，ukey-no-uiability 分支已清理 cfg/依赖）** |
| R10 | customData 隐私 | 不变（§9.3） |
| ~~R11~~ | UIAbility demo 形态 | **v4 失效** |
| **R12** | **HUKS 查询实现未填充 abilityType**（零初始化=0=UIAbility）→ openUkeyAuthDialog 全链路被 -1021 拒 | HUKS 仓后续项；联调临时配合；ForDriver 接口不受影响 |
| **R13** | BMS 预校验为 SA dialog 库新增 bundleMgr 依赖（`QueryExtensionAbilityInfos`），需确认 SA 侧可用 API 与依赖装配 | 实现期核实（spec §9.1）；seam 注入隔离 |
| **R14** | `CRYPTO_EXTENSION_REGISTER` 为 system_basic+ACL 权限：demo 应用需带 ACL 的签名 profile 方可 E2E；三方驱动分发需 ACL 流程 | RK3568 调试签名 + ACL；产品侧文档 |
| R15 | systemui START_SYSTEM_DIALOG 权限正式方案（hvigor）与 SELinux 固化 | 既有遗留，不变 |
| R16 | d.ts 删除已推送分支上的未发布接口（no-context/scene） | 26 未发布，PR 内干净删除即可 |

## 15. 参考实现索引

| 参考点 | 位置 |
|---|---|
| ability 查询适配（Kit/SA 两处） | interfaces/kits/common/src/cm_dialog_api_common.cpp；services/.../dialog/cm_ukey_auth_dialog_manager.cpp |
| IPC token 取调用方 bundle（SA） | services/.../idl/cm_ipc/cm_ukey_auth_dialog_ipc_service.cpp（ReportUkeyAuthResult 处理器） |
| HUKS external crypto 权限模式（CRYPTO_EXTENSION_REGISTER d.ts 注记 + 201） | interface/sdk-js/api/@ohos.security.huksExternalCrypto.d.ts:203 |
| systemui 通用宿主协议 | applications/standard/systemui/product/default/dialog/src/main/ets/ServiceExtAbility/ExtAbility.ts:34 |
| AMS 对 ukeyAuth 扩展的权限校验 | foundation/ability/ability_runtime/services/abilitymgr/src/ability_manager_service.cpp:13245 |
| 会话管理器（requestId CSPRNG fail-closed） | services/.../os_dependency/dialog/cm_ukey_auth_dialog_manager.cpp |
| 既有 openUkeyAuthDialog NAPI 流程 | interfaces/kits/napi/src/dialog/cm_napi_open_ukey_auth_dialog.cpp |
| NAPI 注册表（新增 ForDriver 登记） | interfaces/kits/napi/src/cm_napi.cpp（NAPI_FUNC_DESC） |
| IPC 消息码（追加位置，CODEOWNERS） | frameworks/.../include/cert_manager_service_ipc_interface_code.h:55 |
| 驱动 want 契约与错误码协议 | docs/zh-cn/application-dev/reference/apis-universal-keystore-kit/js-apis-huksExternalCrypto.md |
| ANI 声明副本 | interfaces/kits/ani/certificate_manager_dialog_ani/ets/@ohos.security.certManagerDialog.ets |

## 16. 交付物清单（v4 增量，file-level）

| 模块 | 文件 | 变更 |
|---|---|---|
| SDK | interface/sdk-js api + zh-cn/api `@ohos.security.certManagerDialog.d.ts` | 删无 context 重载/UkeyAuthScene/scene；增 AbilityType/UkeyAuthDialogInfo/openAuthDialogForUkeyDriver；老接口 JSDoc 改写 |
| inner API | cm_type.h / cert_manager_api.{h,c} | UkeyAuthRequest 删 scene；删 CmUkeyAuthScene；增 UkeyAuthDialogInfo + CmOpenUkeyAuthDialogForDriver；-1019 改名 |
| IPC 消息码 | cert_manager_service_ipc_interface_code.h | 增 CM_MSG_OPEN_UKEY_AUTH_DIALOG_FOR_DRIVER |
| IPC 客户端 | cm_ipc_dialog_client.cpp + serialization | OPEN 去 scene；新增 ForDriver 组包 |
| SA | cm_ukey_auth_dialog_manager.{h,cpp} | 路由收敛；OpenDriverDialog + BMS seam；删默认弹框/scene |
| SA IPC | cm_ukey_auth_dialog_ipc_service.{h,cpp} | OPEN 去 scene；新增 ForDriver 处理器（权限 + token bundle） |
| SA 构建 | dialog/BUILD.gn | 增 bundleMgr 依赖 |
| 共享常量 | cm_ukey_dialog_common.h / cm_ukey_ability_type.h | 删 scene 常量/默认弹框常量 |
| kits/common | cm_dialog_api_common.{h,cpp} | 删 UIAbility 直启 want 与 scene；保留 GetDefaultAuthCertWant（非 PC 回退）；映射表修订 |
| NAPI | cm_napi.cpp + cm_napi_open_ukey_auth_dialog.cpp | 路由收敛 + ForDriver 新增 |
| ANI | cm_dialog_ani.cpp + 删 cm_open_ukey_auth_dialog_no_context.cpp + ets | 同 NAPI |
| 测试 | cm_ukey_auth_dialog_manager_test.cpp / cm_ukey_auth_dialog_real_ipc_test.cpp / fuzz | §13 增量 |
| 联调 | /mnt/d/workspace/UkeyAuthAbility2（demo） | 改调 ForDriver；module.json 增 CRYPTO_EXTENSION_REGISTER（ACL 签名） |

## 17. 实现状态

**v1–v3 已交付并真机验证**（详见 git 历史：master 分支 `24552d3`…`506be4d`；
ukey-no-uiability 分支 `b752c27`；interface_sdk-js ukey-auth 分支 `8ac23e3f2`）：
SA 会话机制全量、systemui 拉起、v3 场景路由与 customData 全链路 E2E、
ukey-no-uiability 分支的 SA 侧 UIAbility 拒绝（-1021）与 StartAbility 移除、
29/29 单测 + real-IPC 探针通过。

**v4（简化方案）已实现**——certificate_manager `ukey-kits-migration` 分支 8 个提交
（`e042d49..13ebd22`，含最终评审修复提交）：`0631154` SA 侧 ForDriver 开窗 +
BMS 预校验、`4008727` openAuthDialogForUkeyDriver inner API + IPC 通道、`db4d18b`
NAPI ForDriver、`43adc40` DialogInfo 解析错误码按 spec 拆分、`deb3c4b` 超长
abilityName 前置拒绝、`e226496` ANI ForDriver、`fe909aa` 删除 scene/无 context
重载（仅 UIExtension 路由）、`13ebd22` 最终评审修复（ANI 负路径错误码映射、
abilityName 边界 129、孤儿常量清理）；interface_sdk-js `ukey-auth` 分支 3 个提交
（`487e40ca2..8564bfb5a`：ForDriver 声明、scene/无 context 重载移除、29700009
stale throws 清理）。
真机单测 38/38 通过（33 manager + 5 real-IPC，含 ForDriver/权限探针与
abilityName 边界用例；修复波后全量回归）。
demo 已改造（openAuthDialogForUkeyDriver + CRYPTO_EXTENSION_REGISTER，待 ACL
签名重打包）。延期项：NAPI/ANI 层 parse 测试按无测试桩现实以真机 JS smoke
替代（§13 偏差）；E2E 矩阵（ForDriver happy path + 非 PC 回退）待 demo 重打包
后执行（R12/R14）。
