# openUkeyAuthDialog 支持 UKey 驱动自定义 UIExtensionAbility Pin 码认证弹框 — 详细设计

- 日期：2026-09-03（v3 修订：2026-09-15）
- 状态：基线特性已实现并真机验证（§17）；v3 修订（场景路由 + customData）待实现
- 需求来源：`cm_ukey_pin_design.txt`（基线）；2026-09-15 方案变更指示（场景类型/自定义数据/三种弹框路由）
- 涉及仓库：`base/security/certificate_manager`（主交付）、`interface/sdk-js`（SDK d.ts）、
  `applications/standard/user_certificate_manager`（默认弹框上报桥，TEMP 联调项）；
  `base/security/huks`、`applications/standard/systemui` 为外部依赖，**不在本次交付范围**

## 修订记录

| 版本 | 日期 | 内容 |
|---|---|---|
| v1 | 2026-09-03 | 基线设计（无 context 重载 + UIExtensionAbility 经系统弹窗服务） |
| v2 | 2026-09-11 | D3 修订（abilityType 方案）、D2 修订（公开 report API 收窄为 inner）、超时参数（10 分钟）、requestId CSPRNG fail-closed |
| v3 | 2026-09-15 | **场景路由修订（D9–D19）**：`UkeyAuthRequest` 增 `scene`/`customData` 字段；路由按查询结果三分（默认/UIAbility/UIExtension）；默认弹框与 UIAbility 支持无 context SA 拉起；UIExtension 加 PC/PC 模式门禁；删除 29700008；联调桩运行时旋钮 |

## 1. 背景与目标

证书管理已提供 `openUkeyAuthDialog(context, ukeyAuthRequest)` 接口拉起 UKey Pin 码认证弹框：

- 该接口必须传入应用 context；
- 自定义弹框场景下只支持拉起 UKey 驱动注册的 **UIAbility**。

v1/v2 已交付：无 context 重载经 SA + 系统弹窗服务拉起驱动 UIExtensionAbility、requestId
会话/上报/超时机制。v3 增补需求：

1. `UkeyAuthRequest` 增加 **场景类型 `scene`**（缺省 `Login`）与 **自定义数据
   `customData`**（≤ 2048 字节，base64 编码后下发自定义弹框）；
2. SA 依据 ability 查询结果路由：**未注册 → 系统默认弹框**（`com.ohos.certmanager`）；
   **UIAbility → SA StartAbility 拉起**；**UIExtensionAbility → 经系统弹窗服务拉起**（不变）；
3. `scene == 'Custom'`（声明仅用自定义弹框）而查询结果需要默认弹框时，同步回 29700004；
4. UIExtension 路径（无论有无 context）须设备为 **PC（2in1）或处于 PC 模式**，否则 29700004。

## 2. 术语

| 术语 | 含义 |
|---|---|
| CM / 证书管理 SA | CertManagerService，SA ID 3512（注册见 services/.../sa/cm_sa.cpp） |
| 系统弹窗服务 | `com.ohos.systemui` / `com.ohos.systemui.dialog`（ServiceExtensionAbility），创建系统浮窗并以 `UIExtensionComponent` 承载目标 UIExtensionAbility；**通用宿主，无类型注册表** |
| 驱动应用 | 通过 HUKS `registerProvider` 注册 Pin 码弹框能力的 UKey 厂商 HAP 应用 |
| 老接口 | `openUkeyAuthDialog(context, ukeyAuthRequest)`（argc==2） |
| 新接口 | `openUkeyAuthDialog(ukeyAuthRequest)`（argc==1） |
| 会话 | 一次 SA 链路弹框请求在 SA 侧的完整生命周期（requestId 标识） |
| 默认弹框 | `com.ohos.certmanager` / `CertPickerUIExtAbility`（`sys/commonUI` 类型，pageType=7），CM 自有 UIExtensionAbility |
| 场景 | `UkeyAuthScene`：`Login`（接受默认弹框回退）/ `Custom`（仅自定义弹框） |
| 自定义数据 | `customData`，调用方原始字节（≤2048），base64 后写入自定义弹框 want 的 `customData` 参数 |
| PC/PC 模式 | `const.product.devicetype == "2in1"`，或 `persist.sceneboard.ispcmode == true`（D15） |

## 3. 设计决策记录

| # | 决策点 | 结论 | 理由 |
|---|---|---|---|
| D1 | 弹框承载方式 | SA 连接系统弹窗服务拉起 UIExtensionAbility（参考 useriam `widget_context.cpp`） | 调用方无 context，无法走 `CreateModalUIExtension` / `StartAbilityForResult`；系统弹窗服务是既有的无 context 模态弹窗通道 |
| D2 | 结果回传通道 | **修订（2026-09-11）**：驱动弹框主动上报——SA 生成 requestId 随弹框参数下发，提供方完成后调用 inner API `CmReportUkeyAuthResult(requestId, resultCode)` 上报，SA 校验后回调客户端。**公开 `reportUkeyAuthResult` d.ts/NAPI/ANI 面已删除**，仅保留 inner API（三方驱动的公开上报通道为遗留项 R1） | systemui 转发（改 systemui 仓）与轮询推导被否；公开面经评审收敛为 inner，等驱动侧通道定论后再评估是否公开 |
| D3 | HUKS 范围 | **v2（2026-09-11）**：SA 与 Kit 侧均消费查询返回的 `abilityType`（0=UIAbility，1=UIExtensionAbility）；本树 HUKS `HksAbilityInfo` 尚无该字段，非桩路径暂返回 UIAbility，联调由桩支撑（D16） | HUKS 字段合入后仅需替换适配处（常量集中 `frameworks/.../common/include/cm_ukey_ability_type.h`） |
| D4 | systemui 范围 | 系统弹窗服务**只读复用**现有 `COMMAND_START_DIALOG` 协议，仓零改动 | 需求边界明确；宿主对 bundle/ability/parameters 完全通用（含默认弹框与 ukeyAuth 扩展） |
| D5 | 超时参数 | **修订**：总超时 **10 分钟**（`CM_UKEY_DIALOG_MAX_TOTAL_TIMEOUT_MS = 600000`，请求 `timeout`（ms）可指定，超上限 clamp，0=服务端默认最大）；断连后上报宽限期 **10 秒**；客户端兜底 timer 11 分钟 | 评审定值；v1 暂定的 5 分钟被 10 分钟取代 |
| D6 | 并发约束 | SA 侧全局单飞：同一时刻仅允许一个挂起会话（含三种弹框类型） | 系统弹窗 remote object 按连接方维度共享；模态全屏弹窗互斥 |
| D7 | report 权限 | 不加权限，安全由 requestId CSPRNG 随机性 + 上报者 bundleName 双重校验保障 | 驱动为三方 HAP，通常不持有 `ACCESS_CERT_MANAGER` |
| D8 | 错误码细分 | 提供方超时未上报 → **29700009**；单飞拒绝 → **29700010**；断连宽限超时仍归 29700002 | 专属错误码便于定位，不再折叠为 29700001 |
| D9 | 请求字段面 | **v3（2026-09-15，三轮收敛）**：`UkeyAuthRequest = { keyUri, timeout?, scene?, customData? }`。`scene?: UkeyAuthScene`（`'Login'` 缺省 / `'Custom'`）；`customData?: Uint8Array`（原始字节 ≤2048，仅下发自定义弹框）。中间形态 `supportDefaultDialog: boolean`、`sceneName: UkeyAuthSceneName\|string`（及 `UkeyAuthSceneName` 枚举、`UkeyAuthSceneType` 命名）经 2026-09-15 两轮修订**全部被替代删除**——场景语义并入 `scene` 枚举，自由串场景参数并入 `customData` | 用户裁定：布尔开关升级为场景枚举；场景名与自定义数据合并为单一 `customData` 通道；拼写修正 Sence/Scen→Scene |
| D10 | rule 3/6 错误码 | 需默认弹框但 `scene=='Custom'`（不支持默认）→ 29700004；非 PC 且非 PC 模式拉 UIExtension → 29700004 | **推翻来文指定的 29700005**（现语义为 GLOBAL_USER 安全策略）；29700004（设备不支持）语义贴合，用户裁定采纳 |
| D11 | 非法参数错误码 | `scene` 非枚举值 / `customData` 超限或类型错 → 29700006（沿用本 API 既有约定：request 解析失败 29700006，argc 不匹配 401） | 与既有 NAPI 解析约定一致 |
| D12 | 29700008 处置 | **删除** `CMR_DIALOG_ERROR_UKEY_ABILITY_NOT_SUPPORTED`(-1016) 与 JS 码 29700008（枚举、d.ts throws、映射表、单测用例一并清理） | 新方案下触发条件消失（未注册→默认弹框或 29700004）；26.0.0 未发布无兼容包袱 |
| D13 | scene 校验时机 | ~~flag=true 时解析期校验 sceneName~~ **被 D9 替代**：`scene` 为纯枚举，解析期校验 ∈{'Login','Custom'}（两重载一致），SA 侧 IPC 到达后对 uint32 值再校验一道（纵深防御） | 纯枚举无自由串，校验简化 |
| D14 | 默认弹框结果回传 | SA 拉起的默认弹框：参数带 requestId，`com.ohos.certmanager` 完成后经 inner API `CmReportUkeyAuthResult` 上报（TEMP：user_certificate_manager 仓加 native 桥接模块联调；上游化需产品侧对齐） | 与驱动弹框回传统一；systemui 现有 remote 转发通道（COMMAND_SEND_REMOTE_OBJECT/ExtIndex.onOk）系统内从未启用，风险高被否 |
| D15 | PC 判定口径 | `OHOS::system::GetDeviceType() == "2in1"` **或** `GetBoolParameter("persist.sceneboard.ispcmode", false)`，**每次调用实时读**（模式可运行时切换）；仅 SA 侧判定，做成可注入 seam 供单测；rk3568 联调用 `param set persist.sceneboard.ispcmode true` 切换分支 | 2in1 为 PC 形态权威值（render_service 亦接受 "pc"，本设计不采纳）；ispcmode 为 WMS/ace/RS/powermgr 共同消费的 PC 模式权威信号 |
| D16 | 联调桩旋钮 | `CERT_MANAGER_UKEY_ABILITY_QUERY_STUB` 下读 `persist.security.cm.ukey_stub_type`：`uiextension`（缺省/未知值）固定返回 UIExtension 三元组；`uiability` 返回 UIAbility 三元组；`none` 返回查询失败（未注册）。Kit 与 SA 两处桩同源读同一参数；仍由 GN feature `certificate_manager_ukey_ability_stub` 门控（TEMP，上游 PR 前移除） | 一次刷机覆盖全部路由分支，避免逐路径重编重刷 |
| D17 | ~~sceneType 枚举替代布尔~~ | **被 D19 替代**（中间形态：`UkeyAuthSceneType{Login,Custom}` + `customData` 1MiB） | — |
| D18 | customData×默认弹框 | `scene=='Login'` 且实际拉起默认弹框时，customData **静默丢弃**（记日志与长度）；默认弹框 want 不携带 customData。拒绝组合方案（报错）被否 | LOGIN 本身声明"可接受默认回退"，回退时数据无消费方；拒绝组合过度约束 |
| D19 | customData 限额 | **原始字节 ≤ 2048**（base64 后约 2.7KB 字符串）；超限 29700006。1MiB 中间值被否（满尺寸 parcel/JSON 链路风险 + SA 内存峰值） | 用户裁定收窄；2KB 足够驱动业务透传 |
| D20 | 路由权威 | SA 自行查询 ability 信息并决定拉起方式，不信任客户端声明的 ability 信息；Kit 仅在带 context 时本地路由默认弹框/UIAbility 直启（since-22 现状） | Kit 上传拉起目标 = 恶意 app 可让 SA 以系统身份拉任意 ability（提权）；全部收编 SA 破坏 since-22 行为契约 |

## 4. 总体架构与路由矩阵

### 4.1 路由矩阵（核心）

ability 查询结果（SA 或 Kit 各自执行）：**查询失败=未注册→默认弹框**；成功+type=UIAbility(0)→UIAbility；
成功+type=UIExtension(1)→UIExtension。

| 查询结果 | 老接口（argc==2，有 context） | 新接口（argc==1，无 context） |
|---|---|---|
| 未注册（默认弹框） | Kit 直启 `com.ohos.certmanager`/`CertPickerUIExtAbility`（现状流程，want 增补 `scene`；customData 丢弃 D18）；若 `scene=='Custom'` → **同步抛 29700004** | SA 经系统弹窗服务拉起**同一默认弹框**（bundle/ability/type=`sys/commonUI`、pageType=7）；若 `scene=='Custom'` → 同步回 -1019/29700004 |
| UIAbility | Kit 直启（现状：action `UkeyPINAuth` want；**增补** scene + customData(base64) 参数） | SA `AbilityManagerClient::GetInstance()->StartAbility(want)`（want 含 driver bundle/ability、action、appUid、keyUri、requestId、scene、customData(base64)） |
| UIExtensionAbility | **忽略 context，走 SA**（D3 v2 现状）+ PC 门禁（D15，新增） | SA 经系统弹窗服务（现状）+ PC 门禁（新增）；非 PC 且非 PC 模式 → 同步回 -1020/29700004 |

要点：

- Kit 侧 `scene=='Custom'` + 查询未注册 → **解析后同步拒绝，无 IPC 消耗**（NAPI/ANI 直接抛）；
- SA 侧同样校验（老接口 UIExtension 委托路径、新接口全部路径）——纵深防御；
- PC 门禁仅作用于 UIExtension 路径（默认弹框与 UIAbility 不校验 PC）；
- 同步应答仅承载即时校验结果（参数/权限/单飞/路由拒绝）；同步回错时不触发异步回调；
- 异步结果经客户端回调 stub 回传，保证恰好一次（成功、取消、失败、超时四选一）。

### 4.2 SA 链路时序（三种弹框共用会话机制）

```
应用(JS/ArkTS)   Kit(NAPI/ANI)        证书管理SA(3512)             系统弹窗服务(不改)      弹框提供方
  │ openUkeyAuthDialog(req)              │                            │                  (驱动或certmanager)
  ├───────────────>│ IPC(OPEN: keyUri,timeout,scene,customData,回调stub) │                      │
  │                ├─────────────────────>│ 参数/权限/单飞校验           │                      │
  │                │                      │ scene∈枚举? customData≤2048?│                      │
  │                │                      │ HksQueryAbilityInfo(keyUri) │                      │
  │                │                      │  ├─ 未注册: scene==Custom? →同步回-1019(29700004)    │
  │                │                      │  ├─ 未注册: 默认弹框会话 → LaunchViaSystemDialog     │
  │                │                      │  │   {com.ohos.certmanager, CertPickerUIExtAbility,  │
  │                │                      │  │    sys/commonUI, pageType=7, keyUri,appUid,       │
  │                │                      │  │    requestId, scene}  [无 customData, D18]        │
  │                │                      │  ├─ UIAbility: UIAbility 会话 → StartAbility(want) ─────────────────>│
  │                │                      │  │   {driver bundle/ability, action:UkeyPINAuth,      │
  │                │                      │  │    appUid,keyUri,requestId,scene,customData(b64)}  │
  │                │                      │  └─ UIExtension: PC/PC模式? 否→同步回-1020(29700004)  │
  │                │                      │      UIExtension 会话 → ConnectServiceExtensionAbility│
  │                │                      │<─ 同步回执(0) ────────────┤ SendRequest(START_DIALOG,│
  │                │                      │ 生成 requestId,建会话,启动总超时(默认10min,clamp)     │
  │                │                      │                            │── UIExtensionComponent 装载 →│
  │                │                      │                            │                  (用户输入PIN)│
  │                │                      │<══ CM_MSG_REPORT_UKEY_AUTH_RESULT ════════════════════│
  │                │                      │  {requestId, resultCode}   CmReportUkeyAuthResult() │
  │                │                      │ 校验 requestId + 上报者bundle == 会话上报责任方bundle  │
  │                │                      │ → 完成会话(停定时器/断连/释放)                        │
  │                │<─ SendRequest(1,{code}) ─ 回调stub(TF_ASYNC)      │                      │
  │<─ resolve/reject │                    │                            │                      │
  │                │                      │ [兜底] 断连→10s宽限→取消(29700002)；总超时→29700009   │
```

## 5. SDK 接口变更

### 5.1 `interface/sdk-js/api/@ohos.security.certManagerDialog.d.ts`（含中文镜像）

新增枚举与字段（`@since 26.0.0 dynamic&static`）：

```ts
/**
 * Enumerates the scenarios of the USB Key PIN authentication.
 *
 * @syscap SystemCapability.Security.CertificateManagerDialog
 * @stagemodelonly
 * @since 26.0.0 dynamic&static
 */
export enum UkeyAuthScene {
    /**
     * Login scenario (mutual TLS or unlock). The system default PIN dialog is
     * used when the UKey driver has not registered a custom one.
     */
    LOGIN = 'Login',
    /**
     * Custom scenario. Only the UKey driver's custom dialog is used; the call
     * fails with 29700004 if no custom dialog is registered.
     */
    CUSTOM = 'Custom',
}

export interface UkeyAuthRequest {
    keyUri: string;                 // 既有
    timeout?: number;               // 既有（26.0.0）
    /**
     * Authentication scenario. Defaults to LOGIN.
     */
    scene?: UkeyAuthScene;
    /**
     * Custom data passed through to the driver's custom dialog (UIAbility or
     * UIExtensionAbility) as a base64-encoded string in want parameter
     * "customData". Up to 2048 bytes (raw). Not delivered to the system
     * default dialog (dropped silently).
     */
    customData?: Uint8Array;
}
```

老接口（argc==2）`@throws` 增补：29700004（Custom 场景无自定义弹框 / 非 PC 设备 UIExtension）、
29700009、29700010（UIExtension 委托 SA 会话后可产生）；新接口（argc==1）`@throws`
**删除 29700008**，增补 29700004。`CertificateDialogErrorCode`：删除
`ERROR_UKEY_ABILITY_NOT_SUPPORTED = 29700008`（26.0.0 未发布，无兼容包袱，D12）。

解析约定（两重载共用，NAPI/ANI 各实现，D11）：

| 字段 | 缺省 | 非法值 |
|---|---|---|
| `scene` | LOGIN | 非字符串 / 非 `'Login'`/`'Custom'`（大小写敏感）→ 29700006 |
| `customData` | 无 | 非 Uint8Array / 长度 > 2048 → 29700006 |
| argc 不匹配 | — | 401（沿用 `CheckUkeyAuthDialogArgc`） |

### 5.2 ANI 侧

- `.ets` 声明同步 `scene`/`customData` 字段与 `UkeyAuthScene` 枚举；
- `src/cm_open_ukey_auth_dialog.cpp`（老接口）与 `src/cm_open_ukey_auth_dialog_no_context.cpp`
  （新接口）解析逻辑各增补两字段（语义与 NAPI 严格一致）；
- base64 编码复用 frameworks/common 单一实现（见 §8.4）。

## 6. 外部依赖契约（非本次交付）

### 6.1 HUKS（D3 v2）

- 消费 `HksQueryAbilityInfo(resourceId, &abilityInfo)` 获取 `bundleName`/`abilityName`，
  并读取 `abilityType`（0=UIAbility / 1=UIExtensionAbility）；
- 本树 `struct HksAbilityInfo` 尚无 abilityType 字段：CM 侧非桩路径暂返回 UIAbility
  （常量与桩集中于 `frameworks/.../common/include/cm_ukey_ability_type.h`）；
- **联调桩（D16，TEMP）**：`persist.security.cm.ukey_stub_type` ∈
  {`uiextension`(缺省), `uiability`, `none`}，Kit 与 SA 两处桩同源；GN feature
  `certificate_manager_ukey_ability_stub`（cert_manager.gni）仍为总开关。

### 6.2 系统弹窗服务（只读复用，D4）

- 既有协议不变：连接成功后 `SendRequest(ON_ABILITY_CONNECT_DONE, {int32 size=3,
  ("bundleName", 目标bundle), ("abilityName", 目标ability), ("parameters", JSON字符串)},
  TF_ASYNC)`；服务创建浮窗并以 `UIExtensionComponent({bundleName, abilityName,
  parameters})` 原样装载（宿主对目标完全通用，无类型注册表）；
- **UIExtension 驱动弹框 parameters JSON**（want.parameters 最终形态）：

```json
{
  "keyUri": "<UKey 凭证唯一标识>",
  "appUid": <发起方应用 uid>,
  "requestId": "<32 字符 hex 会话标识>",
  "action": "UkeyPINAuth",
  "ability.want.params.uiExtensionType": "ukeyAuth",
  "timeout": <ms，归一化后实际超时>,
  "scene": "Login" | "Custom",
  "customData": "<base64，仅自定义弹框下发>"
}
```

- **默认弹框 parameters JSON**：`{ability.want.params.uiExtensionType: "sys/commonUI",
  pageType: 7, keyUri, appUid, requestId, scene}`（无 action/customData/timeout）；
- `sys/commonUI` 类型扩展经 systemui 宿主拉起**无先例**（ukeyAuth 有先例）——真机 E2E
  为门禁项（R7）。

### 6.3 弹框提供方契约

**驱动自定义弹框（UIAbility / UIExtensionAbility）**：

1. 认证流程结束后**先**上报（`CmReportUkeyAuthResult`，requestId 从 want.parameters
   读取），**再** terminateSelf（10s 宽限为顺序契约的竞态兜底；UIAbility 路径无断连
   事件，超时后迟到上报一律忽略）；
2. 错误码协议：0 成功 / 29700002 取消 / 29700003 失败 / 29700006 参数错误 / 其余 29700001；
3. `customData`：want 参数键 `customData`，值为 base64 字符串，驱动自行解码；
   `scene`：want 参数键 `scene`（'Login'/'Custom'）；
4. UIAbility 形态结果上报通道同 R1（遗留项）。

**默认弹框（com.ohos.certmanager，D14）**：完成后经 inner API `CmReportUkeyAuthResult`
上报（错误码协议同上）；TEMP 联调由 user_certificate_manager 仓 native 桥接模块调用
（系统应用可加载 innerkit），上游化方案需产品侧对齐（R8）。

## 7. inner API（interfaces/innerkits/cert_manager_standard/main/include）

### 7.1 `cm_type.h`

```c
/* UKey Pin 码认证场景（对齐 d.ts UkeyAuthScene） */
enum CmUkeyAuthScene {
    CM_UKEY_AUTH_SCENE_LOGIN = 0,    /* 缺省：接受默认弹框回退 */
    CM_UKEY_AUTH_SCENE_CUSTOM = 1,   /* 仅自定义弹框 */
};

/* UKey Pin 码认证请求 */
struct UkeyAuthRequest {
    struct CmBlob keyUri;        /* UKey 凭证唯一标识，最大 256 字节，NUL 结尾 */
    uint32_t timeout;            /* ms，0=服务端默认最大值（超上限 clamp），既有 */
    uint32_t scene;              /* enum CmUkeyAuthScene，缺省 0 */
    struct CmBlob customData;    /* 原始字节，最大 2048，可为空（size==0/data==NULL） */
};

/* 对话框内部错误码段：现有 -1017/-1018 保留，-1016 删除（D12），追加： */
CMR_DIALOG_ERROR_DEFAULT_NOT_SUPPORTED = -1019  /* 需默认弹框但 scene=Custom（→29700004） */
CMR_DIALOG_ERROR_NOT_PC_DEVICE = -1020          /* 非 PC 且非 PC 模式拉 UIExtension（→29700004） */
```

### 7.2 `cert_manager_api.h`

`CmOpenUkeyAuthDialog(const struct UkeyAuthRequest *, CmUkeyAuthDialogResultCallback,
void *userData)` / `CmReportUkeyAuthResult(const struct CmBlob *requestId, int32_t
resultCode)` 签名不变（结构体字段扩展为增量）。

## 8. IPC 协议（frameworks ↔ SA，CM 自有通道）

### 8.1 消息码

`CM_MSG_OPEN_UKEY_AUTH_DIALOG` / `CM_MSG_REPORT_UKEY_AUTH_RESULT` 已存在（v1 交付），
本次无新增消息码。

### 8.2 parcel 布局

| 消息 | 请求 parcel | 同步应答 |
|---|---|---|
| OPEN | `[interfaceToken][uint32 size][remote object（客户端回调 stub）][paramSet blob]`（remote 在 buffer 前，binder 对象不可置于 WriteBuffer 补 pad 段之后）paramSet：`PARAM0_BUFFER keyUri` + `PARAM1_UINT32 timeout` + **`PARAM2_UINT32 scene` + `PARAM3_BUFFER customData`（新增）** | `[int32 同步校验码]` |
| REPORT | `[interfaceToken][uint32 size][paramSet blob（PARAM0_BUFFER requestId, PARAM1_UINT32 resultCode）]` | `[int32 校验码]` |

### 8.3 客户端（frameworks/.../os_dependency/cm_ipc/）

- `CmClientOpenUkeyAuthDialog`：组包扩展 scene/customData（序列化处对 customData 长度
  复核 ≤2048，防 inner API 直接调用方绕过）；
- 回调 stub / 29201 冷启动竞态重试机制不变（v1 交付）。

### 8.4 base64 编码（frameworks/common 单一实现）

- 仓内无现成编码实现（已核实），**新增**手写 `Base64Encode`（标准字母表 + padding，约
  30 行，无新依赖，供三处消费）：Kit 直启 UIAbility want、SA StartAbility want、SA
  systemui parameters JSON；随附单测（含 RFC 4648 向量与全 0xFF 长串）；
- 编码仅发生在 want/params 构造边界，inner API / IPC 全程传原始字节；
- 临时缓冲（SA 侧原始字节与 base64 串）释放前 `memset_s` 清零；日志/打点只记长度。

## 9. SA 侧详细设计

`services/cert_manager_standard/cert_manager_service/main/os_dependency/dialog/`（v1 已建，v3 泛化）。

### 9.1 模块构成

| 文件 | 职责（v3 增量） |
|---|---|
| `cm_ukey_auth_dialog_manager.h/.cpp` | 会话管理器泛化：三种拉起策略（见 9.2）、PC 门禁 seam（`SetPcCheckerForTest`）、scene/customData 校验、上报责任方 bundle 校验、桩旋钮同源读取 |
| `cm_system_dialog_connection.h/.cpp` | 不变（默认弹框与 UIExtension 共用：bundle/ability/params 由调用方给定） |

### 9.2 OpenDialog 路由与拉起策略

```
OpenDialog(keyUri, callerUid, timeoutMs, scene, customData, clientCallback):
    参数校验（keyUri 长度/customData ≤2048/scene 枚举）
    单飞检查（-1018）
    querier(keyUri) → {bundle, ability, type}:
      查询失败:
        scene==CUSTOM → -1019                       /* rule 3，同步 */
        session.owner = "com.ohos.certmanager"
        LaunchViaSystemDialog(默认弹框三元组, params{sys/commonUI, pageType=7,
                              keyUri, appUid, requestId, scene})   /* 无 customData */
      type==UIABILITY:
        session.owner = 驱动 bundle
        LaunchViaStartAbility(want{驱动 bundle/ability, action:UkeyPINAuth, appUid,
                              keyUri, requestId, scene, customData(b64)})
      type==UIEXTENSION:
        pcChecker() == false → -1020                /* rule 6，同步 */
        session.owner = 驱动 bundle
        LaunchViaSystemDialog(驱动三元组, params{ukeyAuth JSON, §6.2，含 scene/customData(b64)})
    生成 requestId（CSPRNG fail-closed：getrandom 优先 + /dev/urandom×3 重试，
      全失败拒绝开会话，返回 CMR_DIALOG_ERROR_INTERNAL）
    建会话（state=LAUNCHING）→ 拉起 → 启动总超时（归一化/clamp，D5）→ WAITING_REPORT
```

- `LaunchViaStartAbility`：`AbilityManagerClient::GetInstance()->StartAbility(want)`，
  `ResetCallingIdentity()` 以 SA 身份执行；无连接对象，会话不注册断连/宽限；超时后会话
  终结（迟到上报忽略），孤儿弹窗由用户关闭（驱动契约，同 R2 语义）；
  `cert_manager_service.cfg` 权限增补 `ohos.permission.START_ABILITIES_FROM_BACKGROUND`；
- 总超时/单飞/保活续期/客户端死亡监听对三种类型通用；断连 10s 宽限仅
  systemui 拉起路径（默认/UIExtension）；
- 上报责任方校验：`OnReport` 的 callingBundleName 必须等于 `session.owner`（驱动弹框=
  驱动 bundle；默认弹框= com.ohos.certmanager）；
- `UkeyAuthSession` 结构增 `scene`、`owner` 字段；requestId 生成/校验/状态机其余不变。

### 9.3 上报校验（安全设计，D7）

不变（v1 交付）：requestId 在会话且未终态 → 上报者 HAP bundle == 会话 owner →
resultCode 白名单 `{0, 29700001, 29700002, 29700003, 29700006}`（未知折叠 29700001）。

### 9.4 其他横切关注点

- customData 原始字节仅会话参数构造期间持有，不持久化、不打内容日志（只记长度）；
  释放前 memset_s；
- SA 保活续期 / 专用 EventHandler 线程 / SA 身份拉起（ResetCallingIdentity）沿用 v1；
- SELinux：systemui 拉起路径既有项（联调 setenforce 0，策略固化遗留）；StartAbility
  路径需新增 cert_manager_service → ability_mgr 的 binder 规则（R9）。

## 10. Kit 层（NAPI/ANI）改造

### 10.1 `cm_dialog_api_common`（kits/common）

- `GetUkeyAbilityInfo` 不变；`GetCustomerAuthCertWant`（UIAbility 直启）增补
  scene + customData(base64) 参数；
- `DIALOG_CODE_TO_JS_CODE_MAP` / `DIALOG_CODE_TO_MSG_MAP`：删除 -1016/29700008 条目，
  追加 `{CMR_DIALOG_ERROR_DEFAULT_NOT_SUPPORTED, 29700004}`、
  `{CMR_DIALOG_ERROR_NOT_PC_DEVICE, 29700004}` 及文案（29700004 复用既有
  "the API is not supported on this device" 文案基线，按场景细化后缀）。

### 10.2 NAPI `cm_napi_open_ukey_auth_dialog.cpp`

```
CMNapiOpenUkeyAuthorizeDialog:
    argc 校验（1 或 2，其余 401）
    解析 UkeyAuthRequest（keyUri/timeout/scene/customData，D11 约定）
    argc == 1（新接口）：
        → CmOpenUkeyAuthDialog → promise（回调经 threadsafe function 回 JS 线程）
    argc == 2（老接口）：
        GetUkeyAbilityInfo:
          UIExtension → 走 SA 链路（同 argc==1，忽略 context）
          UIAbility   → 原 Kit 直启流程（want 增补 scene/customData(b64)）
          查询失败    → scene==CUSTOM → 同步 reject 29700004（无 IPC）
                       → 默认弹框 Kit 直启（现状流程，want 增补 scene；customData 丢弃）
```

- metrics 沿现有 `CmMetricsReport("openUkeyAuthDialog", DIALOG)` 覆盖全部分支；
- ANI 两实现与 NAPI 语义严格一致。

## 11. 错误码汇总

| 场景 | 内部码 | JS 码 |
|---|---|---|
| 需默认弹框但 scene=Custom（rule 3） | -1019（新） | 29700004 |
| 非 PC 且非 PC 模式拉 UIExtension（rule 6） | -1020（新） | 29700004 |
| ~~ability 查询为空 / 类型非 UIExtension~~ | ~~-1016~~ **已删除**（D12） | ~~29700008~~ |
| 提供方超时未上报（总超时到期） | -1017 | 29700009 |
| 已有挂起会话（单飞拒绝） | -1018 | 29700010 |
| 连接失败 / 发命令失败 / StartAbility 失败 / 上报校验失败 / CSPRNG 不可用 | CMR_DIALOG_ERROR_INTERNAL | 29700001 |
| 断连宽限超时（判定取消） | CMR_DIALOG_ERROR_OPERATION_CANCELS | 29700002 |
| 提供方上报透传 | 29700003 / 29700006 | 29700003 / 29700006 |
| scene 非枚举 / customData 超限 / 参数校验失败 | CMR_DIALOG_ERROR_PARAMETER_VALIDATION_FAILED | 29700006 |
| argc 不匹配 / 字段类型错 | — | 401 |
| 无权限 | CMR_DIALOG_ERROR_PERMISSION_DENIED | 201 |

## 12. 兼容性

- 老接口（argc==2）：UIAbility 驱动与默认弹框 Kit 直启行为兼容（want 仅增补可选参数，
  提供方不读则无感）；UIExtension 驱动走 SA（v2 起现状）；
- 新增 `scene`/`customData` 均可选字段，缺省行为 = v2 现状（LOGIN / 无数据）；
  **唯一行为变化**：未注册驱动 + 新接口，v2 回 29700008，v3 起拉默认弹框（正是本修订
  目标，26.0.0 未发布无兼容包袱）；
- 删除 -1016/29700008 属未发布码，无存量调用方；
- inner `UkeyAuthRequest` 结构体追加字段（尾部），sizeof 变化但 ABI 上调用方按指针+
  显式初始化使用，源码级兼容（随源码树整体编译）；
- IPC paramSet 新增 tag 为追加，旧 SA 收到新客户端会解出多余 param 但按 tag 取值不受
  影响；消息码无变化。

## 13. 测试与验证

- **单元测试**（`test/unittest/`，重点 `cm_ukey_auth_dialog_manager_test` 扩展）：
  - 路由矩阵：查询结果（未注册/UIAbility/UIExtension）× scene（LOGIN/CUSTOM）×
    PC（注入 true/false）全组合断言拉起策略与同步错误码；
  - rule 3（-1019）、rule 6（-1020）、scene/customData SA 侧复核；
  - 默认弹框会话：owner=com.ohos.certmanager 的上报校验（驱动 bundle 上报被拒）；
  - UIAbility 会话：无宽限、超时终结、迟到上报忽略；
  - params/want 内容断言：默认弹框无 customData、自定义弹框含 base64、scene 传递；
  - 既有 22 用例回归（-1016 用例改造为路由断言）；
  - NAPI 解析：scene 缺省/非法、customData 0/1/2048/2049 字节边界；
  - requestId 唯一性/格式（既有 CSPRNG 用例保留）。
- **Fuzz**：OPEN/REPORT 两 fuzzer 扩字段（scene uint32 混乱值、customData 超长）；
  NAPI fuzzer 扩 scene/customData 类型混乱。
- **构建验证**：`--build-only-gn`；`--build-target cert_manager_service`、
  `certmanager`、`cert_manager_sdk`、`cm_sdk_test`。
- **真机 E2E**（rk3568，桩旋钮 D16 + `param set persist.sceneboard.ispcmode true/false`）：
  - UIExtension：PC=true 通、PC=false 回 29700004（新接口与老接口各一）；
  - 默认弹框：新接口 → SA 经 systemui 拉起 `sys/commonUI` 扩展（R7 门禁）→
    certmanager 上报（TEMP 桥）→ 回调 resolve；scene=CUSTOM 同步 29700004；
  - UIAbility：SA StartAbility 拉起 demo（需驱动 demo 应用补 UIAbility 形态），
    上报经 cmtest 探针验证（R1 通道未定的替代验证）；
  - customData：1B/2048B 经 systemui JSON 全链路送达弹框；LOGIN+默认弹框不携带；
  - 老接口 UIAbility/默认弹框回归 + 老接口 UIExtension 回归。

## 14. 风险与遗留事项

| # | 风险/事项 | 缓解 |
|---|---|---|
| R1 | 三方驱动弹框（UIAbility/UIExtension）的**公开上报通道未定**（公开 API 已删，仅 inner；三方 HAP 无法调 innerkit）；本修订 UIAbility-no-context 路径加深该依赖 | E2E 用 cmtest 探针验证 SA 侧；驱动侧通道随 HUKS/产品侧对齐后单独立项 |
| R2 | 提供方不遵守"先上报后终止"契约：systemui 路径 10s 宽限兜底；UIAbility 路径超时终结 + 迟到上报忽略，孤儿弹窗留待用户关闭 | 契约写入 §6.3；HUKS 驱动文档对齐 |
| R4 | SA 保活续期与按需卸载策略交互 | 已实现（v1），随 v3 路由回归 |
| R5 | `appUid` 多用户/多应用并发语义依赖提供方实现 | 契约随 §6.2/6.3 |
| R7 | `sys/commonUI` 类型扩展经 systemui 宿主拉起**无先例**（ukeyAuth 有先例），AMS 校验行为需真机确认 | E2E 门禁项；失败则与 AMS/systemui 对齐（可能需宿主侧适配，违反 D4 时重新裁决） |
| R8 | 默认弹框上报桥（user_certificate_manager native 模块）为 TEMP 跨仓联调改动，上游化需产品侧对齐（默认弹框是否走 requestId 上报） | §6.3 契约 + TEMP 标注 |
| R9 | StartAbility 路径权限/SELinux：`START_ABILITIES_FROM_BACKGROUND` 授予 + cert_manager_service → ability_mgr binder 规则 | cfg 增补 + selinux_adapter 跨仓项（连同既有 systemui 路径策略一并固化） |
| R10 | customData 隐私：内容不经日志/打点/持久化外泄 | §8.4/§9.4 约束 + 单测断言日志仅长度 |
| R11 | UIAbility demo 应用当前仅 UIExtension 形态，E2E 需补 UIAbility | 向用户索取 demo 工程位置后补 |

## 15. 参考实现索引

| 参考点 | 位置 |
|---|---|
| 现有 openUkeyAuthDialog NAPI 流程（argc 分叉） | interfaces/kits/napi/src/dialog/cm_napi_open_ukey_auth_dialog.cpp |
| ability 查询与默认弹框 Want 构造 | interfaces/kits/common/src/cm_dialog_api_common.cpp |
| 会话管理器（含 requestId CSPRNG fail-closed） | services/.../os_dependency/dialog/cm_ukey_auth_dialog_manager.cpp |
| systemui 通用宿主协议（无类型注册表） | applications/standard/systemui/product/default/dialog/src/main/ets/ServiceExtAbility/ExtAbility.ts:34 |
| UIExtensionComponent 装载 | applications/standard/systemui/product/default/dialog/src/main/ets/pages/ExtIndex.ets:109 |
| AMS 对 UKEY_AUTH 扩展的权限校验（宿主持 START_SYSTEM_DIALOG） | foundation/ability/ability_runtime/services/abilitymgr/src/ability_manager_service.cpp:13245,13284 |
| PC 模式权威信号（WMS/ace/RS/powermgr 消费） | persist.sceneboard.ispcmode；foundation/window/window_manager/.../scene_session_manager.cpp:882 |
| 设备形态读取（2in1=PC） | OHOS::system::GetDeviceType()（base/startup/init/interfaces/innerkits/include/syspara/parameters.h:64） |
| SA StartAbility 参考（useriam） | base/useriam/user_auth_framework（AbilityManagerClient 用例） |
| 驱动 want 契约与错误码协议（UIAbility 场景） | docs/zh-cn/application-dev/reference/apis-universal-keystore-kit/js-apis-huksExternalCrypto.md:94 |
| ANI 现有 openUkeyAuthDialog | interfaces/kits/ani/certificate_manager_dialog_ani/ets/@ohos.security.certManagerDialog.ets |

## 16. 交付物清单（v3 增量，file-level）

| 模块 | 文件 | 变更 |
|---|---|---|
| SDK | interface/sdk-js/api + zh-cn/api/@ohos.security.certManagerDialog.d.ts | `UkeyAuthScene` 枚举、`scene`/`customData` 字段、throws 修订（删 29700008、增 29700004）、删枚举项 29700008 |
| inner API | interfaces/innerkits/.../cm_type.h | `UkeyAuthRequest` 增字段、`CmUkeyAuthScene`、删 -1016、增 -1019/-1020 |
| IPC 客户端 | frameworks/.../cm_ipc/ | OPEN 组包增 scene/customData |
| frameworks/common | cm_util（新增 Base64Encode + 单测） | 共享 base64 编码 |
| SA | services/.../dialog/cm_ukey_auth_dialog_manager.{h,cpp} | 三策略路由、PC seam、owner 校验、scene/customData 校验、桩旋钮 |
| SA 配置 | services/cert_manager_standard/cert_manager_service.cfg | 增 START_ABILITIES_FROM_BACKGROUND |
| kits/common | cm_dialog_api_common.{h,cpp} | 错误码映射修订、UIAbility want 增参 |
| NAPI/ANI | cm_napi_open_ukey_auth_dialog.cpp、cm_open_ukey_auth_dialog*.cpp | 解析两字段、老接口路由修订 |
| 测试 | test/unittest、test/fuzz_test | §13 增量 |
| TEMP 联调 | user_certificate_manager native 桥（默认弹框上报） | R8 |

## 17. 实现状态

**基线（v1/v2）已交付**：22+ 提交在 master（最新 `7c1d09c`，已推 leal 远端）——SA 会话
管理器（requestId CSPRNG fail-closed/单飞/10min 总超时/宽限/保活/死亡监听）、systemui
连接、IPC OPEN/REPORT、客户端（29201 重试）、NAPI/ANI、fuzz ×2、spec；真机 E2E：UIExtension
全链路（拉起/上报/取消/超时/clamp）、timeout 全链路、requestId 唯一性；单测 23 用例通过。

**v3（本修订）待实现**：按 §16 清单推进，实施计划另行制定（writing-plans）。
