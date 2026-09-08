# certificate_manager 组件指引（OpenHarmony security / certificate_manager）

> 本仓库面向 Agent 的指导文档统一使用中文；代码标识符、命令、路径、文件名保留原文。本部件为 OpenHarmony 系统级证书管理组件（部件名 `certificate_manager`，子系统 **security**，SysCap `SystemCapability.Security.CertificateManager`），提供证书全生命周期（安装、存储、授权、使用、销毁）的管理与安全使用。采用 **SDK 层（kits/innerkits）→ Service 层（SA 3512）→ Engine 层（核心引擎）** 三层架构：主体语言为 **C**（引擎、公共库、IPC 序列化、NDK），辅以 **C++**（SA 骨架、RDB、权限检查、NAPI/ANI），构建体系为 **GN + Ninja**（无 hvigor）。私钥**不落盘**，密钥全部经 **HUKS** 导入与操作，文件系统仅存证书文件与 `keyUri` 句柄；证书文件存于 `/data/service/el1/public/cert_manager_service/certificates`（按 userId/uid 隔离），证书属性存 RDB。SA ID **3512**（descriptor `u"ohos.security.cm.service"`），按需启动（监听 USER_REMOVED/PACKAGE_REMOVED 事件），空闲 DelayUnload。IPC 为**手写消息码 + 手写序列化**（无 .idl 生成，消息码头文件受 CODEOWNERS 强制审查）。对外共 **5 种接口形态**：innerkit C SDK、NAPI（模块名 `security.certmanager`）、NDK C API（`ohcert_manager`，@since 22）、CJ FFI、ANI；注意 **`@ohos.security.certManager.d.ts` 声明文件在 interface_sdk-js 仓，不在本仓库**（本仓 `interfaces/kits/ani/*/ets/` 下有 ets 参考副本）。另预置 **125 个系统 CA 证书**至 `/etc/security/certificates`。

## 项目定位

本仓库是 OpenHarmony 安全子系统的证书管理部件，向上对接应用框架（NAPI/NDK/仓颉/ArkTS），向下依赖 HUKS（密钥）、OpenSSL（证书解析）、relational_store（属性库）。

优先按这些目录定位问题：

- `services/cert_manager_standard/cert_manager_engine/`：核心引擎（纯 C）。`main/core/src/` 按业务拆分——`cert_manager.c`（通用安装/卸载编排、URI）、`cert_manager_app_cert_process.c`（应用凭据安装）、`cert_manager_storage.c`（存储路径推导与文件读写）、`cert_manager_status.c`（启停状态）、`cert_manager_auth_mgr.c`/`cert_manager_auth_list_mgr.c`（授权管理）、`cert_manager_session_mgr.c`/`cert_manager_crypto_operation.c`/`cert_manager_key_operation.c`（签名验签三段式会话，直连 HUKS）、`cert_manager_query.c`（查询）、`cert_manager_ukey_operation.c`（Ukey）、`cm_event_process.c`/`cm_event_observer.cpp`（用户/包卸载事件清理）；`main/rdb/` 为证书属性数据库（C++，`cm_cert_property_rdb.cpp`、`cm_rdb_data_manager.cpp`）。
- `services/cert_manager_standard/cert_manager_service/`：SA 服务外壳（C++）。`main/os_dependency/sa/cm_sa.{h,cpp}`（`CertManagerService : SystemAbility, IRemoteStub`，SA 3512 骨架与按需启动）、`main/os_dependency/idl/cm_ipc/`（IPC 服务端 stub：`cm_ipc_service.c` 各 `CmIpcServiceXxx` 分发、`cm_ipc_service_cert_pack.c` 证书打包、`cm_response.cpp` 应答）、`main/os_dependency/sa/sa_profile/`（SA 3512 json 配置）、`main/hisysevent_wrapper/`（CERT_FAULT 打点）、`main/security_guard_report/`（可选安全上报）；服务 init 配置 `services/cert_manager_standard/cert_manager_service.cfg`（专用 uid `cert_manager_server`、SELinux 域 `u:r:cert_manager_service:s0`）。
- `frameworks/cert_manager_standard/main/`：SDK 与服务共用基础库（C）。`common/`（`cm_util.c` 工具、`cm_param.c` CmParamSet 序列化、`cm_pfx.c`/`cm_x509.c` 解析）；`os_dependency/cm_ipc/`（**IPC 客户端 proxy**：`cm_ipc_client.c` 各 `CmClientXxx`、`cm_ipc_client_serialization.c` 请求序列化、`cm_request.cpp` 经 samgr 取 SA 3512）；`os_dependency/log/`（HiLog 封装）、`os_dependency/posix/`（`CmMalloc/CmFree`）。IPC 消息码定义于 `common/include/cert_manager_service_ipc_interface_code.h`（**受 CODEOWNERS 审查**）。
- `interfaces/`：`innerkits/cert_manager_standard/main/include/`（innerkit C 头 `cert_manager_api.h` 全部 `CmXxx` API + `cm_type.h` 类型/错误码/常量，实现 `source/cert_manager_api.c`）；`kits/napi/`（JS/ArkTS NAPI，`src/cm_napi.cpp` 注册 `security.certmanager`，按功能拆 `cm_napi_install_app_cert.cpp`、`cm_napi_sign_verify.cpp`、`cm_napi_grant.cpp` 等）；`kits/c/`（NDK：`cm_native_api.h` 的 `OH_CertManager_*`，导出符号受 `libcmndk.map` 约束）；`kits/cj/`（仓颉 FFI）、`kits/ani/`（ArkTS Native Interface，含 ets 声明参考）；`kits/common/`（JS 错误码 `cm_api_common.h`、弹窗公共、`metrics/` API 打点）。
- `config/`：`systemCertificates/` 125 个 OpenSSL 哈希命名（`.0`）系统 CA 证书，经 `trusted_system_certificate0..124` 目标预置到 system/updater 镜像 `/etc/security/certificates`；`integrate_cacert/` 为证书集成工具（Python）。
- `test/`：`unittest/src/`（22 个 gtest 源文件 + `cm_test_common.cpp`，测试数据头 `unittest/include/cm_cert_data_*.h`）、`unittest/module_test|inner_permission_test|common_permission_test|multi_thread_test/`、`fuzz_test/`（**124 个 fuzzer** 目录 + 公共桩 `fuzz_test_common/`）、`mocks/hks_api/`（HUKS API 桩）、`resource/certificate_manager/ohos_test.xml`。
- `cert_manager.gni`：全局 GN 参数（feature 开关、路径变量）。`hisysevent.yaml`：打点事件定义（domain `CERT_MANAGER`）。`OAT.xml`：开源审计（每个源文件须带 Apache-2.0 头）。

### 按任务类型定位代码

| 任务类型 | 首选位置 | 关键锚点 |
|---|---|---|
| 新增 IPC 命令（全链路） | `frameworks/.../include/cert_manager_service_ipc_interface_code.h` + `cm_ipc_client.c` + `cm_ipc_client_serialization.c` + `cm_ipc_service.c`(+`cm_ipc_service_cert_pack.c`) + innerkit `cert_manager_api.{h,c}` | `cert_manager_service_ipc_interface_code.h:24`(`enum CertManagerInterfaceCode`，新命令必须加在 `:56` 注释处 `CM_MSG_MAX` 之前，CODEOWNERS `@leonchan5` 审查)；服务端模板 `cm_ipc_service.c:79`(`CmIpcServiceGetCertificateList`)；客户端模板 `cm_ipc_client.c:104`(`CmClientGetCertList`) |
| 应用凭据安装/卸载 | `cert_manager_app_cert_process.c` + `cert_manager.c` | `CmInstallAppCertPro`(`cert_manager_app_cert_process.c:545`)；`CmRemoveAppCert`(`cert_manager.c:272`)、`CmRemoveAllAppCert`(`cert_manager.c:511`) |
| 用户/系统 CA 证书安装卸载 | `cert_manager_storage.c` + `cert_manager.c` | `CmWriteUserCert`(`cert_manager.c:730`)、`CmRemoveUserCert`(`cert_manager.c:900`)、`CmRemoveAllUserCert`(`cert_manager.c:1004`)；存储根路径宏 `cert_manager_storage.h:25-33` |
| 证书状态启停 | `cert_manager_status.c` | `CmGetCertConfigStatus`(`cert_manager_status.c:37`) |
| 授权（grant/is authed/remove） | `cert_manager_auth_mgr.c` + `cert_manager_auth_list_mgr.c` | `CmAuthGrantAppCertificate`(`cert_manager_auth_mgr.c:340`) |
| 签名/验签会话（Init/Update/Finish/Abort） | `cert_manager_session_mgr.c` + `cert_manager_crypto_operation.c` + `cert_manager_key_operation.c` | `CmServiceInit`(`cert_manager_service.c:265`)；`CmCreateSession`(`cert_manager_session_mgr.c:139`)；HUKS 调用 `HksInit`(`cert_manager_key_operation.c:287`)、`HksImportKey`(`cert_manager_key_operation.c:341`) |
| 查询（证书/凭据列表与详情） | `cert_manager_query.c` | `CmGetCertListInfo`(`cert_manager_query.c:584`)；按 uid/调用方查询 `CmServiceGetAppCertListByUid`/`CmServiceGetCallingAppCertList`(`cert_manager.c:570/615`) |
| Ukey（USB Key）证书 | `cert_manager_ukey_operation.c` | `CmServiceGetUkeyCertList`/`CmServiceGetUkeyCert`(`cert_manager.c:591/603`) |
| SA 生命周期/按需启动 | `cm_sa.cpp` + `sa_profile/cert_manager_service.json` + `cert_manager_service.cfg` | `OnStart`(`cm_sa.cpp:299`)、`OnRemoteRequest`(`cm_sa.cpp:258`)；`cert_manager_service.json:11-19`(start-on-demand 监听 USER_REMOVED/PACKAGE_REMOVED)、`:21`(low-memory 回收) |
| 用户/应用卸载事件清理 | `cm_event_process.c` + `cm_event_observer.cpp` | SA 按需拉起后由事件处理入口触发 |
| 证书属性 RDB | `services/.../cert_manager_engine/main/rdb/` | `cm_cert_property_rdb.cpp`、`cm_rdb_data_manager.cpp` |
| NAPI 接口 | `interfaces/kits/napi/src/` | `cm_napi.cpp:179`(`NAPI_FUNC_DESC` 注册表，新增 JS 接口在此登记) |
| NDK C API | `interfaces/kits/c/` | `cm_native_api.h`(`OH_CertManager_*`)；导出符号 `libcmndk.map` |
| 错误码 | `cm_type.h`(C 层) + `cm_api_common.h`(JS 层) | `CmErrorCode`(`cm_type.h:135`)；JS 错误码 `cm_api_common.h` |
| 日志 | `cm_log.h` | `:39-42`(`CM_LOG_I/W/E/D`) |
| HiSysEvent 故障打点 | `hisysevent.yaml` + `hisysevent_wrapper/` | `hisysevent.yaml:16`(`CERT_FAULT`) |
| API metrics 打点 | `interfaces/kits/common/metrics/` | 开关 `cm_api_metrics_enable`(`cert_manager.gni:34`) |
| 系统 CA 证书预置 | `config/systemCertificates/` + `config/BUILD.gn` | `trusted_system_certificate0..124`（装至 `/etc/security/certificates`） |
| Fuzz 用例 | `test/fuzz_test/` | 命名 `cm<功能>_fuzzer`，公共桩 `fuzz_test_common/`，每个 fuzzer 自带 `corpus/` |

## 对外接口实况

> 以下以代码为准；README 与接口文档若有出入，以头文件实现为准。

- **store 参数取值**（`cm_type.h:85-89`，同时也是目录推导依据）：`CM_CREDENTIAL_STORE=0`（应用凭据）、`CM_SYSTEM_TRUSTED_STORE=1`（系统 CA）、`CM_USER_TRUSTED_STORE=2`（用户 CA）、`CM_PRI_CREDENTIAL_STORE=3`（私有凭据）、`CM_SYS_CREDENTIAL_STORE=4`（系统应用凭据）。
- **错误码分段**（`cm_type.h:135` 起）：通用 `CM_SUCCESS=0`/`CM_FAILURE=-1`、`CMR_ERROR_*` -2~-55；`-10000~-19999` 非法参数段（`CMR_ERROR_INVALID_ARGUMENT_BEGIN`，`cm_type.h:198`）；`-20000~-29999` 密钥操作段（`CMR_ERROR_KEY_OPERATION_BEGIN`，`cm_type.h:218`）；`-30000~-39999` 授权段（`CMR_ERROR_AUTH_FAILED_BEGIN`，`cm_type.h:239`）。新增错误码先查分段再落位。
- **JS 层错误码**在 `interfaces/kits/common/include/cm_api_common.h`（`PARAM_ERROR=401`、`INNER_FAILURE=17500001` 等），与 NAPI/ANI 层枚举 `CMErrorCode` 对应，改一处须同步另一处。
- **innerkit API** 全集见 `cert_manager_api.h`：查询 `:24-31`、应用凭据安装 `:33-38`（`CmInstallAppCertEx` 带 `CmAppCertParam`/`CmAuthStorageLevel`，支持 EL1/EL2/EL4）、授权 `:51-57`、三段式签名 `:59-65`、用户证书 `:69-85`、系统应用/CA `:82-85`、Ukey `:95-105`。实现经 `cert_manager_api.c` 转发 `CmClientXxx`。
- **凭据格式**：`CmAppCertParam`（P12 或 证书链+私钥 `CHAIN_KEY`，`CredFormat`）；用户 CA 证书格式 `enum CmCertFileFormat`（`cm_type.h:531`，PEM/DER/P7B）。
- **IPC 参数编码**：跨进程统一走 `CmParamSet` + `CmTag`（tag 类型位段 `CM_TAG_TYPE_*` `cm_type.h:272-276` 与 `CM_TAG_PARAM0_BUFFER..CM_TAG_PARAM4_NULL` `:282-301`，序列化实现 `cm_param.c`）。
- **NDK**：`OH_CertManager_*`（`interfaces/kits/c/include/cm_native_api.h`，@since 22，权限 `ohos.permission.ACCESS_CERT_MANAGER`）；JS/ArkTS 声明 `@ohos.security.certManager.d.ts` **在 interface_sdk-js 仓**，本仓 `interfaces/kits/ani/*/ets/` 下 ets 文件仅为参考副本。
- **NAPI 模块**：`security.certmanager`，安装于 `module/security`（`interfaces/kits/napi/BUILD.gn:80`）；授权/安装/卸载弹窗为独立模块 `certmanagerdialog`（`certificate_manager_feature_dialog_enabled` 开启时才编译）。
- **特权接口**：按 uid 查询（`CmGetAppCertListByUid`）、`CmCheckAppPermission` 等在 IPC 服务端走 access_token 校验（`cert_manager_permission_check.cpp`），调用方需系统权限。

## 构建和验证

构建在 **OpenHarmony 源码根目录**执行（本仓无独立构建入口，无 hvigor/package.json）：

1. 整编或单编部件目标（GN 目标名见下）：

```bash
./build.sh --product-name <product>                               # 整编
./build.sh --product-name <product> --build-target cert_manager_service   # SA 服务 libcert_manager_service.z.so
./build.sh --product-name <product> --build-target certmanager           # NAPI libcertmanager.z.so
./build.sh --product-name <product> --build-target ohcert_manager        # NDK libohcert_manager.z.so
./build.sh --product-name <product> --build-target cert_manager_sdk      # innerkit libcert_manager_sdk.z.so
```

2. 产物与部署位置：`libcert_manager_service.z.so` + SA 配置（SA 3512）；NAPI 装至 `/system/lib64/module/security/libcertmanager.z.so`；NDK 导出符号受 `libcmndk.map` 约束；innerkit `libcert_manager_sdk.z.so`（innerapi_tags 含 platformsdk/chipsetsdk/sasdk）；125 个系统 CA 装至 `/etc/security/certificates`（system+updater 镜像）。
3. 编译装配：根 `BUILD.gn` 分组 `cert_manager_type_base`(`:80`，napi/capi/ani/cjapi+系统证书)/`cert_manager_type_fwk`(`:222`，innerkit)/`cert_manager_typer_services`(`:234`，SA)；内部静态库 `cert_manager_engine_core_standard`、`libcert_manager_common_standard_static`、`libcert_manager_ipc_client_static`、`libcert_manager_log_mem_static`、`libcm_service_idl_standard_static`、`libcert_manager_rdb_static` 等被各目标复用。统一加固选项：`-Wall -Werror`、`branch_protector_ret = "pac_ret"`、sanitize（cfi/cfi_cross_dso/boundary_sanitize/integer_overflow/ubsan）。

测试（注册于 `bundle.json` test 字段与根 `BUILD.gn` `cert_manager_sdk_test` group）：

```bash
./build.sh --product-name <product> --build-target cm_sdk_test        # 单测(直链 engine core 静态库,可脱离 SA 测引擎)
./build.sh --product-name <product> --build-target cm_module_test     # 模块级测试
./build.sh --product-name <product> --build-target cm_inner_permission_test   # 权限测试(access_token nativetoken 模拟身份)
```

测试二进制位于 `out/<product>/tests/unittest/certificate_manager/certificate_manager/`，gtest 体系，可过滤执行：

```bash
out/<product>/tests/unittest/certificate_manager/certificate_manager/cm_sdk_test --gtest_filter=CmAppCertTest.*
```

- 单测源在 `test/unittest/src/`（`cm_app_cert_test.cpp`、`cm_grant_test.cpp`、`cm_user_cert_test.cpp`、`cm_pfx_test.cpp` 等 22 个），测试数据头 `test/unittest/include/cm_cert_data_*.h`（RSA/ECC/Ed25519/P7B/chain_key）。
- fuzz 位于 `test/fuzz_test/`（124 个 `ohos_fuzztest` 目标，公共桩 `fuzz_test_common`）；HUKS 桩在 `test/mocks/hks_api/`。
- HUKS 软件等级下测试目标自动定义 `DEPS_HUKS_UNTRUSTED_RUNNING_ENV`（`test/BUILD.gn:93-95`）。
- 新增对外接口时须同步补充：`test/unittest/src/` 单测 + `test/fuzz_test/` 对应 fuzzer。

### 完成标准

任务被认为完成，当且仅当：

1. **代码改动已完成** - `git commit -s`
2. **本地构建通过** - `./build.sh --product-name <product> --build-target <受影响目标>` 编译成功
3. **相关测试通过** - 受影响的 gtest 目标执行并提供输出摘要（cm_sdk_test / cm_module_test 等）
4. **IPC 链路完整性核对** - 触及 IPC 的改动确认四件套（消息码/proxy 序列化/stub 分发/innerkit API）全部同步
5. **安全清单逐条核对** - 见“项目约束→安全关键约束”

### 如果无法运行验证

说明原因（如需真机 SA 3512 运行环境、HUKS 设备级密钥、系统应用身份 `cert_manager_server`、SELinux 策略），列出推荐验证步骤与预期输出关键字（如 gtest `OK`、HiLog `[CertManager]` 前缀输出、`hdc shell` 查询 `/data/service/el1/public/cert_manager_service/certificates` 目录内容），供人工执行，不得声称已验证。

### 完成报告格式

改动摘要（文件列表、改动点）、验证结果（构建/测试输出）、风险评估（IPC 兼容性、存储/数据升级兼容、权限与隔离、HUKS 密钥生命周期）、未完成事项。

## 知识索引

本仓无独立 `docs/knowledge/`，稳定背景知识以代码与常量定义为准，改动前按场景读取：

| 场景 | 修改位置 | 先读锚点 |
|---|---|---|
| IPC 消息码与兼容 | `cert_manager_service_ipc_interface_code.h` | `:24`(枚举)、`:56`(新命令必须加在 `CM_MSG_MAX` 前；CODEOWNERS `@leonchan5`) |
| IPC 请求/应答序列化 | `cm_ipc_client_serialization.c` + `cm_ipc_service_cert_pack.c` + `cm_response.cpp` | 参数编码 `CmParamSet`/`CmTag`(`cm_type.h:272-301`，实现 `cm_param.c`) |
| store 类型与目录推导 | `cert_manager_storage.{h,c}` | `cm_type.h:85-89`(五种 store)；路径宏 `cert_manager_storage.h:25-33`(`CERT_DIR`、`CREDNTIAL_STORE`、`USER_CA_STORE`、`PRI_CREDNTIAL_STORE`、`SYS_CREDNTIAL_STORE`) |
| keyUri/authUri 句柄 | `cert_manager_uri.c` + `cert_manager.c` | `CmGetUri`(`cert_manager.c:402`)；授权句柄由 `cert_manager_auth_list_mgr.c` 管理 |
| SA 骨架与按需启动 | `cm_sa.{h,cpp}` + `sa_profile/` + `cert_manager_service.cfg` | `cm_sa.h:39`(`SA_ID_KEYSTORE_SERVICE = 3512`)、`:43`(descriptor `u"ohos.security.cm.service"`)；`cert_manager_service.json:5`(SA 3512、libpath)；`cert_manager_service.cfg:22/25`(uid/secon) |
| 错误码 | `cm_type.h` + `cm_api_common.h` | `CmErrorCode`(`cm_type.h:135-195`，分段 `:198` 起)；JS 错误码 `cm_api_common.h` |
| HUKS 密钥操作 | `cert_manager_key_operation.c` | `HksImportKey`(`:341`)、`HksInit`(`:287`)；HUKS 桩 `test/mocks/hks_api/` |
| 会话管理 | `cert_manager_session_mgr.c` | `CmCreateSession`(`:139`)；会话上限 `CMR_ERROR_SESSION_REACHED_LIMIT`(`cm_type.h:159`) |
| 存储等级 EL1/EL2/EL4 | `cm_type.h` | `enum CmAuthStorageLevel`(`:483`)、`struct CmAppCertParam`(`:502` 起) |
| feature 编译裁剪 | `cert_manager.gni` | `:22-30`(ca/credential/dialog 开关)、`:34-50`(api_metrics/os_account/security_guard 按 global_parts_info 自动探测)；关闭宏 `CERTIFICATE_MANAGER_FEATURE_CA_DISABLED`/`CERTIFICATE_MANAGER_FEATURE_CREDENTIAL_DISABLED` |
| HiSysEvent 打点 | `hisysevent.yaml` + `hisysevent_wrapper/` | `hisysevent.yaml:14-24`(domain `CERT_MANAGER`、`CERT_FAULT` 字段) |
| API metrics 打点 | `interfaces/kits/common/metrics/` | `cm_api_metrics_enable`(`cert_manager.gni:34`)；错误码映射 `CmGetMetricErrorCode()` |
| 证书解析（PFX/X509/P7B） | `frameworks/.../common/src/` | `cm_pfx.c`、`cm_x509.c`、`cm_util.c` |
| RDB 属性库 | `engine/main/rdb/` | `cm_cert_property_rdb.cpp`、`cm_rdb_data_manager.cpp` |
| 系统证书预置 | `config/` | `trusted_system_certificate0..124`；集成工具 `config/integrate_cacert/build_integrate_cacert.py` |
| 测试资源与数据 | `test/` | `resource/certificate_manager/ohos_test.xml`；测试数据头 `test/unittest/include/cm_cert_data_*.h` |

### 开始编辑前

1. 确认任务类别，按“按任务类型定位代码”表定位锚点
2. 涉及 IPC 的改动先确认四件套同步方案（消息码→proxy→stub→innerkit）
3. 根据“项目约束”确认不违反任何约束
4. 声明：“我将修改 X，已读取 Y 锚点，遵循 Z 约束”

## 编码约定

- **4 空格**缩进禁 Tab；无 `.clang-format`，遵循同目录现有文件风格；C 主体 + C++（SA/RDB/NAPI，无显式 `-std=`，由 OHOS 全局工具链统一设定）。
- 文件命名 `snake_case` + 分层前缀：frameworks/common 层 `cm_`（`cm_util.c`）；engine 层 `cert_manager_`（`cert_manager_storage.c`）；NAPI 层 `cm_napi_`；IPC 服务端 `cm_ipc_service*`；fuzzer `cm<功能>_fuzzer.cpp`。
- 函数命名 PascalCase + 分层前缀：innerkit `CmXxx`（`CmGetCertList`）、IPC 客户端 `CmClientXxx`、IPC 服务端 `CmIpcServiceXxx`、引擎服务层 `CmServiceXxx`、NDK `OH_CertManager_*`。
- 类型 PascalCase（`CmBlob`、`CertInfo`、`CertList`、`CmParamSet`、`UkeyInfo`）；枚举值 UPPER_SNAKE（`CM_SUCCESS`、`CMR_ERROR_*`）；C++ 命名空间 `OHOS::Security::CertManager`，类 `DISALLOW_COPY_AND_MOVE`。
- C 接口导出统一 `CM_API_EXPORT` + `extern "C"` 包裹；innerkit 头文件即 API 契约，改动需评估兼容性。
- 日志：`CM_LOG_I/W/E/D`（`cm_log.h:39`，`LOG_TAG "CertManager"`、`LOG_DOMAIN 0xD002F09`）；**禁止直接调 hilog/printf**。
- 内存：`CmMalloc`/`CmFree` + 宏 `CM_FREE_PTR`/`CM_FREE_BLOB`/`SELF_FREE_PTR`（`cm_mem.h`）；敏感数据清零用 `memset_s`（bounds_checking_function）；**禁裸 malloc/free**。
- IPC/跨层数据一律 `CmParamSet`+`CmTag` 参数集（`cm_param.c`）；Blob 传参前必须 `CmCheckBlob` 校验。
- 错误码统一 `int32_t` 负值返回，先查 `CmErrorCode` 分段落位，不得随意发明新码。
- 版权头：每个源文件带 Apache-2.0 license 头（`OAT.xml` 审计强制）。
- 测试：gtest，`class XxxTest : public testing::Test` + `TEST_F`；权限测试用 access_token 的 `nativetoken`/`token_setproc` 模拟调用身份（参考 `test/unittest/inner_permission_test/`）。

## 项目约束

### 安全关键约束（红线，改动必查）

**Do not（禁止）：**

- 在日志/HiSysEvent/打点输出明文私钥、P12 口令（`appCertPwd`）、密钥材料、证书私钥内容。敏感缓冲区释放前必须 `memset_s` 清零。
- 私钥明文落盘：密钥必须经 HUKS 导入（`HksImportKey`，`cert_manager_key_operation.c:341`），文件系统只存证书与 `keyUri`；卸载凭据（`CmRemoveAppCert`/`CmRemoveAllAppCert`）必须同步删除 HUKS 密钥。
- 绕过 IPC 服务端身份/权限校验：`cm_ipc_service.c` 各 `CmIpcServiceXxx` 入口必须构造并校验 `CmContext`（callingUid/userId）；特权接口（按 uid 查询、`CM_MSG_CHECK_APP_PERMISSION` 等）必须走 `cert_manager_permission_check.cpp` 的 access_token 校验。
- 破坏 IPC 兼容：`CertManagerInterfaceCode` 只能追加在 `CM_MSG_MAX` 之前，不得重排/删除/复用消息码；该头文件受 CODEOWNERS `@leonchan5` 强制审查。
- 直接信任跨进程传入的路径与长度：入参必须 `CmCheckBlob`；证书路径一律按 store 从固定根目录推导（`cert_manager_storage.h:25-33`），不得拼接客户端提供的绝对路径，防路径穿越。
- 破坏用户/UID 隔离：证书与凭据按 userId/uid 隔离存储与查询，不得新增跨 uid 越权读取路径。
- 直接 `hilog`/`printf` 打日志（统一 `CM_LOG_*`）；裸 `malloc`/`free`（统一 `CmMalloc`/`CmFree`）。
- 擅自修改服务身份：服务运行于专用 uid `cert_manager_server`、SELinux 域 `u:r:cert_manager_service:s0`（`cert_manager_service.cfg:22/25`），存储目录权限 `0700/0701` 不得放宽。

**Ask before（修改前必须确认）：**

- 修改 SA ID（3512）或 descriptor（`u"ohos.security.cm.service"`）（`cm_sa.h:39/43`）：影响 samgr 注册与所有客户端。
- 修改 `cm_type.h` 公开类型、错误码取值、`CmTag` 编码：innerkit/NDK 稳定性（innerapi_tags 含 platformsdk/chipsetsdk/sasdk/ndk）。
- 修改 `CmBlob`/`CmParamSet` 二进制布局或序列化格式（`cm_param.c`）：IPC 新旧版本互通。
- 修改证书存储目录结构/文件命名/备份目录（`cert_manager_storage.h:25-33`、`CmBackupRemove` `cert_manager.c:910`）：升级数据兼容与迁移。
- 修改 RDB 表结构（`cm_cert_property_rdb.cpp`）：存量数据升级。
- 修改 `libcmndk.map` 导出符号：NDK ABI 兼容。
- 修改系统 CA 预置列表/命名规则（`config/systemCertificates/`，OpenSSL 哈希 `.0` 命名）：影响全局 TLS 信任链。
- 修改 `hisysevent.yaml` 事件定义：打点数据消费方兼容。

### 架构约束

- **三层依赖方向**：SDK（interfaces/kits + innerkits）→ frameworks（common + IPC 客户端）→（IPC/samgr）→ SA 服务外壳（cert_manager_service）→ 引擎（cert_manager_engine）。引擎为纯 C，不得反向依赖 kits/frameworks 上层；SA 外壳只做分发与生命周期，业务逻辑下沉引擎。
- **IPC 手写四件套**：新增能力须同步 ①消息码（`cert_manager_service_ipc_interface_code.h`，加在 `CM_MSG_MAX` 前）②proxy（`cm_ipc_client.c` + `cm_ipc_client_serialization.c`）③stub（`cm_ipc_service.c` + `cm_ipc_service_cert_pack.c` + `cm_response.cpp`）④innerkit API（`cert_manager_api.{h,c}`）；漏改任一处即断链。
- **密钥操作全部经 HUKS**：`CmInit/CmUpdate/CmFinish/CmAbort` 三段式会话由 `cert_manager_session_mgr.c` 管理，底层 `HksInit` 等；`keyUri` 是凭据的跨层句柄，删除凭据须同步删 HUKS 密钥，防止密钥残留。
- **SA 按需启动模型**：SA 3512 `run-on-create=false`，监听 USER_REMOVED/PACKAGE_REMOVED 拉起做账户/应用数据清理（`cm_event_process.c`/`cm_event_observer.cpp`），空闲 `DelayUnload`，低内存可被回收（`recycle-strategy: low-memory`）。服务端逻辑测试须注意生命周期与重复拉起。
- **多接口形态同步**：同一能力需 NAPI/NDK/CJ/ANI 四形态同步暴露并保持语义一致；JS 错误码（`cm_api_common.h`）与 C 错误码映射同步维护；d.ts 在 interface_sdk-js 仓，接口变更需跨仓协同。
- **feature 裁剪与可选依赖**：`certificate_manager_feature_ca_enabled`/`credential_enabled`/`dialog_enabled`（`cert_manager.gni:22-30`）控制功能裁剪，关闭时以 `CERTIFICATE_MANAGER_FEATURE_*_DISABLED` 宏隔离代码；security_guard/api_metrics/os_account 等可选依赖按 `global_parts_info` 自动探测，不得写成硬依赖。
- **测试直链引擎**：`cm_sdk_test` 直接编入 `cert_manager_engine_core_standard` 静态库（不经 SA 进程），可在本机/模拟器验证引擎逻辑；`DEPS_HUKS_UNTRUSTED_RUNNING_ENV` 在 HUKS 软件等级下自动定义（`test/BUILD.gn:93-95`）。
