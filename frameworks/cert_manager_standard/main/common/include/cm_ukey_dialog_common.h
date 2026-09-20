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

#ifndef CM_UKEY_DIALOG_COMMON_H
#define CM_UKEY_DIALOG_COMMON_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "cm_type.h"
#include "cm_ukey_ability_type.h"
#include "syspara/parameters.h"

/* UKey Pin 弹框链路共享常量与工具（Kit 直启 / SA 拉起两侧同源，spec v3 §6/§8.4）。
 * 本头文件仅供 C++ 消费（kits/common 与 SA dialog 模块）。 */

namespace OHOS::Security::CertManager {

/* ---- want / parameters JSON 参数键（弹框提供方契约，spec §6.2/§6.3）---- */
constexpr const char *CM_UKEY_DIALOG_PARAM_CUSTOM_DATA = "customData";

/* ---- PC 平台 / PC 模式判定（spec D15，用户裁定）----
 * 第一级（编译期）：PC 平台构建（BUILD.gn target_platform == "pc" 注入
 * CM_TARGET_PLATFORM_PC 宏，经 frameworks/common 的 public config 传播）放行；
 * 第二级（运行时，仅非 PC 平台构建）：读 persist.sceneboard.ispcmode 判定
 * PC 模式。不读 const.product.devicetype——SA 域对该参数受 SELinux
 * neverallow 管控。
 * 消费方：kits 直启路由（NAPI/ANI 的 SA 会话分流）与 SA 服务端 PC 门禁。 */
constexpr const char *CM_UKEY_PARAM_IS_PC_MODE = "persist.sceneboard.ispcmode";

inline bool CmUkeyIsPcPlatformOrPcMode()
{
#ifdef CM_TARGET_PLATFORM_PC
    return true; /* PC 平台构建：编译期放行，不读系统参数 */
#else
    /* 每次调用实时读（模式可运行时切换）；读取失败按非 PC 模式处理 */
    return OHOS::system::GetBoolParameter(CM_UKEY_PARAM_IS_PC_MODE, false);
#endif
}

/* ---- 驱动弹框扩展名长度上限（spec v4 D24 / v4.1 用户裁定修正：
 * UkeyAuthDialogInfo.abilityName 非空字符串，≤256 字节）---- */
constexpr uint32_t CM_UKEY_ABILITY_NAME_MAX_LEN = 256;

/* ---- base64 编码（spec §8.4：标准字母表 + padding，仅 want/params 构造边界使用；
 * inner API / IPC 全程传原始字节；实现位于 cm_ukey_dialog_common.cpp）---- */
std::string CmBase64Encode(const uint8_t *data, size_t size);

} // namespace OHOS::Security::CertManager

#endif /* CM_UKEY_DIALOG_COMMON_H */
