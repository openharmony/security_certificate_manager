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

/* ---- 场景（spec D9：UkeyAuthScene）---- */
constexpr const char *CM_UKEY_SCENE_LOGIN_STR = "Login";   /* 接受默认弹框回退 */
constexpr const char *CM_UKEY_SCENE_CUSTOM_STR = "Custom"; /* 仅自定义弹框 */

inline const char *CmUkeySceneToString(uint32_t scene)
{
    return (scene == CM_UKEY_AUTH_SCENE_CUSTOM) ? CM_UKEY_SCENE_CUSTOM_STR : CM_UKEY_SCENE_LOGIN_STR;
}

inline bool CmUkeySceneIsValid(uint32_t scene)
{
    return scene == CM_UKEY_AUTH_SCENE_LOGIN || scene == CM_UKEY_AUTH_SCENE_CUSTOM;
}

/* ---- want / parameters JSON 参数键（弹框提供方契约，spec §6.2/§6.3）---- */
constexpr const char *CM_UKEY_DIALOG_PARAM_SCENE = "scene";
constexpr const char *CM_UKEY_DIALOG_PARAM_CUSTOM_DATA = "customData";

/* ---- 系统默认弹框身份（spec v3 D14 修订：com.ohos.certmanager 内新增的
 * ukeyAuth 类型 UIExtensionAbility，复用既有 UKeyAuthSheet 页面；其
 * UkeyAuthExtensionContext.terminateSelf* 由框架完成对 CM SA 的上报）---- */
constexpr const char *CM_UKEY_DEFAULT_DIALOG_BUNDLE = "com.ohos.certmanager";
constexpr const char *CM_UKEY_DEFAULT_DIALOG_ABILITY = "UkeyAuthExtensionAbility";
constexpr const char *CM_UKEY_DEFAULT_DIALOG_EXT_TYPE = "ukeyAuth";

/* ---- PC / PC 模式判定（spec D15，仅 SA 消费）---- */
constexpr const char *CM_UKEY_PARAM_DEVICETYPE = "const.product.devicetype";
constexpr const char *CM_UKEY_DEVICETYPE_PC = "2in1";
constexpr const char *CM_UKEY_PARAM_IS_PC_MODE = "persist.sceneboard.ispcmode";

inline bool CmUkeyIsPcOrPcMode()
{
    /* 每次调用实时读（模式可运行时切换）；2in1 为 PC 形态权威值 */
    if (OHOS::system::GetParameter(CM_UKEY_PARAM_DEVICETYPE, "default") == CM_UKEY_DEVICETYPE_PC) {
        return true;
    }
    return OHOS::system::GetBoolParameter(CM_UKEY_PARAM_IS_PC_MODE, false);
}

#ifdef CERT_MANAGER_UKEY_ABILITY_QUERY_STUB
/* ---- 联调桩运行时旋钮（spec D16，TEMP：上游 PR 前随桩一并移除）----
 * persist.security.cm.ukey_stub_type:
 *   uiextension（缺省/未知值）固定返回 UIExtensionAbility 三元组
 *   uiability                 固定返回 UIAbility 三元组
 *   none                      返回失败（模拟未注册 → 默认弹框路由） */
constexpr const char *CM_UKEY_ABILITY_STUB_PARAM = "persist.security.cm.ukey_stub_type";
constexpr const char *CM_UKEY_ABILITY_STUB_VAL_UIEXTENSION = "uiextension";
constexpr const char *CM_UKEY_ABILITY_STUB_VAL_UIABILITY = "uiability";
constexpr const char *CM_UKEY_ABILITY_STUB_VAL_NONE = "none";

inline int32_t CmUkeyAbilityStubQuery(std::string &bundleName, std::string &abilityName,
    uint32_t &abilityType)
{
    std::string knob = OHOS::system::GetParameter(CM_UKEY_ABILITY_STUB_PARAM,
        CM_UKEY_ABILITY_STUB_VAL_UIEXTENSION);
    if (knob == CM_UKEY_ABILITY_STUB_VAL_NONE) {
        bundleName.clear();
        abilityName.clear();
        abilityType = CM_UKEY_ABILITY_TYPE_UIABILITY;
        return CM_FAILURE; /* 模拟未注册：调用方按查询失败走默认弹框路由 */
    }
    bundleName = CM_UKEY_ABILITY_STUB_BUNDLE;
    abilityName = CM_UKEY_ABILITY_STUB_ABILITY;
    abilityType = (knob == CM_UKEY_ABILITY_STUB_VAL_UIABILITY) ? CM_UKEY_ABILITY_TYPE_UIABILITY
                                                               : CM_UKEY_ABILITY_TYPE_UIEXTENSION;
    return CM_SUCCESS;
}
#endif /* CERT_MANAGER_UKEY_ABILITY_QUERY_STUB */

/* ---- base64 编码（spec §8.4：标准字母表 + padding，仅 want/params 构造边界使用；
 * inner API / IPC 全程传原始字节）---- */
inline std::string CmBase64Encode(const uint8_t *data, size_t size)
{
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    if (data == nullptr || size == 0) {
        return out;
    }
    out.reserve(((size + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 3 <= size; i += 3) {
        uint32_t n = (static_cast<uint32_t>(data[i]) << 16) |
            (static_cast<uint32_t>(data[i + 1]) << 8) | static_cast<uint32_t>(data[i + 2]);
        out += table[(n >> 18) & 0x3F];
        out += table[(n >> 12) & 0x3F];
        out += table[(n >> 6) & 0x3F];
        out += table[n & 0x3F];
    }
    size_t rem = size - i;
    if (rem == 1) {
        uint32_t n = static_cast<uint32_t>(data[i]) << 16;
        out += table[(n >> 18) & 0x3F];
        out += table[(n >> 12) & 0x3F];
        out += "==";
    } else if (rem == 2) {
        uint32_t n = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8);
        out += table[(n >> 18) & 0x3F];
        out += table[(n >> 12) & 0x3F];
        out += table[(n >> 6) & 0x3F];
        out += '=';
    }
    return out;
}

} // namespace OHOS::Security::CertManager

#endif /* CM_UKEY_DIALOG_COMMON_H */
