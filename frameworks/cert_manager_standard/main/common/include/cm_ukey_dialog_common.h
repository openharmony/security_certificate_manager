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

/* ---- 驱动弹框扩展名长度上限（spec v4 D24 / v4.1 用户裁定修正：
 * UkeyAuthDialogInfo.abilityName 非空字符串，≤256 字节）---- */
constexpr uint32_t CM_UKEY_ABILITY_NAME_MAX_LEN = 256;

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
