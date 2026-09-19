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

/* UKey Pin 弹框链路共享工具实现（声明见 cm_ukey_dialog_common.h，spec §8.4）。
 * base64 自 header 内联实现移出：内联函数不得超 10 行。 */

#include "cm_ukey_dialog_common.h"

namespace OHOS::Security::CertManager {
/* hidden 可见性：该工具仅随静态库消费（kits/common 与 SA dialog 模块），不得
 * 进入任何 .so 动态符号表——否则依赖方会把引用绑定到 .so 导出符号（如
 * libcert_manager_sdk.z.so），旧版 so 部署场景下运行时解析失败 */
__attribute__((visibility("hidden"))) std::string CmBase64Encode(const uint8_t *data, size_t size)
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
