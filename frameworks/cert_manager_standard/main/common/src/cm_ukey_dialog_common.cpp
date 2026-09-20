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

/* Shared utility implementation for the UKey Pin dialog chain (declarations in
 * cm_ukey_dialog_common.h, spec §8.4).
 * base64 moved out of the inline implementation in the header: inline
 * functions must not exceed 10 lines. */

#include "cm_ukey_dialog_common.h"

namespace OHOS::Security::CertManager {
/* base64 (RFC 4648): every 3 input bytes (24 bits) encode to 4 chars of
 * 6 bits each, MSB first; a shorter tail is zero-padded and marked with '=' */
constexpr size_t BASE64_INPUT_GROUP_BYTES = 3;
constexpr size_t BASE64_OUTPUT_GROUP_CHARS = 4;
constexpr uint32_t BASE64_BITS_PER_CHAR = 6;
constexpr uint32_t BASE64_CHAR_MASK = (1U << BASE64_BITS_PER_CHAR) - 1;

/* hidden visibility: this utility is consumed only via the static library
 * (kits/common and the SA dialog module) and must not enter any .so dynamic
 * symbol table - otherwise dependents would bind the reference to an exported
 * .so symbol (e.g. libcert_manager_sdk.z.so) and runtime resolution would
 * fail when an older .so is deployed */
__attribute__((visibility("hidden"))) std::string CmBase64Encode(const uint8_t *data, size_t size)
{
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    if (data == nullptr || size == 0) {
        return out;
    }
    out.reserve(((size + BASE64_INPUT_GROUP_BYTES - 1) / BASE64_INPUT_GROUP_BYTES) *
        BASE64_OUTPUT_GROUP_CHARS);
    size_t i = 0;
    for (; i + BASE64_INPUT_GROUP_BYTES <= size; i += BASE64_INPUT_GROUP_BYTES) {
        /* pack one 3-byte group big-endian into 24 bits */
        uint32_t n = (static_cast<uint32_t>(data[i]) << (2 * CM_BITS_PER_BYTE)) |
            (static_cast<uint32_t>(data[i + 1]) << CM_BITS_PER_BYTE) |
            static_cast<uint32_t>(data[i + 2]);
        out += table[(n >> (3 * BASE64_BITS_PER_CHAR)) & BASE64_CHAR_MASK];
        out += table[(n >> (2 * BASE64_BITS_PER_CHAR)) & BASE64_CHAR_MASK];
        out += table[(n >> BASE64_BITS_PER_CHAR) & BASE64_CHAR_MASK];
        out += table[n & BASE64_CHAR_MASK];
    }
    size_t rem = size - i;
    if (rem == 1) {
        uint32_t n = static_cast<uint32_t>(data[i]) << (2 * CM_BITS_PER_BYTE);
        out += table[(n >> (3 * BASE64_BITS_PER_CHAR)) & BASE64_CHAR_MASK];
        out += table[(n >> (2 * BASE64_BITS_PER_CHAR)) & BASE64_CHAR_MASK];
        out += "==";
    } else if (rem == 2) {
        uint32_t n = (static_cast<uint32_t>(data[i]) << (2 * CM_BITS_PER_BYTE)) |
            (static_cast<uint32_t>(data[i + 1]) << CM_BITS_PER_BYTE);
        out += table[(n >> (3 * BASE64_BITS_PER_CHAR)) & BASE64_CHAR_MASK];
        out += table[(n >> (2 * BASE64_BITS_PER_CHAR)) & BASE64_CHAR_MASK];
        out += table[(n >> BASE64_BITS_PER_CHAR) & BASE64_CHAR_MASK];
        out += '=';
    }
    return out;
}
} // namespace OHOS::Security::CertManager
