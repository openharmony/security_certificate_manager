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
/* base64 (RFC 4648): every BASE64_INPUT_GROUP_BYTES input bytes (24 bits)
 * encode to BASE64_OUTPUT_GROUP_CHARS chars of BASE64_BITS_PER_CHAR bits each,
 * MSB first; a shorter tail is zero-padded and marked with BASE64_PAD_CHAR */
constexpr size_t BASE64_INPUT_GROUP_BYTES = 3;
constexpr size_t BASE64_OUTPUT_GROUP_CHARS = 4;
constexpr uint32_t BASE64_BITS_PER_CHAR = 6;
constexpr uint32_t BASE64_CHAR_MASK = (1U << BASE64_BITS_PER_CHAR) - 1;
constexpr char BASE64_PAD_CHAR = '=';

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
    /* ceil(size / group bytes) * group chars = upper bound of the output length */
    out.reserve(((size + BASE64_INPUT_GROUP_BYTES - 1) / BASE64_INPUT_GROUP_BYTES) *
        BASE64_OUTPUT_GROUP_CHARS);
    /* full groups: pack the bytes big-endian, emit the chars MSB-first */
    size_t i = 0;
    for (; i + BASE64_INPUT_GROUP_BYTES <= size; i += BASE64_INPUT_GROUP_BYTES) {
        uint32_t n = 0;
        for (size_t b = 0; b < BASE64_INPUT_GROUP_BYTES; b++) {
            n = (n << CM_BITS_PER_BYTE) | data[i + b];
        }
        for (size_t c = BASE64_OUTPUT_GROUP_CHARS; c > 0; c--) {
            out += table[(n >> ((c - 1) * BASE64_BITS_PER_CHAR)) & BASE64_CHAR_MASK];
        }
    }
    /* tail: zero-pad the missing bytes; rem real bytes yield rem + (chars -
     * bytes) chars, the rest of the group is padding */
    size_t rem = size - i;
    if (rem > 0) {
        uint32_t n = 0;
        for (size_t b = 0; b < rem; b++) {
            n = (n << CM_BITS_PER_BYTE) | data[i + b];
        }
        n <<= (BASE64_INPUT_GROUP_BYTES - rem) * CM_BITS_PER_BYTE;
        size_t tailChars = rem + (BASE64_OUTPUT_GROUP_CHARS - BASE64_INPUT_GROUP_BYTES);
        for (size_t c = BASE64_OUTPUT_GROUP_CHARS; c > BASE64_OUTPUT_GROUP_CHARS - tailChars; c--) {
            out += table[(n >> ((c - 1) * BASE64_BITS_PER_CHAR)) & BASE64_CHAR_MASK];
        }
        out.append(BASE64_OUTPUT_GROUP_CHARS - tailChars, BASE64_PAD_CHAR);
    }
    return out;
}
} // namespace OHOS::Security::CertManager
