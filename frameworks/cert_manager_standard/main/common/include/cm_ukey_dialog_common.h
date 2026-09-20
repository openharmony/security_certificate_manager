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

/* Shared constants and utilities for the UKey Pin dialog chain (single source
 * for both the kit direct-launch and SA-launch sides, spec v3 §6/§8.4).
 * This header is for C++ consumers only (kits/common and the SA dialog module). */

namespace OHOS::Security::CertManager {

/* ---- want / parameters JSON keys (dialog provider contract, spec §6.2/§6.3) ---- */
constexpr const char *CM_UKEY_DIALOG_PARAM_CUSTOM_DATA = "customData";

/* ---- PC platform / PC mode check (spec D15, user ruling) ----
 * Level 1 (compile time): PC platform builds (BUILD.gn target_platform == "pc"
 * injects the CM_TARGET_PLATFORM_PC macro, propagated through the
 * frameworks/common public config) pass directly;
 * Level 2 (runtime, non-PC builds only): read persist.sceneboard.ispcmode to
 * decide PC mode. const.product.devicetype is not read - that parameter is
 * governed by a SELinux neverallow rule in the SA domain.
 * Consumers: kit direct-launch routing (NAPI/ANI SA-session branching) and the
 * SA-side PC gate. */
constexpr const char *CM_UKEY_PARAM_IS_PC_MODE = "persist.sceneboard.ispcmode";

inline bool CmUkeyIsPcPlatformOrPcMode()
{
#ifdef CM_TARGET_PLATFORM_PC
    return true; /* PC platform build: pass at compile time, no system parameter read */
#else
    /* Read live on every call (mode can switch at runtime); read failure counts as non-PC mode */
    return OHOS::system::GetBoolParameter(CM_UKEY_PARAM_IS_PC_MODE, false);
#endif
}

/* ---- Driver dialog extension name length limit (spec v4 D24 / v4.1 user
 * ruling amendment: UkeyAuthDialogInfo.abilityName is a non-empty string,
 * <= 256 bytes) ---- */
constexpr uint32_t CM_UKEY_ABILITY_NAME_MAX_LEN = 256;

/* ---- base64 encoding (spec §8.4: standard alphabet + padding, used only at
 * the want/params construction boundary; raw bytes travel over inner API /
 * IPC the whole way; implementation lives in cm_ukey_dialog_common.cpp) ---- */
std::string CmBase64Encode(const uint8_t *data, size_t size);

} // namespace OHOS::Security::CertManager

#endif /* CM_UKEY_DIALOG_COMMON_H */
