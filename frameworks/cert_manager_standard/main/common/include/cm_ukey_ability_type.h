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

#ifndef CM_UKEY_ABILITY_TYPE_H
#define CM_UKEY_ABILITY_TYPE_H

/* Custom Pin dialog ability type registered by a UKey driver (aligned with the
 * HUKS HksAbilityInfo.abilityType value convention: 0 = UIAbility,
 * 1 = UIExtensionAbility; since v4 openUkeyAuthDialog only admits 1).
 * Note: HksAbilityInfo in this source tree has not yet merged the
 * abilityType field, so the non-stub path temporarily returns UIAbility;
 * switch to pass-through once the HUKS field lands. */
#define CM_UKEY_ABILITY_TYPE_UIABILITY   0
#define CM_UKEY_ABILITY_TYPE_UIEXTENSION 1

#endif /* CM_UKEY_ABILITY_TYPE_H */
