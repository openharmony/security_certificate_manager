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

/* UKey 驱动注册的自定义 Pin 弹框 ability 类型（对齐 HUKS HksAbilityInfo.abilityType
 * 取值约定：0 = UIAbility（默认，兼容存量注册），1 = UIExtensionAbility）。
 * 注：本源码树 HUKS 的 HksAbilityInfo 尚未合入 abilityType 字段，非桩路径
 * 暂固定返回 UIAbility，待 HUKS 字段合入后替换为透传。 */
#define CM_UKEY_ABILITY_TYPE_UIABILITY   0
#define CM_UKEY_ABILITY_TYPE_UIEXTENSION 1

#ifdef CERT_MANAGER_UKEY_ABILITY_QUERY_STUB
/* TEMP(联调桩，上游 PR 前移除)：由 certificate_manager_ukey_ability_stub 开启，
 * HksQueryAbilityInfo 查询按 persist.security.cm.ukey_stub_type 旋钮返回，模拟
 * UKey 驱动注册的 UIExtensionAbility / UIAbility 两类自定义 Pin 弹框，用于无真实
 * UKey 设备的真机联调全链路。 */
#define CM_UKEY_ABILITY_STUB_BUNDLE  "com.example.ukeyauthability2"
#define CM_UKEY_ABILITY_STUB_ABILITY "MyUkeyAuthExtensionAbility"
#define CM_UKEY_ABILITY_STUB_UIABILITY_NAME "MyUkeyAuthAbility"
#endif

#endif /* CM_UKEY_ABILITY_TYPE_H */
