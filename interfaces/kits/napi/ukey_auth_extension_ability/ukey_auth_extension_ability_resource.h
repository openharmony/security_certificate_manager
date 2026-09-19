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

/* 嵌入资源符号声明（ukeyAuth 扩展 ability 模块的 js/abc 资源）：
 * 符号由构建期 gen_js_obj / es2abc_gen_abc 将资源编入目标文件生成，
 * 无对应头文件可 include，统一收敛到本声明头（禁止在源文件中裸写 extern
 * 引用外部变量）。符号区间 [_start, _end) 为资源内容。 */

#ifndef UKEY_AUTH_EXTENSION_ABILITY_RESOURCE_H
#define UKEY_AUTH_EXTENSION_ABILITY_RESOURCE_H

#ifdef __cplusplus
extern "C" {
#endif

extern const char _binary_ukey_auth_extension_ability_js_start[];
extern const char _binary_ukey_auth_extension_ability_js_end[];
extern const char _binary_ukey_auth_extension_ability_abc_start[];
extern const char _binary_ukey_auth_extension_ability_abc_end[];

#ifdef __cplusplus
}
#endif

#endif /* UKEY_AUTH_EXTENSION_ABILITY_RESOURCE_H */
