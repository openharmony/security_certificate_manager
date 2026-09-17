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

import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import ExtensionAbility from '@ohos.app.ability.ExtensionAbility';
import Want from '@ohos.app.ability.Want';
import UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';
import UkeyAuthExtensionContext from '@ohos.security.UkeyAuthExtensionContext';

export default class UkeyAuthExtensionAbility extends ExtensionAbility {

  private destroyCallbackPoint: long;
  private native nativeOnDestroyCallback(): void;
  public callOnDestroy(): boolean {
    let p = this.onDestroy();
    if (p instanceof Promise) {
      p.then(() => this.nativeOnDestroyCallback());
      return true;
    }
    return false;
  }

  context: UkeyAuthExtensionContext = {};

  onCreate(launchParam: AbilityConstant.LaunchParam): void {}

  onSessionCreate(want: Want, session: UIExtensionContentSession): void {}

  onSessionDestroy(session: UIExtensionContentSession): void {}

  onDestroy(): Promise<void> | undefined {
    return undefined;
  }
}
