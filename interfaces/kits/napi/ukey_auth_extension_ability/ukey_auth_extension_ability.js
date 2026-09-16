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

let ExtensionAbility = requireNapi('app.ability.ExtensionAbility');
let hilog = requireNapi('hilog');

let domainID = 0xD001320;
let TAG = 'JSENV';

class UkeyAuthExtensionAbility extends ExtensionAbility {
  onCreate(launchParam) {
    hilog.sLogI(domainID, TAG, 'onCreate');
  }

  onSessionCreate(want, session) {
    hilog.sLogI(domainID, TAG, 'onSessionCreate, want:' + want.abilityName);
  }

  onSessionDestroy(session) {
    hilog.sLogI(domainID, TAG, 'onSessionDestroy');
  }

  onDestroy() {
    hilog.sLogI(domainID, TAG, 'onDestroy');
  }
}

export default UkeyAuthExtensionAbility;
