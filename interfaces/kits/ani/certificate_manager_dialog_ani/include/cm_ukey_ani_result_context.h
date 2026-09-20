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

#ifndef CM_UKEY_ANI_RESULT_CONTEXT_H
#define CM_UKEY_ANI_RESULT_CONTEXT_H

#include <memory>

#include "ani.h"
#include "cm_ani_common.h"
#include "cm_log.h"
#include "cm_metrics.h"

namespace OHOS::Security::CertManager::Ani {

/* Result context kept alive from the open call (openUkeyAuthDialog SA session /
 * openAuthDialogForUkeyProvider) until the AsyncCallbackWrapper is invoked on
 * the IPC thread; ownership is handed to the result callback which deletes it
 * after settling. */
struct CmUkeyAuthDialogAniResultContext {
    ani_vm *vm = nullptr;
    ani_ref globalCallback = nullptr;
    std::shared_ptr<CmMetricsReport> metricsReport = nullptr;
};

/* Common cleanup of the result context: delete the global callback reference,
 * detach the IPC thread from the VM, then free the context itself. */
inline void ReleaseUkeyAuthResultResources(ani_env *env, CmUkeyAuthDialogAniResultContext *context)
{
    ani_status status = env->GlobalReference_Delete(context->globalCallback);
    if (status != ANI_OK) {
        CM_LOG_E("delete global reference failed. status = %d", static_cast<int32_t>(status));
    }
    status = DetachCurrentThreadEnv(context->vm);
    if (status != ANI_OK) {
        CM_LOG_E("DetachCurrentThreadEnv failed. status = %d", static_cast<int32_t>(status));
    }
    delete context;
}

} // namespace OHOS::Security::CertManager::Ani

#endif // CM_UKEY_ANI_RESULT_CONTEXT_H
