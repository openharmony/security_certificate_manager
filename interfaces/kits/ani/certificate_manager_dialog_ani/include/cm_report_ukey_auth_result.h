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

#ifndef CM_REPORT_UKEY_AUTH_RESULT_H
#define CM_REPORT_UKEY_AUTH_RESULT_H

#include "cm_ani_impl.h"
#include "cm_log.h"
#include "cm_type.h"

namespace OHOS::Security::CertManager::Ani {
class CmReportUkeyAuthResult : public CertManagerAniImpl {
private:
    /* ani params */
    ani_string aniRequestId = nullptr;
    ani_double aniResultCode = 0;
    ani_object callback = nullptr;
    /* parsed params */
    CmBlob requestId = { 0 };
    int32_t resultCode = 0;

public:
    CmReportUkeyAuthResult(ani_env *env, ani_string aniRequestId, ani_double aniResultCode,
        ani_object callback);
    ~CmReportUkeyAuthResult() {};

    int32_t Init() override;
    int32_t GetParamsFromEnv() override;
    int32_t InvokeInnerApi() override;
    int32_t UnpackResult() override;
    void OnFinish() override;
    ani_object GenerateResult() override;
};
}
#endif // CM_REPORT_UKEY_AUTH_RESULT_H
