/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef CM_ANI_IMPL_H
#define CM_ANI_IMPL_H

#include <memory>

#include "ani.h"
#include "cm_metrics.h"
#include "cm_type.h"

namespace OHOS::Security::CertManager::Ani {
class CertManagerAniImpl {
public:
    ani_env *env = nullptr;
    int32_t resultCode = 0;
    ani_object result = nullptr;

public:
    CertManagerAniImpl(ani_env *env, const char *interfaceName,
        CmMetricsKind kind = CmMetricsKind::NON_DIALOG);
    virtual ~CertManagerAniImpl();

    virtual int32_t Init() = 0;
    virtual int32_t GetParamsFromEnv() = 0;
    virtual int32_t InvokeInnerApi() = 0;
    virtual int32_t UnpackResult() = 0;
    virtual void OnFinish() = 0;
    virtual ani_object GenerateResult();

    const char *GetInterfaceName() const { return interfaceName_; }

    ani_object Invoke();

    // 开始执行打点上报(虚函数,子类可自定义上报逻辑)
    virtual void OnInvokeStart();
    // 结束执行打点上报(虚函数,子类可自定义上报逻辑,如异步场景下延迟到回调再上报)
    virtual void OnInvokeEnd(int32_t errorCode);

protected:
    std::shared_ptr<CmMetricsReport> metricsReport_ = nullptr;
    CmMetricsKind metricsKind_ = CmMetricsKind::NON_DIALOG;

private:
    const char *interfaceName_ = "CmAniUnknown";
};
} // OHOS::Security::CertManager::Ani

#endif // CM_ANI_IMPL_H
