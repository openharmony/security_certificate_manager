/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CM_DATA_PARCEL_PROCESSOR_H
#define CM_DATA_PARCEL_PROCESSOR_H

#include "cm_data_parcel_strategy.h"

#include "cert_manager_service_ipc_interface_code.h"
#include "message_parcel.h"

namespace OHOS {
class CmDataParcelProcessor {
public:
    CmDataParcelProcessor() = default;
    explicit CmDataParcelProcessor(std::unique_ptr<CmDataParcelStrategy> initParcelHelper);

    static std::unique_ptr<CmDataParcelStrategy> CreateParcelStrategy(enum CertManagerInterfaceCode type);

    void SetParcelStrategy(std::unique_ptr<CmDataParcelStrategy> newDataParcelHelper);
    int32_t ReadFromParcel(MessageParcel &reply, void *data);
    int32_t WriteToParcel(MessageParcel *reply, void *data);


private:
    std::unique_ptr<CmDataParcelStrategy> dataParcelStrategy;
};
}

#endif