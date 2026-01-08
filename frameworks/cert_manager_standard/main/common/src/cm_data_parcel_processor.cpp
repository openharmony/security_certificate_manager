/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "cm_data_parcel_processor.h"

#include "cm_log.h"

namespace OHOS {
CmDataParcelProcessor::CmDataParcelProcessor(std::unique_ptr<CmDataParcelStrategy> initParcelStrategy)
    : dataParcelStrategy(std::move(initParcelStrategy)) {}

void CmDataParcelProcessor::SetParcelStrategy(std::unique_ptr<CmDataParcelStrategy> newDataParcelStrategy)
{
    CM_LOG_D("SetParcelStrategy begin");
    dataParcelStrategy = std::move(newDataParcelStrategy);
}

int32_t CmDataParcelProcessor::ReadFromParcel(MessageParcel &reply, void *data)
{
    if (dataParcelStrategy == nullptr) {
        CM_LOG_E("ReadFromParcel dataParcelStrategy is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }
    int32_t res = dataParcelStrategy->ParcelReadInvoke(reply, data);
    if (res != CM_SUCCESS) {
        CM_LOG_E("ParcelReadInvoke failed");
        return CMR_ERROR_INVALID_OPERATION;
    }
    return CM_SUCCESS;
}

int32_t CmDataParcelProcessor::WriteToParcel(MessageParcel *reply, void *data)
{
    if (dataParcelStrategy == nullptr) {
        CM_LOG_E("WriteToParcel dataParcelStrategy is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }
    int32_t res = dataParcelStrategy->ParcelWriteInvoke(reply, data);
    if (res != CM_SUCCESS) {
        CM_LOG_E("ParcelWriteInvoke failed");
        return CMR_ERROR_INVALID_OPERATION;
    }
    return CM_SUCCESS;
}
}