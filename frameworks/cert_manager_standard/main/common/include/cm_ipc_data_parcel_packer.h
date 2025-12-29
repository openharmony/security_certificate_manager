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

#ifndef CM_IPC_DATA_PARCEL_PACKER_H
#define CM_IPC_DATA_PARCEL_PACKER_H

#include <unordered_map>

#include "message_parcel.h"

namespace OHOS {
class CmIpcDataParcelPacker {
public:
    static CmIpcDataParcelPacker &GetInstance();

    int32_t ParcelReadInvoke(uint32_t code, MessageParcel &reply, void *data);
    int32_t ParcelWriteInvoke(uint32_t code, MessageParcel *reply, void *data);

private:
    DISALLOW_COPY_AND_MOVE(CmIpcDataParcelPacker);
    CmIpcDataParcelPacker();
    ~CmIpcDataParcelPacker();

    int32_t ReadCertListFromParcel(MessageParcel &reply, void *data);
    int32_t WriteCertListToParcel(MessageParcel *reply, void *data);

    using CmIpcDataParcelPackerReadFunc = int32_t (CmIpcDataParcelPacker::*)(MessageParcel&, void*);
    using CmIpcDataParcelPackerWriteFunc = int32_t (CmIpcDataParcelPacker::*)(MessageParcel*, void*);

    void SetReadFuncMap();
    void SetWriteFuncMap();

    std::unordered_map<int32_t, CmIpcDataParcelPackerReadFunc> innerReadFuncMap_;
    std::unordered_map<int32_t, CmIpcDataParcelPackerWriteFunc> innerWriteFuncMap_;
};
}

#endif