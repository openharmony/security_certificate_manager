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

#ifndef CM_IPC_RESPONSE_TYPE_H
#define CM_IPC_RESPONSE_TYPE_H

#include "cm_type_inner.h"
#include "parcel.h"

namespace OHOS {

struct CredentialDetailListParcelInfo final : public Parcelable {
public:
    CredentialDetailListParcelInfo& operator=(const CredentialDetailListParcelInfo&) = delete;

    bool Marshalling(Parcel &parcel) const override;
    static CredentialDetailListParcelInfo *Unmarshalling(Parcel &parcel);
    bool ReadFromParcel(Parcel &parcel);
    int32_t TransPortUkeyCertList(struct CredentialDetailList *credentialDetailList);

    struct CredentialDetailList *credentialDetailList;
};
}

#endif /* CM_IPC_RESPONSE_TYPE_H */
