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

#ifndef CM_REQUEST_DIALOG_H
#define CM_REQUEST_DIALOG_H

/* C++-only request helper for the dialog messages: same parcel layout as
 * SendRequestParcel (token + uint32 size + buffer) plus one trailing
 * remote object (the client callback stub), consumed by the SA-side dialog
 * routing in cm_sa.cpp OnRemoteRequest. */

#include <cstdint>

#include "cert_manager_service_ipc_interface_code.h"
#include "cm_type_inner.h"
#include "iremote_object.h"

namespace OHOS {
int32_t SendRequestWithRemote(enum CertManagerInterfaceCode type, const struct CmBlob *inBlob,
    const sptr<IRemoteObject> &remoteObject, int32_t *replyCode);
}

#endif /* CM_REQUEST_DIALOG_H */
