/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef CM_UKEY_AUTH_DIALOG_IPC_SERVICE_H
#define CM_UKEY_AUTH_DIALOG_IPC_SERVICE_H

#include "iremote_object.h"

#include "cm_type.h"
#include "cm_response.h"

namespace OHOS::Security::CertManager {
/* UKey auth dialog IPC handlers (aligned with the ukey parcel-series table
 * pattern: context is the reply parcel; handlers write the sync response via
 * CmSendResponse; ConvertErrorCode does not fold -1016/-1018).
 * Request parcels: OPEN   [uint32 size][remote object callback stub][paramSet buffer]
 *                  (the remote object sits before the buffer: WriteBuffer
 *                   pads the tail to 4-byte alignment while ReadBuffer does
 *                   not skip the pad, so an object written after a
 *                   non-aligned buffer cannot be read on the SA side)
 *                 REPORT [uint32 size][paramSet buffer: CM_TAG_PARAM0_BUFFER=requestId,
 *                  CM_TAG_PARAM1_UINT32=resultCode]
 * OPEN is dispatched from a branch of cm_sa.cpp OnRemoteRequest because it
 * must read the remote object from the data parcel; REPORT has no extra
 * params and is dispatched via the g_cmParcelIpcHandler table. */
void CmIpcServiceOpenUkeyAuthDialog(uint32_t code, const struct CmBlob *paramSetBlob,
    const struct CmContext *context, const sptr<IRemoteObject> &clientCallback);

void CmIpcServiceOpenUkeyAuthDialogForDriver(uint32_t code, const struct CmBlob *paramSetBlob,
    const struct CmContext *context, const sptr<IRemoteObject> &clientCallback);

void CmIpcServiceReportUkeyAuthResult(uint32_t code, const struct CmBlob *paramSetBlob,
    const struct CmContext *context);
} // namespace OHOS::Security::CertManager
#endif // CM_UKEY_AUTH_DIALOG_IPC_SERVICE_H
