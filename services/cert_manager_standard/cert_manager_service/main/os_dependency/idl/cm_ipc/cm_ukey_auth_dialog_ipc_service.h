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
/* UKey 认证弹框 IPC 处理器（对齐 ukey parcel 系列表模式：context 即 reply parcel，
 * 处理器经 CmSendResponse 写同步应答，ConvertErrorCode 不折叠 -1016/-1018）。
 * 请求 parcel：OPEN   [uint32 size][paramSet: CM_TAG_PARAM0_BUFFER=keyUri][remote object 回调stub]
 *             REPORT [uint32 size][paramSet: CM_TAG_PARAM0_BUFFER=requestId, CM_TAG_PARAM1_UINT32=resultCode]
 * OPEN 因需从 data parcel 读取 remote object，由 cm_sa.cpp OnRemoteRequest 分支调用；
 * REPORT 无额外参数，经 g_cmParcelIpcHandler 表分发。 */
void CmIpcServiceOpenUkeyAuthDialog(uint32_t code, const struct CmBlob *paramSetBlob,
    const struct CmContext *context, const sptr<IRemoteObject> &clientCallback);

void CmIpcServiceReportUkeyAuthResult(uint32_t code, const struct CmBlob *paramSetBlob,
    const struct CmContext *context);
} // namespace OHOS::Security::CertManager
#endif // CM_UKEY_AUTH_DIALOG_IPC_SERVICE_H
