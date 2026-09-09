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

namespace OHOS::Security::CertManager {
/* UKey 认证弹框 IPC 处理器（新式同步应答：处理器返回值由路由层
 * reply.WriteInt32 原样透传，不经 ConvertErrorCode 折叠）。
 * 请求 parcel：OPEN   [uint32 size][paramSet: CM_TAG_PARAM0_BUFFER=keyUri][remote object 回调stub]
 *             REPORT [uint32 size][paramSet: CM_TAG_PARAM0_BUFFER=requestId, CM_TAG_PARAM1_UINT32=resultCode] */
int32_t CmIpcServiceOpenUkeyAuthDialog(const struct CmBlob *paramSetBlob,
    const sptr<IRemoteObject> &clientCallback);

int32_t CmIpcServiceReportUkeyAuthResult(const struct CmBlob *paramSetBlob);
} // namespace OHOS::Security::CertManager
#endif // CM_UKEY_AUTH_DIALOG_IPC_SERVICE_H
