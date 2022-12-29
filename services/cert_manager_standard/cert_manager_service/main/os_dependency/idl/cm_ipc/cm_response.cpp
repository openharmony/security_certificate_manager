/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "cm_response.h"

#include <dlfcn.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "ipc_skeleton.h"

#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type_inner.h"
#include "os_account_manager.h"

using namespace OHOS;

void CmSendResponse(const struct CmContext *context, int32_t result, const struct CmBlob *response)
{
    if (context == nullptr) {
        CM_LOG_E("SendResponse NULL Pointer");
        return;
    }
    MessageParcel *reply = reinterpret_cast<MessageParcel *>(const_cast<CmContext *>(context));
    reply->WriteInt32(result);
    if (response == nullptr) {
        reply->WriteUint32(0);
    } else {
        reply->WriteUint32(response->size);
        reply->WriteBuffer(response->data, static_cast<size_t>(response->size));
        CM_LOG_I("CmSendResponse before result = %d, size = %u", result, response->size);
    }
}

int32_t CmGetProcessInfoForIPC(struct CmContext *cmContext)
{
    if (cmContext == nullptr) {
        CM_LOG_D("CmGetProcessInfoForIPC Paramset is Invalid");
        return CM_FAILURE;
    }

    int userId = 0;
    auto callingUid = IPCSkeleton::GetCallingUid();

    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId);
    CM_LOG_I("CmGetProcessInfoForIPC callingUid = %d, userId = %d", callingUid, userId);

    cmContext->uid = (uint32_t)callingUid;
    cmContext->userId = static_cast<uint32_t>(userId);

    return CM_SUCCESS;
}
