/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "os_account_manager.h"

#define MAX_SIZE_CAPACITY (1 * 1024 * 1024) /* Prevent sendrequest from failing to send due to memory limitations */

using namespace OHOS;

static bool IsBetween(int32_t result, int32_t resultBegin, int32_t resultEnd)
{
    if ((result > resultEnd) && (result < resultBegin)) {
        return true;
    }
    return false;
}

static int32_t ConvertErrorCode(int32_t result)
{
    if (IsBetween(result, CMR_ERROR_INVALID_ARGUMENT_BEGIN, CMR_ERROR_INVALID_ARGUMENT_END)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (IsBetween(result, CMR_ERROR_KEY_OPERATION_BEGIN, CMR_ERROR_KEY_OPERATION_END)) {
        return CMR_ERROR_KEY_OPERATION_FAILED;
    }

    if (IsBetween(result, CMR_ERROR_AUTH_FAILED_BEGIN, CMR_ERROR_AUTH_FAILED_END)) {
        return CMR_ERROR_AUTH_CHECK_FAILED;
    }

    return result;
}

void CmSendResponse(const struct CmContext *context, int32_t result, const struct CmBlob *response)
{
    if (context == nullptr) {
        CM_LOG_E("SendResponse NULL Pointer");
        return;
    }

    int32_t ret = ConvertErrorCode(result);
    MessageParcel *reply = reinterpret_cast<MessageParcel *>(const_cast<CmContext *>(context));
    reply->WriteInt32(ret);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("SendResponse result is %d.", ret);
        return;
    }
    if (response == nullptr) {
        reply->WriteUint32(0);
    } else {
        reply->SetMaxCapacity(MAX_SIZE_CAPACITY);
        reply->WriteUint32(response->size);
        reply->WriteBuffer(response->data, static_cast<size_t>(response->size));
    }
}

int32_t CmGetProcessInfoForIPC(struct CmContext *cmContext)
{
    if (cmContext == nullptr) {
        CM_LOG_D("CmGetProcessInfoForIPC Paramset is Invalid");
        return CMR_ERROR_NULL_POINTER;
    }

    int userId = 0;
    auto callingUid = IPCSkeleton::GetCallingUid();

    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId);

    cmContext->uid = (uint32_t)callingUid;
    cmContext->userId = static_cast<uint32_t>(userId);

    return CM_SUCCESS;
}
