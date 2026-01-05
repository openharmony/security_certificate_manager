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

#include "cm_ukeylist_data_helper.h"

#include "cm_ipc_response_type.h"
#include "cm_log.h"
#include "cm_type.h"
#include "cm_type_free.h"

namespace OHOS {
int32_t CmUkeyListDataHelper::ParcelReadInvoke(MessageParcel &reply, void *data)
{
    struct CredentialDetailList *credentialDetailList = (struct CredentialDetailList *)data;
    std::unique_ptr<struct CredentialDetailListParcelInfo> certificateListParceInfo(
        reply.ReadParcelable<CredentialDetailListParcelInfo>());
    if (certificateListParceInfo == nullptr) {
        CM_LOG_E("ReadUkeyCertListFromReply infos failed");
        return CMR_ERROR_NULL_POINTER;
    }
    int32_t ret = certificateListParceInfo->TransPortUkeyCertList(credentialDetailList);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("TransPortUkeyCertList failed");
        CmFreeUkeyCertList(certificateListParceInfo->credentialDetailList);
        CM_FREE_PTR(certificateListParceInfo->credentialDetailList);
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    CmFreeUkeyCertList(certificateListParceInfo->credentialDetailList);
    CM_FREE_PTR(certificateListParceInfo->credentialDetailList);
    return CM_SUCCESS;
}

int32_t CmUkeyListDataHelper::ParcelWriteInvoke(MessageParcel *reply, void *data)
{
    struct CredentialDetailList *credentialDetailList = (struct CredentialDetailList *)data;
    std::unique_ptr<struct CredentialDetailListParcelInfo> credentialDetailListParcelInfo(
        new(std::nothrow) CredentialDetailListParcelInfo());
    if (credentialDetailListParcelInfo == nullptr) {
        CM_LOG_E("new CredentialDetailListParcelInfo failed");
        return CMR_ERROR_NULL_POINTER;
    }
    credentialDetailListParcelInfo->credentialDetailList = credentialDetailList;
    if (!reply->WriteParcelable(credentialDetailListParcelInfo.get())) {
        CM_LOG_E("WriteParcelable failed");
        return CMR_ERROR_INVALID_OPERATION;
    }
    return CM_SUCCESS;
}
}