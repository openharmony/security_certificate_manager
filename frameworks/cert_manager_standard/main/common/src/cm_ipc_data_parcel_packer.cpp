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

#include "cm_ipc_data_parcel_packer.h"

#include "cm_ipc_response_type.h"
#include "cm_log.h"
#include "cm_type.h"
#include "cert_manager_service_ipc_interface_code.h"

namespace OHOS {
CmIpcDataParcelPacker &CmIpcDataParcelPacker::GetInstance()
{
    static CmIpcDataParcelPacker instance;
    return instance;
}

CmIpcDataParcelPacker::CmIpcDataParcelPacker()
{
    CM_LOG_D("CmIpcDataParcelPacker constructor");
    SetReadFuncMap();
    SetWriteFuncMap();
}

CmIpcDataParcelPacker::~CmIpcDataParcelPacker()
{
    CM_LOG_D("CmIpcDataParcelPacker destructor");
    innerReadFuncMap_.clear();
    innerWriteFuncMap_.clear();
}

void CmIpcDataParcelPacker::SetReadFuncMap()
{
    innerReadFuncMap_[static_cast<uint32_t>(CM_MSG_GET_UKEY_CERTIFICATE_LIST)] =
        &CmIpcDataParcelPacker::ReadCertListFromParcel;
    innerReadFuncMap_[static_cast<uint32_t>(CM_MSG_GET_UKEY_CERTIFICATE)] =
        &CmIpcDataParcelPacker::ReadCertListFromParcel;
}

void CmIpcDataParcelPacker::SetWriteFuncMap()
{
    innerWriteFuncMap_[static_cast<uint32_t>(CM_MSG_GET_UKEY_CERTIFICATE_LIST)] =
        &CmIpcDataParcelPacker::WriteCertListToParcel;
    innerWriteFuncMap_[static_cast<uint32_t>(CM_MSG_GET_UKEY_CERTIFICATE)] =
        &CmIpcDataParcelPacker::WriteCertListToParcel;
}

int32_t CmIpcDataParcelPacker::ParcelReadInvoke(uint32_t code, MessageParcel &reply, void *data)
{
    if (data == nullptr) {
        CM_LOG_E("ParcelReadInvoke data is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }
    CM_LOG_D("ParcelReadInvoke, type: %u", code);
    if (innerReadFuncMap_.find(code) == innerReadFuncMap_.end()) {
        CM_LOG_E("code is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    auto func = innerReadFuncMap_[code];
    if (func == nullptr) {
        CM_LOG_E("get parcel read function failed");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return (this->*func)(reply, data);
}

int32_t CmIpcDataParcelPacker::ParcelWriteInvoke(uint32_t code, MessageParcel *reply, void *data)
{
    if (data == nullptr) {
        CM_LOG_E("ParcelWriteInvoke data is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }
    CM_LOG_D("ParcelWriteInvoke, type: %u", code);
    if (innerWriteFuncMap_.find(code) == innerWriteFuncMap_.end()) {
        CM_LOG_E("code is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    auto func = innerWriteFuncMap_[code];
    if (func == nullptr) {
        CM_LOG_E("get parcel write function failed");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return (this->*func)(reply, data);
}

int32_t CmIpcDataParcelPacker::ReadCertListFromParcel(MessageParcel &reply, void *data)
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
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    return CM_SUCCESS;
}

int32_t CmIpcDataParcelPacker::WriteCertListToParcel(MessageParcel *reply, void *data)
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