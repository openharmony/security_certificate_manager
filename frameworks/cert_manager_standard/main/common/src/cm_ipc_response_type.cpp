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

#include "cm_ipc_response_type.h"

#include "cm_type.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_type_free.h"

namespace OHOS {
static bool ReadCertInfoFromParcel(Parcel &parcel, Credential *credential)
{
    const uint8_t *typeData = parcel.ReadUnpadBuffer(MAX_LEN_SUBJECT_NAME);
    if (typeData == nullptr) {
        return false;
    }
    if (memcpy_s(credential->type, MAX_LEN_SUBJECT_NAME, typeData, MAX_LEN_SUBJECT_NAME) != EOK) {
        CM_LOG_E("copy type failed");
        return false;
    }
    const uint8_t *aliasData = parcel.ReadUnpadBuffer(MAX_LEN_CERT_ALIAS);
    if (aliasData == nullptr) {
        return false;
    }
    if (memcpy_s(credential->alias, MAX_LEN_CERT_ALIAS, aliasData, MAX_LEN_CERT_ALIAS) != EOK) {
        CM_LOG_E("copy alias failed");
        return false;
    }
    const uint8_t *keyUriData = parcel.ReadUnpadBuffer(MAX_LEN_URI);
    if (keyUriData == nullptr) {
        return false;
    }
    if (memcpy_s(credential->keyUri, MAX_LEN_URI, keyUriData, MAX_LEN_URI) != EOK) {
        CM_LOG_E("copy keyUri failed");
        return false;
    }
    return true;
}

static bool ReadCredDataFromParcel(Parcel &parcel, Credential *credential)
{
    uint32_t credDataSize = 0;
    if (!parcel.ReadUint32(credDataSize)) {
        return false;
    }
    credential->credData.data = static_cast<uint8_t*>(CmMalloc(credDataSize));
    if (credential->credData.data == nullptr) {
        return false;
    }
    credential->credData.size = credDataSize;
    if (credential->credData.size > MAX_LEN_CERTIFICATE) {
        CM_LOG_E("credData size is too big");
        CM_FREE_BLOB(credential->credData);
        return false;
    }
    const uint8_t *curCredData = parcel.ReadUnpadBuffer(credDataSize);
    if (memcpy_s(credential->credData.data, credDataSize, curCredData, credDataSize) != EOK) {
        CM_FREE_BLOB(credential->credData);
        CM_LOG_E("copy credData failed");
        return false;
    }
    return true;
}

static bool ReadCredentialFromParcel(Parcel &parcel, Credential *credential)
{
    if (!parcel.ReadUint32(credential->isExist)) {
        CM_LOG_E("read isExist failed");
        return false;
    }
    
    if (!ReadCertInfoFromParcel(parcel, credential)) {
        CM_LOG_E("read credential failed");
        return false;
    }
    
    if (!parcel.ReadUint32(credential->certNum)) {
        CM_LOG_E("read certNum failed");
        return false;
    }
    if (!parcel.ReadUint32(credential->keyNum)) {
        CM_LOG_E("read keyNum failed");
        return false;
    }

    if (!ReadCredDataFromParcel(parcel, credential)) {
        CM_LOG_E("read credential failed");
        return false;
    }
    return true;
}

bool CredentialDetailListParcelInfo::ReadFromParcel(Parcel &parcel)
{
    credentialDetailList = static_cast<struct CredentialDetailList *>(CmMalloc(sizeof(CredentialDetailList)));
    if (credentialDetailList == nullptr) {
        CM_LOG_E("malloc credentialDetailList failed");
        return false;
    }
    credentialDetailList->credentialCount = 0;
    credentialDetailList->credential = nullptr;
    if (!parcel.ReadUint32(credentialDetailList->credentialCount)) {
        CM_LOG_E("read credentialCount failed");
        CM_FREE_PTR(credentialDetailList);
        return false;
    }
    if (credentialDetailList->credentialCount > MAX_COUNT_UKEY_CERTIFICATE) {
        CM_LOG_E("credentialCount is too big");
        CM_FREE_PTR(credentialDetailList);
        return false;
    }
    uint32_t buffSize = (credentialDetailList->credentialCount * sizeof(struct Credential));
    credentialDetailList->credential = static_cast<struct Credential *>(CmMalloc(buffSize));
    if (credentialDetailList->credential == nullptr) {
        CM_LOG_E("malloc file buffer failed");
        CM_FREE_PTR(credentialDetailList);
        return false;
    }
    (void)memset_s(credentialDetailList->credential, buffSize, 0, buffSize);
    for (uint32_t i = 0; i < credentialDetailList->credentialCount; ++i) {
        if (!ReadCredentialFromParcel(parcel, &credentialDetailList->credential[i])) {
            CM_LOG_E("read credential failed, the failed index is %u", i);
            return false;
        }
        uint32_t certPurpose = 0;
        if (!parcel.ReadUint32(certPurpose)) {
            CM_LOG_E("read certPurpose failed");
            return false;
        }
        credentialDetailList->credential[i].certPurpose = static_cast<enum CmCertificatePurpose>(certPurpose);
    }
    return true;
}

static bool WriteCredentialToParcel(Parcel &parcel, Credential *credential)
{
    if (!parcel.WriteUint32(credential->isExist)) {
        CM_LOG_E("write isExist failed");
        return false;
    }
    if (!parcel.WriteBuffer(credential->type, MAX_LEN_SUBJECT_NAME)) {
        CM_LOG_E("write type failed");
        return false;
    }
    if (!parcel.WriteBuffer(credential->alias, MAX_LEN_CERT_ALIAS)) {
        CM_LOG_E("write alias failed");
        return false;
    }
    if (!parcel.WriteBuffer(credential->keyUri, MAX_LEN_URI)) {
        CM_LOG_E("write keyUri failed");
        return false;
    }
    if (!parcel.WriteUint32(credential->certNum)) {
        CM_LOG_E("write certNum failed");
        return false;
    }
    if (!parcel.WriteUint32(credential->keyNum)) {
        CM_LOG_E("write keyNum failed");
        return false;
    }
    if (!parcel.WriteUint32(credential->credData.size)) {
        CM_LOG_E("write credData.size failed");
        return false;
    }
    if (!parcel.WriteBuffer(credential->credData.data, credential->credData.size)) {
        CM_LOG_E("write credData.data failed");
        return false;
    }
    return true;
}

static bool WriteCredentialDetailListToParcel(Parcel &parcel, const CredentialDetailList *credentialDetailList)
{
    for (uint32_t i = 0; i < credentialDetailList->credentialCount; ++i) {
        if (!WriteCredentialToParcel(parcel, &credentialDetailList->credential[i])) {
            CM_LOG_E("write credential failed, the failed index is %u", i);
            return false;
        }
        if (!parcel.WriteUint32(static_cast<uint32_t>(credentialDetailList->credential[i].certPurpose))) {
            CM_LOG_E("write certPurpose failed, the failed index is %u", i);
            return false;
        }
    }
    return true;
}

bool CredentialDetailListParcelInfo::Marshalling(Parcel &parcel) const
{
    CM_LOG_D("CredentialDetailListParcelInfo Marshalling start");
    if (!parcel.WriteUint32(credentialDetailList->credentialCount)) {
        CM_LOG_E("CredentialDetailListParcelInfo write credentialCount failed");
        return false;
    }
    if (!WriteCredentialDetailListToParcel(parcel, credentialDetailList)) {
        CM_LOG_E("CredentialDetailListParcelInfo write CredentialDetailList failed");
        return false;
    }
    return true;
}

CredentialDetailListParcelInfo *CredentialDetailListParcelInfo::Unmarshalling(Parcel &parcel)
{
    CM_LOG_D("CredentialDetailListParcelInfo Unmarshalling start");
    CredentialDetailListParcelInfo *info = new (std::nothrow) CredentialDetailListParcelInfo();
    if (info == nullptr) {
        CM_LOG_E("info is null");
        return nullptr;
    }
    if (!info->ReadFromParcel(parcel)) {
        CM_LOG_E("read from parcel failed");
        CmFreeUkeyCertList(info->credentialDetailList);
        delete info;
        return nullptr;
    }
    return info;
}

static int32_t TransPortAppCertInfo(const struct Credential *oriCredntial, struct Credential *destCredntial)
{
    if (memcpy_s(destCredntial->type, MAX_LEN_SUBJECT_NAME, oriCredntial->type, MAX_LEN_SUBJECT_NAME) != EOK) {
        CM_LOG_E("copy type failed");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }

    if (memcpy_s(destCredntial->keyUri, MAX_LEN_URI, oriCredntial->keyUri, MAX_LEN_URI) != EOK) {
        CM_LOG_E("copy keyUri failed");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }

    if (memcpy_s(destCredntial->alias, MAX_LEN_CERT_ALIAS, oriCredntial->alias, MAX_LEN_CERT_ALIAS) != EOK) {
        CM_LOG_E("copy alias failed");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }

    return CM_SUCCESS;
}

static int32_t TransPortCredential(const struct Credential *oriCredntial, struct Credential *destCredntial)
{
    destCredntial->isExist = oriCredntial->isExist;

    int32_t ret = TransPortAppCertInfo(oriCredntial, destCredntial);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get AppCert failed");
        return ret;
    }
    destCredntial->certNum = oriCredntial->certNum;
    destCredntial->keyNum = oriCredntial->keyNum;
    destCredntial->credData.data = static_cast<uint8_t*>(CmMalloc(oriCredntial->credData.size));
    if (destCredntial->credData.data == nullptr) {
        CM_LOG_E("malloc credData buffer failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    if (memcpy_s(destCredntial->credData.data, oriCredntial->credData.size,
        oriCredntial->credData.data, oriCredntial->credData.size) != EOK) {
        CM_FREE_BLOB(destCredntial->credData);
        CM_LOG_E("copy credData failed");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    destCredntial->credData.size = oriCredntial->credData.size;
    return CM_SUCCESS;
}

int32_t CredentialDetailListParcelInfo::TransPortUkeyCertList(CredentialDetailList *credentialDetailList)
{
    if (credentialDetailList == nullptr || this->credentialDetailList == nullptr ||
        this->credentialDetailList->credential == nullptr) {
        CM_LOG_E("TransPortUkeyCertList arguments invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    credentialDetailList->credentialCount = this->credentialDetailList->credentialCount;
    uint32_t buffSize = (credentialDetailList->credentialCount * sizeof(struct Credential));
    credentialDetailList->credential = static_cast<struct Credential *>(CmMalloc(buffSize));
    if (credentialDetailList->credential == nullptr) {
        CM_LOG_E("malloc credential buffer failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(credentialDetailList->credential, buffSize, 0, buffSize);
    int32_t res = CM_SUCCESS;
    for (uint32_t i = 0; i < this->credentialDetailList->credentialCount; ++i) {
        res = TransPortCredential(&this->credentialDetailList->credential[i], &credentialDetailList->credential[i]);
        if (res != CM_SUCCESS) {
            CM_LOG_E("TransPortCredential failed, the failed index is %u", i);
            return res;
        }
        credentialDetailList->credential[i].certPurpose = this->credentialDetailList->credential[i].certPurpose;
    }
    return CM_SUCCESS;
}
}

