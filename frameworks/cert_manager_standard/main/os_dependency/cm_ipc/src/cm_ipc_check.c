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

#include "cm_ipc_check.h"
#include "cm_ipc_serialization.h"

#include "cm_log.h"

int32_t CheckCertificateListPara(const struct CmBlob *inBlob, const struct CmBlob *outBlob,
    const struct CmContext *cmContext, const uint32_t store, const struct CertList *certificateList)
{
    if ((inBlob == NULL) || (outBlob == NULL) || (cmContext == NULL) || (certificateList == NULL)) {
        CM_LOG_E("CheckCertificateListPara arg error");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t CheckCertificateInfoPara(const struct CmBlob *inBlob, const struct CmBlob *outBlob,
    const struct CmContext *cmContext, const uint32_t store, const struct CertInfo *certificateInfo)
{
    if ((inBlob == NULL) || (outBlob == NULL) || (cmContext == NULL) || (certificateInfo == NULL)) {
        CM_LOG_E("CmCertificateInfoPack arg error");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}