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

#ifndef CM_IPC_SERIALIZATION_H
#define CM_IPC_SERIALIZATION_H

#include "cm_type_inner.h"

#define MAX_IPC_BUF_SIZE    0x10000   /* Maximun IPC message buffer size. */
#define MAX_IPC_RSV_SIZE    0x400     /* Reserve IPC message buffer size */
#define MAX_PROCESS_SIZE    (MAX_IPC_BUF_SIZE - MAX_IPC_RSV_SIZE)

#ifdef __cplusplus
extern "C" {
#endif
int32_t CopyUint32ToBuffer(uint32_t value, const struct CmBlob *destBlob, uint32_t *destOffset);

int32_t CopyBlobToBuffer(const struct CmBlob *blob, const struct CmBlob *destBlob, uint32_t *destOffset);

int32_t GetUint32FromBuffer(uint32_t *value, const struct CmBlob *srcBlob, uint32_t *srcOffset);

int32_t CmGetBlobFromBuffer(struct CmBlob *blob, const struct CmBlob *srcBlob, uint32_t *srcOffset);

int32_t CmCertificateListPack(struct CmBlob *inData, const struct CmContext *cmContext, const uint32_t store);

int32_t CmCertificateInfoPack(struct CmBlob *inData, const struct CmContext *cmContext, const struct CmBlob *certUri,
    const uint32_t store);

int32_t CmCertificateListUnpackFromService(const struct CmBlob *outData, bool needEncode,
    const struct CmContext *context, struct CertList *certificateList);

int32_t CmCertificateInfoUnpackFromService(const struct CmBlob *outData, const struct CmContext *context,
    struct CertInfo *certificateInfo, const struct CmBlob *certUri);

int32_t CmCertificateStatusPack(struct CmBlob *inData, const struct CmContext *cmContext, const struct CmBlob *certUri,
    const uint32_t store, const uint32_t status);

int32_t CmParamsToParamSet(struct CmParam *params, uint32_t cnt, struct CmParamSet **outParamSet);

#ifdef __cplusplus
}
#endif

#endif /* CM_IPC_SERIALIZATION_H */