/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CERT_MANAGER_QUERY_H
#define CERT_MANAGER_QUERY_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CmGetCertPathList(const struct CmContext *context, uint32_t store, struct CmMutableBlob *pathList);

int32_t CmGetSysCertPathList(const struct CmContext *context, struct CmMutableBlob *pathList);

int32_t CreateCertFileList(const struct CmMutableBlob *pathList, struct CmMutableBlob *certFileList);

int32_t CmGetCertAlias(const uint32_t store, const char *uri, const struct CmBlob *certData,
    struct CmBlob *alias);

int32_t CmGetCertListInfo(const struct CmContext *context, uint32_t store,
    const struct CmMutableBlob *certFileList, struct CertBlob *certBlob, uint32_t *status);

void CmFreeCertBlob(struct CertBlob *certBlob);

int32_t CmGetMatchedCertIndex(const struct CmMutableBlob *certFileList, const struct CmBlob *certUri);

void CmFreeCertFiles(struct CertFileInfo *cFileList, uint32_t certCount);

void CmFreePathList(struct CmMutableBlob *pList, uint32_t pathCount);
#ifdef __cplusplus
}
#endif

#endif /* CERT_MANAGER_QUERY_H */
