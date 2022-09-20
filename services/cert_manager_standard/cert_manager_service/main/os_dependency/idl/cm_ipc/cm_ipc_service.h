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

#ifndef CM_IPC_SERVICE_H
#define CM_IPC_SERVICE_H

#include "cm_type_inner.h"

#ifdef __cplusplus
extern "C" {
#endif

struct CertParam {
    uint8_t *aliasBuff;
    uint8_t *passWdBuff;
};

void CmIpcServiceGetCertificateList(const struct CmBlob *srcData, const struct CmContext *context);

void CmIpcServiceGetCertificateInfo(const struct CmBlob *srcData, const struct CmContext *context);

void CmIpcServiceSetCertStatus(const struct CmBlob *srcData, const struct CmContext *context);

void CmIpcServiceInstallAppCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceUninstallAppCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceUninstallAllAppCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceGetAppCertList(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceGetAppCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

#ifdef __cplusplus
}
#endif

#endif
