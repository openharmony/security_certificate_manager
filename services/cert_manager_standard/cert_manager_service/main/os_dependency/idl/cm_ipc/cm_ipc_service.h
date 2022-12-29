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

void CmIpcServiceGetCertificateList(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceGetCertificateInfo(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceSetCertStatus(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

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

void CmIpcServiceGrantAppCertificate(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceGetAuthorizedAppList(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceIsAuthorizedApp(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceRemoveGrantedApp(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceInit(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceUpdate(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceFinish(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceAbort(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceGetUserCertList(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceGetUserCertInfo(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceSetUserCertStatus(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceInstallUserCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceUninstallUserCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

void CmIpcServiceUninstallAllUserCert(const struct CmBlob *paramSetBlob, struct CmBlob *outData,
    const struct CmContext *context);

#ifdef __cplusplus
}
#endif

#endif
