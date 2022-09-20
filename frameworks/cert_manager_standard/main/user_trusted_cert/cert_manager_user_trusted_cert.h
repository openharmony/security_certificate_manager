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
#ifndef CERT_MANAGER_H
#define CERT_MANAGER_H

#include "cert_manager_type.h"
#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t BuildUserUri(char **userUri, const char *aliasName, uint32_t type, const struct CmContext *ipcInfo);

int32_t CmGetCertFilePath(const struct CmContext *context, uint32_t store, struct CmMutableBlob *pathBlob);

int32_t CmRemoveUserCert(struct CmMutableBlob *pathBlob, const struct CmBlob *certUri);

int32_t CmFreeCertPaths(struct CmMutableBlob *certPaths);

int32_t CmGetCertPathList(const struct CmContext *context, uint32_t store, struct CmMutableBlob *certPathList);

int32_t CmRemoveAllUserCert(uint32_t store, const struct CmMutableBlob *certPathList);

int32_t CmServiceGetCertList(const struct CmContext *context, uint32_t store, struct CmMutableBlob *certFileList);

int32_t CmGetCertListInfo(const struct CmContext *context, uint32_t store,
    const struct CmMutableBlob *certFileList, struct CertBlob *certBlob, uint32_t *status)

int32_t CmGetServiceCertInfo(const struct CmContext *context, const struct CmBlob *certUri,
    uint32_t store, struct CmBlob *certificateData, uint32_t *status);

int32_t CmDirRemove(const char *path);

int32_t CmGetSubDir(DIR *dirp, struct CmFileDirentInfo *direntInfo);

int32_t CmSetStatusEnable(const struct CmContext *ipcInfo, struct CmMutableBlob *pathBlob,
    const struct CmBlob *certUri, uint32_t store);
#ifdef __cplusplus
}
#endif

#endif