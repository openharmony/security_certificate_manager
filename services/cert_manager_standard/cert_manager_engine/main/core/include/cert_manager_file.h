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

#ifndef CERT_MANAGER_FILE_H
#define CERT_MANAGER_FILE_H

#include "cert_manager_file.h"
#include "cm_type.h"

#ifdef _cplusplus
extern "C"
#endif

int32_t CertManagerGetFilenames(struct CmMutableBlob *fileNames, const char *path);

uint32_t CertManagerFileSize(const char *path, const char *fileName);

uint32_t CertManagerFileRead(const char *path, const char *fileName, uint32_t offset, uint8_t *buf, uint32_t len);

int32_t CertManagerFileWrite(const char *path, const char *fileName, uint32_t offset,
    const uint8_t *buf, uint32_t len);

int32_t CertManagerFileRemove(const char *path, const char *fileName);

int32_t GetNumberOfDirs(const char *userIdPath);

int32_t GetCertCount(const char *path);

void FreeFileNames(struct CmMutableBlob *fNames, uint32_t fileCount);

#ifdef __cplusplus
}
#endif
#endif