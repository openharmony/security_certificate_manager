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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "securec.h"
#include "cert_manager.h"
#include "cert_manager_file.h"
#include "cert_manager_mem.h"
#include "cert_manager_type.h"
#include "cm_log.h"
#include "cm_type.h"
#include "cert_manager_file_operator.h"

#define MAX_LEN_URI          64

inline uint32_t CertManagerFileSize(const char *path, const char *fileName)
{
    return CmFileSize(path, fileName);
}

inline uint32_t CertManagerFileRead(const char *path, const char *fileName, uint32_t offset, uint8_t *buf, uint32_t len)
{
    return CmFileRead(path, fileName, offset, buf, len);
}

inline int32_t CertManagerFileWrite(const char *path, const char *fileName,
    uint32_t offset, const uint8_t *buf, uint32_t len)
{
    return CM_ERROR(CmFileWrite(path, fileName, offset, buf, len));
}

inline int32_t CertManagerFileRemove(const char *path, const char *fileName)
{
    return CM_ERROR(CmFileRemove(path, fileName));
}

static uint32_t GetNumberOfFiles(const char *path)
{
    void *dir = CmOpenDir(path);
    if (dir == NULL) {
        CM_LOG_W("can't open directory");
        return -1;
    }

    uint32_t count = 0;
    struct CmFileDirentInfo dire = {{0}};
    while (CmGetDirFile(dir, &dire) == CMR_OK) {
        count++;
    }
    (void)CmCloseDir(dir);
    return count;
}

static int32_t MallocFileNames(struct CmMutableBlob *fileNames, const char *path, struct CmMutableBlob **fNames,
    uint32_t *fileCount)
{
    struct CmMutableBlob *tmp = NULL;
    uint32_t fileNums = GetNumberOfFiles(path);
    if (fileNums < 0) {
        CM_LOG_E("Failed to obtain number of files from: path = %s", path);
        return -1;
    }

    *fileCount = (uint32_t)fileNums;

    tmp = (struct CmMutableBlob *)CMMalloc(sizeof(struct CmMutableBlob) * fileNums);
    if (tmp == NULL) {
        CM_LOG_E("Failed to allocate memory for file names");
        return -1;
    }

    for (uint32_t i = 0; i < fileNums; i++) {
        tmp[i].data = NULL;
        tmp[i].size = 0;
    }
    fileNames->data = (uint8_t *)tmp;
    fileNames->size = (uint32_t)fileNums;
    *fNames = tmp;

    return 0;
}

static void FreeFileNames(struct CmMutableBlob *fNames, uint32_t endIndex)
{
    uint32_t i;
    for (i = 0; i < endIndex; i++) {
        if (fNames[i].data != NULL) {
            if (memset_s(fNames[i].data, fNames[i].size, 0, fNames[i].size) != EOK) {
                return;
            }
            CMFree(fNames[i].data);
            fNames[i].data = NULL;
            fNames[i].size = 0;
        }
    }
    CMFree(fNames);
    fNames = NULL;
}

int32_t CertManagerGetFilenames(struct CmMutableBlob *fileNames, const char *path, struct CmBlob *uri)
{
    uint32_t i = 0, fileCount = 0;
    struct CmMutableBlob *fNames = NULL;

    if ((fileNames == NULL) || (path == NULL)) {
        CM_LOG_E("Bad parameters: path = %s", path);
        return -1;
    }

    if (MallocFileNames(fileNames, path, &fNames, &fileCount) != 0) {
        CM_LOG_E("Failed to malloc memory for files name");
        return -1;
    }

    void *d = CmOpenDir(path);
    if (d == NULL) {
        CM_LOG_E("Failed to open directory: %s", path);
        goto err;
    }

    struct CmFileDirentInfo dire = {0};
    while (CmGetDirFile(d, &dire) == CMR_OK) {
        fNames[i].size = strlen(dire.fileName) + 1; /* include '\0' at end */
        fNames[i].data = (uint8_t *) strdup(dire.fileName);

        uri[i].size = MAX_LEN_URI;
        uri[i].data = (uint8_t *)CMMalloc(MAX_LEN_URI);
        if (uri[i].data == NULL) {
            goto err;
        }
        if (memset_s(uri[i].data, MAX_LEN_URI, 0, MAX_LEN_URI) != EOK) {
            goto err;
        }

        uri[i].size = fNames[i].size;
        if (memcpy_s(uri[i].data, MAX_LEN_URI, fNames[i].data, fNames[i].size) != EOK) {
            goto err;
        }
        i++;
    }

    if (i != fileCount) {
        goto err;
    }

    (void) CmCloseDir(d);

    return fileCount;
err:
    (void) CmCloseDir(d);
    FreeFileNames(fNames, i);
    CmFreeFileNameUri(uri, MAX_COUNT_CERTIFICATE);

    return -1;
}