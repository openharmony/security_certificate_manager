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

#include "cert_manager_file.h"

#include "securec.h"

#include "cert_manager_file_operator.h"
#include "cert_manager_mem.h"
#include "cm_log.h"
#include "cm_type.h"

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
    return CmFileWrite(path, fileName, offset, buf, len);
}

inline int32_t CertManagerFileRemove(const char *path, const char *fileName)
{
    return CmFileRemove(path, fileName);
}

static int32_t GetNumberOfFiles(const char *path)
{
    void *dir = CmOpenDir(path);
    if (dir == NULL) {
        CM_LOG_W("can't open directory");
        return -1;
    }

    int32_t count = 0;
    struct CmFileDirentInfo dire = {{0}};
    while (CmGetDirFile(dir, &dire) == CMR_OK) {
        count++;
    }
    (void)CmCloseDir(dir);
    return count;
}

void FreeFileNames(struct CmMutableBlob *fileNames)
{
    if (fileNames == NULL) {
        return ;
    }

    if (fileNames->data == NULL) {
        fileNames->size = 0;
        return;
    }

    struct CmMutableBlob *fNames = (struct CmMutableBlob *)fileNames->data;
    for (uint32_t i = 0; i < fileNames->size; i++) {
        fNames[i].size = 0;
        CM_FREE_PTR(fNames[i].data);
    }
    CMFree(fNames);
    fileNames->size = 0;
}

static int32_t MallocFileNames(struct CmMutableBlob *fileNames, const char *path, uint32_t *fileCount)
{
    int32_t fileNums = GetNumberOfFiles(path);
    if (fileNums == 0) {
        CM_LOG_I("dir is empty");
        return CM_SUCCESS;
    }

    if (fileNums < 0) {
        CM_LOG_E("Failed to obtain number of files from: path = %s", path);
        return CM_FAILURE;
    }

    if (fileNums > MAX_COUNT_CERTIFICATE) {
        CM_LOG_E("cert count %d beyond MAX", fileNums);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t bufSize = sizeof(struct CmMutableBlob) * fileNums;
    struct CmMutableBlob *fNames = (struct CmMutableBlob *)CMMalloc(bufSize);
    if (fNames == NULL) {
        CM_LOG_E("Failed to allocate memory for file names");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(fNames, bufSize, 0, bufSize);

    fileNames->data = (uint8_t *)fNames;
    fileNames->size = (uint32_t)fileNums;
    *fileCount = (uint32_t)fileNums;

    return CM_SUCCESS;
}

static int32_t GetFileNames(const char *path, struct CmMutableBlob *fNames, uint32_t fileCount)
{
    void *d = CmOpenDir(path);
    if (d == NULL) {
        CM_LOG_E("Failed to open directory: %s", path);
        return CM_FAILURE;
    }

    int32_t ret = CM_SUCCESS;
    uint32_t i = 0;
    struct CmFileDirentInfo dire = {0};
    while (CmGetDirFile(d, &dire) == CMR_OK) {
        /* get fileCount files first, verify in follow-up process, no need return err code */
        if (i >= fileCount) {
            CM_LOG_I("only get %u certfiles", fileCount);
            break;
        }

        uint32_t nameSize = strlen(dire.fileName) + 1; /* include '\0' at end */
        fNames[i].data = (uint8_t *)CMMalloc(nameSize);
        if (fNames[i].data == NULL) {
            CM_LOG_E("malloc file name data failed");
            ret = CMR_ERROR_MALLOC_FAIL;
            break;
        }

        fNames[i].size = nameSize;
        (void)memset_s(fNames[i].data, nameSize, 0, nameSize);
        if (sprintf_s((char *)fNames[i].data, nameSize, "%s", dire.fileName) < 0) {
            CM_LOG_E("copy file name failed");
            ret = CM_FAILURE;
            break;
        }

        i++;
    }

    (void) CmCloseDir(d);
    if (i != fileCount) {
        CM_LOG_E("get certfiles no enough");
        ret = CM_FAILURE;
    }

    return ret;
}

int32_t CertManagerGetFilenames(struct CmMutableBlob *fileNames, const char *path)
{
    if ((fileNames == NULL) || (path == NULL)) {
        CM_LOG_E("invalid parameters");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret;
    uint32_t fileCount = 0;
    do {
        ret = MallocFileNames(fileNames, path, &fileCount);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to malloc memory for files name");
            break;
        }

        struct CmMutableBlob *fNames = (struct CmMutableBlob *)fileNames->data;
        ret = GetFileNames(path, fNames, fileCount);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get file name failed");
            break;
        }
    } while (0);

    if (ret != CM_SUCCESS) {
        FreeFileNames(fileNames);
    }
    return ret;
}

uint32_t GetNumberOfDirs(const char *userIdPath)
{
    void *dir = CmOpenDir(userIdPath);
    if (dir == NULL) {
        CM_LOG_W("can't open directory");
        return CM_FAILURE;
    }

    uint32_t fileCount = 0;
    struct CmFileDirentInfo dire = {{0}};
    while (CmGetSubDir(dir, &dire) == CMR_OK) {
        fileCount++;
    }
    (void)CmCloseDir(dir);
    return fileCount;
}

int32_t GetCertCount(const char *path)
{
    return GetNumberOfFiles(path);
}