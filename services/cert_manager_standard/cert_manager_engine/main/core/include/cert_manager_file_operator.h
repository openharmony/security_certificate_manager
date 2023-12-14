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

#ifndef CM_FILE_OPERATOR_H
#define CM_FILE_OPERATOR_H

#include <sys/stat.h>
#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CM_MAX_FILE_NAME_LEN   512
#define CM_MAX_DIRENT_FILE_LEN 256

struct CmFileDirentInfo {
    char fileName[CM_MAX_DIRENT_FILE_LEN]; /* point to dirent->d_name */
};

uint32_t CmFileRead(const char *path, const char *fileName, uint32_t offset, uint8_t *buf, uint32_t len);

int32_t CmFileWrite(const char *path, const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len);

int32_t CmUserBackupFileWrite(
    const char *path, const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len);

int32_t CmFileRemove(const char *path, const char *fileName);

uint32_t CmFileSize(const char *path, const char *fileName);

int32_t CmIsFileExist(const char *path, const char *fileName);

int32_t CmMakeDir(const char *path);

/**
 * @brief Creating a directory related to certificate backup (directory permissions can be specified)
 *
 * @param[in] path Directory absolute path
 * @param[in] mode When not NULL, the permissions specified by *mode are used when creating directory
 * @return int32_t Create result
 * @retval CMR_OK Creating a directory succeeded
 * @retval CMR_ERROR_ALREADY_EXISTS Directory already exists
 * @retval CMR_ERROR_MAKE_DIR_FAIL Failed to create a directory
 */
int32_t CmUserBakupMakeDir(const char *path, const mode_t *mode);

void *CmOpenDir(const char *path);

int32_t CmCloseDir(void *dirp);

int32_t CmGetDirFile(void *dirp, struct CmFileDirentInfo *direntInfo);

int32_t CmIsDirExist(const char *path);

int32_t CmUserIdLayerGetFileCountAndNames(const char *path, struct CmBlob *fileNames,
    const uint32_t arraySize, uint32_t *fileCount);

int32_t CmUidLayerGetFileCountAndNames(const char *path, struct CmBlob *fileNames,
    const uint32_t arraySize, uint32_t *fileCount);

int32_t CmGetSubDir(void *dirp, struct CmFileDirentInfo *direntInfo);

int32_t CmDirRemove(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* CM_FILE_OPERATOR_H */

