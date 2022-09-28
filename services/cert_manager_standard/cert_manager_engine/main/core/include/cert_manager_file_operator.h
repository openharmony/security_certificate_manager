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

#include "cert_manager_type.h"

#define CM_PROCESS_INFO_LEN    128
#define CM_MAX_FILE_NAME_LEN   512
#define CM_MAX_DIRENT_FILE_LEN 256

#define CM_KEY_STORE_KEY_PATH        "key"
#define CM_KEY_STORE_ROOT_KEY_PATH   "info"
#define CM_KEY_STORE_CERTCHAIN_PATH  "certchain"

#ifdef _STORAGE_LITE_
    #define CM_KEY_STORE_PATH                CM_CONFIG_KEY_STORE_PATH
#else
    #ifdef L2_STANDARD
        #define CM_KEY_STORE_PATH            "/data/data/maindata"
        #define CM_KEY_STORE_BAK_PATH        "/data/data/bakdata"
    #else
        #define CM_KEY_STORE_PATH            "/storage/maindata"
        #define CM_KEY_STORE_BAK_PATH        "/storage/bakdata"
    #endif
#endif

struct CmFileDirentInfo {
    char fileName[CM_MAX_DIRENT_FILE_LEN]; /* point to dirent->d_name */
};

enum CmStoragePathType {
    CM_STORAGE_MAIN_PATH,
    CM_STORAGE_BACKUP_PATH,
};

#ifdef __cplusplus
extern "C" {
#endif

uint32_t CmFileRead(const char *path, const char *fileName, uint32_t offset, uint8_t *buf, uint32_t len);

int32_t CmFileWrite(const char *path, const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len);

int32_t CmFileRemove(const char *path, const char *fileName);

uint32_t CmFileSize(const char *path, const char *fileName);

int32_t CmIsFileExist(const char *path, const char *fileName);

int32_t CmMakeDir(const char *path);

void *CmOpenDir(const char *path);

int32_t CmCloseDir(void *dirp);

int32_t CmGetDirFile(void *dirp, struct CmFileDirentInfo *direntInfo);

int32_t CmIsDirExist(const char *path);

int32_t CmUserIdLayerGetFileCountAndNames(const char *path, struct CmBlob *fileNames,
    const uint32_t arraySize, uint32_t *fileCount);

int32_t CmGetSubDir(void *dirp, struct CmFileDirentInfo *direntInfo);

int32_t CmDirRemove(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* CM_FILE_OPERATOR_H */
