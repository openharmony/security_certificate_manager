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

#include "cert_manager_file_operator.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include "securec.h"

#include "cert_manager_mem.h"
#include "cm_log.h"

static int32_t GetFileName(const char *path, const char *fileName, char *fullFileName, uint32_t fullFileNameLen)
{
    if (path != NULL) {
        if (strncpy_s(fullFileName, fullFileNameLen, path, strlen(path)) != EOK) {
            return CMR_ERROR_INVALID_OPERATION;
        }

        if (path[strlen(path) - 1] != '/') {
            if (strncat_s(fullFileName, fullFileNameLen, "/", strlen("/")) != EOK) {
                return CMR_ERROR_INVALID_OPERATION;
            }
        }

        if (strncat_s(fullFileName, fullFileNameLen, fileName, strlen(fileName)) != EOK) {
            return CMR_ERROR_INVALID_OPERATION;
        }
    } else {
        if (strncpy_s(fullFileName, fullFileNameLen, fileName, strlen(fileName)) != EOK) {
            return CMR_ERROR_INVALID_OPERATION;
        }
    }
    return CMR_OK;
}

static int32_t GetFullFileName(const char *path, const char *fileName, char **fullFileName)
{
    uint32_t nameLen = CM_MAX_FILE_NAME_LEN;
    char *tmpFileName = (char *)CMMalloc(nameLen);
    if (tmpFileName == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(tmpFileName, nameLen, 0, nameLen);

    int32_t ret = GetFileName(path, fileName, tmpFileName, nameLen);
    if (ret != CMR_OK) {
        CM_LOG_E("get full fileName failed");
        CM_FREE_PTR(tmpFileName);
        return ret;
    }
    *fullFileName = tmpFileName;

    return CMR_OK;
}

static int32_t IsFileExist(const char *fileName)
{
    if (access(fileName, F_OK) != 0) {
        return CMR_ERROR_NOT_EXIST;
    }

    return CMR_OK;
}

int32_t CmIsDirExist(const char *path)
{
    if (path == NULL) {
        return CMR_ERROR_NULL_POINTER;
    }
    return IsFileExist(path);
}

static uint32_t FileRead(const char *fileName, uint32_t offset, uint8_t *buf, uint32_t len)
{
    (void)offset;
    if (IsFileExist(fileName) != CMR_OK) {
        return 0;
    }

    char filePath[PATH_MAX + 1] = {0};
    (void)realpath(fileName, filePath);
    if (strstr(filePath, "../") != NULL) {
        CM_LOG_E("invalid filePath");
        return 0;
    }

    FILE *fp = fopen(filePath, "rb");
    if (fp == NULL) {
        CM_LOG_E("failed to open file");
        return 0;
    }

    uint32_t size = fread(buf, 1, len, fp);
    if (fclose(fp) < 0) {
        CM_LOG_E("failed to close file");
        return 0;
    }

    return size;
}

static uint32_t FileSize(const char *fileName)
{
    if (IsFileExist(fileName) != CMR_OK) {
        CM_LOG_E("file IsFileExist fail.");
        return 0;
    }

    struct stat fileStat;
    (void)memset_s(&fileStat, sizeof(fileStat), 0, sizeof(fileStat));

    if (stat(fileName, &fileStat) != 0) {
        CM_LOG_E("file stat fail.");
        return 0;
    }

    return (uint32_t)fileStat.st_size;
}

static int32_t FileWrite(const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len)
{
    (void)offset;
    char filePath[PATH_MAX + 1] = {0};
    if (memcpy_s(filePath, sizeof(filePath) - 1, fileName, strlen(fileName)) != EOK) {
        return CMR_ERROR_INVALID_OPERATION;
    }
    (void)realpath(fileName, filePath);
    if (strstr(filePath, "../") != NULL) {
        CM_LOG_E("invalid filePath");
        return CMR_ERROR_NOT_EXIST;
    }

    int32_t fd = open(filePath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        CM_LOG_E("open file failed, errno = 0x%x", errno);
        return CMR_ERROR_OPEN_FILE_FAIL;
    }

    int32_t size = write(fd, buf, len);
    if (size < 0) {
        CM_LOG_E("write file failed, errno = 0x%x", errno);
        close(fd);
        return CMR_ERROR_WRITE_FILE_FAIL;
    }
    if (fsync(fd) < 0) {
        CM_LOG_E("sync file failed");
        close(fd);
        return CMR_ERROR_WRITE_FILE_FAIL;
    }
    close(fd);
    return CMR_OK;
}

static int32_t FileRemove(const char *fileName)
{
    int32_t ret = IsFileExist(fileName);
    if (ret != CMR_OK) {
        return CMR_OK; /* if file not exist, return ok */
    }

    struct stat tmp;
    if (stat(fileName, &tmp) != 0) {
        return CMR_ERROR_INVALID_OPERATION;
    }

    if (S_ISDIR(tmp.st_mode)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if ((unlink(fileName) != 0) && (errno != ENOENT)) {
        CM_LOG_E("failed to remove file: errno = 0x%x", errno);
        return CMR_ERROR_REMOVE_FILE_FAIL;
    }

    return CMR_OK;
}

int32_t CmFileRemove(const char *path, const char *fileName)
{
    if (fileName == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    if (ret != CMR_OK) {
        return ret;
    }

    ret = FileRemove(fullFileName);
    CM_FREE_PTR(fullFileName);
    return ret;
}

int32_t CmMakeDir(const char *path)
{
    if ((access(path, F_OK)) != -1) {
        CM_LOG_I("path exist");
        return CMR_OK;
    }

    if (mkdir(path, S_IRWXU) == 0) {
        return CMR_OK;
    } else {
        if (errno == EEXIST  || errno == EAGAIN) {
            return CMR_ERROR_ALREADY_EXISTS;
        } else {
            return CMR_ERROR_MAKE_DIR_FAIL;
        }
    }
}

void *CmOpenDir(const char *path)
{
    return (void *)opendir(path);
}

int32_t CmCloseDir(void *dirp)
{
    return closedir((DIR *)dirp);
}

int32_t CmGetDirFile(void *dirp, struct CmFileDirentInfo *direntInfo)
{
    DIR *dir = (DIR *)dirp;
    struct dirent *dire = readdir(dir);

    while (dire != NULL) {
        if (dire->d_type != DT_REG) { /* only care about files. */
            dire = readdir(dir);
            continue;
        }

        uint32_t len = strlen(dire->d_name);
        if (memcpy_s(direntInfo->fileName, sizeof(direntInfo->fileName) - 1, dire->d_name, len) != EOK) {
            return CMR_ERROR_INVALID_OPERATION;
        }
        direntInfo->fileName[len] = '\0';
        return CMR_OK;
    }

    return CMR_ERROR_NOT_EXIST;
}

uint32_t CmFileRead(const char *path, const char *fileName, uint32_t offset, uint8_t *buf, uint32_t len)
{
    if ((fileName == NULL) || (buf == NULL) || (len == 0)) {
        return 0;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    if (ret != CMR_OK) {
        return 0;
    }

    uint32_t size = FileRead(fullFileName, offset, buf, len);
    CM_FREE_PTR(fullFileName);
    return size;
}

int32_t CmFileWrite(const char *path, const char *fileName, uint32_t offset, const uint8_t *buf, uint32_t len)
{
    if ((fileName == NULL) || (buf == NULL) || (len == 0)) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    if (ret != CMR_OK) {
        return ret;
    }

    ret = FileWrite(fullFileName, offset, buf, len);
    CM_FREE_PTR(fullFileName);
    return ret;
}

uint32_t CmFileSize(const char *path, const char *fileName)
{
    if (fileName == NULL) {
        CM_LOG_E("fileName is NULL");
        return 0;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    if (ret != CMR_OK) {
        CM_LOG_E("GetFullFileName failed");
        return 0;
    }

    uint32_t size = FileSize(fullFileName);
    CM_FREE_PTR(fullFileName);
    return size;
}

static int32_t CmUidLayerGetFileNames(const char *filePath, struct CmBlob *fileNames,
    const uint32_t arraySize, uint32_t count)
{
    if (count >= arraySize) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    uint32_t filePathLen = strlen(filePath);
    if (filePathLen >= CM_MAX_FILE_NAME_LEN) {
        CM_LOG_E("CmUidLayerGetFileNames filePathLen:%u", filePathLen);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    fileNames[count].data = (uint8_t *)CMMalloc(filePathLen + 1);
    if (fileNames[count].data == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(fileNames[count].data, filePathLen + 1, 0, filePathLen + 1);
    if (memcpy_s(fileNames[count].data, CM_MAX_FILE_NAME_LEN, filePath, filePathLen) != EOK) {
        /* fileNames memory free in top layer function */
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    fileNames[count].size = filePathLen + 1; /* include '\0' at end */
    return CM_SUCCESS;
}

int32_t CmUidLayerGetFileCountAndNames(const char *path, struct CmBlob *fileNames,
    const uint32_t arraySize, uint32_t *fileCount)
{
    /* do nothing when dir is not exist */
    if (CmIsDirExist(path) != CMR_OK) {
        CM_LOG_I("Uid layer dir is not exist");
        return CM_SUCCESS;
    }
    DIR *dir = opendir(path);
    if (dir == NULL) {
        CM_LOG_E("open uid layer dir failed");
        return CMR_ERROR_OPEN_FILE_FAIL;
    }

    int32_t ret = CM_SUCCESS;
    uint32_t count = *fileCount;
    struct dirent *dire = readdir(dir);
    while (dire != NULL) {
        char uidPath[CM_MAX_FILE_NAME_LEN] = {0};
        if (strncpy_s(uidPath, sizeof(uidPath), path, strlen(path)) != EOK) {
            ret = CMR_ERROR_INVALID_OPERATION;
            break;
        }

        if (uidPath[strlen(uidPath) - 1] != '/') {
            if (strncat_s(uidPath, sizeof(uidPath), "/", strlen("/")) != EOK) {
                ret = CMR_ERROR_INVALID_OPERATION;
                break;
            }
        }

        if (strncat_s(uidPath, sizeof(uidPath), dire->d_name, strlen(dire->d_name)) != EOK) {
            ret = CMR_ERROR_INVALID_OPERATION;
            break;
        }

        if ((dire->d_type == DT_REG) && (strcmp("..", dire->d_name) != 0) && (strcmp(".", dire->d_name) != 0)) {
            ret = CmUidLayerGetFileNames(uidPath, fileNames, arraySize, count);
            if (ret != CM_SUCCESS) {
                break;
            }
            count++;
        }
        dire = readdir(dir);
    }
    *fileCount = count;
    closedir(dir);
    return ret;
}

int32_t CmUserIdLayerGetFileCountAndNames(const char *path, struct CmBlob *fileNames,
    const uint32_t arraySize, uint32_t *fileCount)
{
    char userIdPath[CM_MAX_FILE_NAME_LEN] = { 0 };
    /* do nothing when dir is not exist */
    if (CmIsDirExist(path) != CMR_OK) {
        CM_LOG_I("UserId layer dir is not exist");
        return CM_SUCCESS;
    }
    DIR *dir = opendir(path);
    if (dir  == NULL) {
        CM_LOG_E("open userId layer dir failed");
        return CMR_ERROR_OPEN_FILE_FAIL;
    }
    struct dirent *dire = readdir(dir);
    while (dire != NULL) {
        (void)memset_s(userIdPath, CM_MAX_FILE_NAME_LEN, 0, CM_MAX_FILE_NAME_LEN);
        if (strncpy_s(userIdPath, sizeof(userIdPath), path, strlen(path)) != EOK) {
            closedir(dir);
            return CMR_ERROR_INVALID_OPERATION;
        }

        if (userIdPath[strlen(userIdPath) - 1] != '/') {
            if (strncat_s(userIdPath, sizeof(userIdPath), "/", strlen("/")) != EOK) {
                closedir(dir);
                return CMR_ERROR_INVALID_OPERATION;
            }
        }

        if (strncat_s(userIdPath, sizeof(userIdPath), dire->d_name, strlen(dire->d_name)) != EOK) {
            closedir(dir);
            return CMR_ERROR_INVALID_OPERATION;
        }

        if ((dire->d_type == DT_DIR) && (strcmp("..", dire->d_name) != 0) && (strcmp(".", dire->d_name) != 0)) {
            if (CmUidLayerGetFileCountAndNames(userIdPath, fileNames, arraySize, fileCount) != CM_SUCCESS) {
                CM_LOG_E("CmUidLayerGetFileCountAndNames faild");
                closedir(dir);
                return CM_FAILURE;
            }
        } else if (dire->d_type != DT_DIR) {
            (void)remove(userIdPath);
        }
        dire = readdir(dir);
    }
    closedir(dir);
    return CM_SUCCESS;
}

int32_t CmIsFileExist(const char *path, const char *fileName)
{
    if (fileName == NULL) {
        CM_LOG_E("fileName is NULL");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    char *fullFileName = NULL;
    int32_t ret = GetFullFileName(path, fileName, &fullFileName);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("GetFullFileName failed");
        return ret;
    }

    ret = IsFileExist(fullFileName);
    CM_FREE_PTR(fullFileName);
    return ret;
}

int32_t CmGetSubDir(void *dirp, struct CmFileDirentInfo *direntInfo)
{
    DIR *dir = (DIR *)dirp;
    struct dirent *dire = readdir(dir);

    while (dire != NULL) {
        if ((dire->d_type != DT_DIR) || (strcmp(dire->d_name, ".") == 0) ||
            (strcmp(dire->d_name, "..") == 0)) {
            dire = readdir(dir);
            continue;
        }

        uint32_t dirLen = strlen(dire->d_name);
        if (memcpy_s(direntInfo->fileName, sizeof(direntInfo->fileName) - 1, dire->d_name, dirLen) != EOK) {
            return CMR_ERROR_INVALID_OPERATION;
        }
        direntInfo->fileName[dirLen] = '\0';
        return CMR_OK;
    }

    return CMR_ERROR_NOT_EXIST;
}

static int32_t DirRemove(const char *path)
{
    if (access(path, F_OK) != 0) {
        return CMR_ERROR_NOT_EXIST;
    }

    struct stat tmp;
    if (stat(path, &tmp) != 0) {
        return CMR_ERROR_INVALID_OPERATION;
    }

    if (S_ISDIR(tmp.st_mode)) {
        uint32_t i = 0;
        struct dirent *dire = NULL;
        DIR *dirp = opendir(path);
        if (dirp == NULL) {
            CM_LOG_E("open dir failed");
            return CMR_ERROR_OPEN_FILE_FAIL;
        }
        while ((dire = readdir(dirp)) != NULL) {
            if ((strcmp(dire->d_name, ".") == 0) || (strcmp(dire->d_name, "..") == 0)) {
                continue;
            }
            i++;
        }
        closedir(dirp);

        if (i != 0) {
            CM_LOG_E("Dir is not empty");
            return CMR_ERROR_INVALID_ARGUMENT;
        }
        rmdir(path);
        return CMR_OK;
    }
    return CMR_ERROR_INVALID_ARGUMENT;
}

int32_t CmDirRemove(const char *path)
{
    if (path == NULL) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    return DirRemove(path);
}
