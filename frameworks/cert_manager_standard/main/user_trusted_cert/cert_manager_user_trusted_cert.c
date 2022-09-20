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

#include "stdio.h"
#include "stdbool.h"
#include "stdint.h"
#include "cert_manager_user_trusted_cert.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CmFreeCertPaths(struct CmMutableBlob *certPaths)
{
    uint32_t i;
    int32_t ret = 0;
    struct CmMutableBlob *cPaths;

    if (certPaths == NULL) {
        CM_LOG_E("Failed to free memory for certificate paths");
        return -1;
    }
    cPaths = (struct CmMutableBlob *)certPaths->data;

    for (i = 0; i < certPaths->size; i++) {
        if (cPaths[i].data == NULL) {
            CM_LOG_E("Failed to free memory for certificate name: %d", i);
            ret = -1;
        } else {
            if (memset_s(cPaths[i].data, MAX_PATH_LEN, 0, cPaths[i].size) != EOK) {
                return CMR_ERROR;
            }
            cPaths[i].size = 0;
            CMFree(cPaths[i].data);
        }
    }
    CMFree(cPaths);
    certPaths->size = 0;

    return ret;
}

int32_t CmGetCertFilePath(const struct CmContext *context, uint32_t store, struct CmMutableBlob *pathBlob)
{
    char pathPtr[MAX_PATH_LEN] = {0};

    if ((pathBlob == NULL) || (pathBlob->data == NULL)) {
        CM_LOG_E("Null pointer failure");
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = ConstructUidPath(context, store, pathPtr, MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get file path faild");
        return CM_FAILURE;
    }

    char *path = (char *)pathBlob->data;
    if (sprintf_s(path, MAX_PATH_LEN, "%s", pathPtr) < 0) {
            return CM_FAILURE;
    }
    pathBlob->size = strlen(path) + 1;
    if (CmMakeDir(path) == CMR_ERROR_MAKE_DIR_FAIL) {
        CM_LOG_E("Failed to create folder %s", path);
        return CMR_FILE_WRITE_ERROR;
    }
    return CM_SUCCESS;
}

static int32_t CmGetUserIdPath(const struct CmContext *context, uint32_t store, struct CmMutableBlob *pathBlob)
{
    char pathPtr[MAX_PATH_LEN] = {0};

    if ((pathBlob == NULL) || (pathBlob->data == NULL)) {
        CM_LOG_E("Null pointer failure");
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t ret = ConstructUserIdPath(context, store, pathPtr, MAX_PATH_LEN);
    if (ret != CMR_OK) {
        CM_LOG_E("Get file path faild");
        return CMR_ERROR;
    }

    char *useridpath = (char *)pathBlob->data;
    if (sprintf_s(useridpath, MAX_PATH_LEN, "%s", pathPtr) < 0) {
            return CM_FAILURE;
    }
    pathBlob->size = strlen(path) + 1;
    if (CmMakeDir(useridpath) == CMR_ERROR_MAKE_DIR_FAIL) {
        CM_LOG_E("Failed to create folder %s", useridpath);
        return CMR_FILE_WRITE_ERROR;
    }
    return CMR_OK;
}

static int32_t CreateCertPathList(char *useridPath, struct CmMutableBlob *certPathList)
{
    ASSERT_ARGS(useridPath && certPathList);
    int32_t ret = CM_SUCCESS;
    uint32_t i = 0;
    uint32_t uidCount = 0;
    struct CmMutableBlob *cPaths = NULL;

    if (MallocFileNames(certPathList, useridPath, &cPaths, &uidCount) != 0) {
        CM_LOG_E("Failed to malloc memory for certPath List");
        return CM_FAILURE;
    }
    do {
        void *d = CmOpenDir(useridPath);
        if (d == NULL) {
            CM_LOG_E("Failed to open directory: %s", useridPath);
            ret = CM_FAILURE;
            break;
        }

        struct CmFileDirentInfo dire = {0};
        while (CmGetSubDir(d, &dire) == CMR_OK) {
            char pathBuf[CERT_MAX_PATH_LEN] = {0};
            if (snprintf_s(pathBuf, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s", useridPath, dire.fileName) < 0) {
                CM_LOG_E("mkdir uid path failed");
                ret = CM_FAILURE;
                break;
            }

            cPaths[i].size = strlen(pathBuf) + 1;
            cPaths[i].data = (uint8_t *)CmMalloc(cPaths[i].size);
            char *path = (char *)cPaths[i].data;
            if (sprintf_s(path, MAX_PATH_LEN, "%s", pathBuf) < 0) {
                ret = CM_FAILURE;
                break;
            }
            i++;
        }

        if (i != uidCount) {
            ret = CM_FAILURE;
            break;
        }
    } while (0);
    (void) CmCloseDir(d);
    FreeFileNames(cPaths, i);
    return ret;
}

int32_t CmGetCertPathList(const struct CmContext *context, uint32_t store,
    struct CmMutableBlob *certPathList)
{
    int32_t ret = CM_SUCCESS;
    uint8_t userPathBuf[CERT_MAX_PATH_LEN] = {0};
    struct CmMutableBlob userPathBlob = { sizeof(userPathBuf), userPathBuf };

    do {
        ret = CmGetUserIdPath(context, store, &userPathBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed obtain userpath for store %u", store);
            break;
        }

        ret = CreateCertPathList((char *)userPathBlob.data, certPathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed create certPathList for userid %u", context->userId);
            break;
        }
    } while (0);
    return ret;
}

int32_t CmRemoveUserCert(struct CmMutableBlob *pathBlob,
    const struct CmBlob *certUri)
{
    return CertManagerFileRemove((char *)pathBlob->data, (char *)certUri->data);
}

static int32_t RemoveAllUserCert(const struct CmContext *context, uint32_t store, const char* path)
{
    ASSERT_ARGS(path);
    int32_t ret = CM_SUCCESS;
    struct CmMutableBlob fileNames = { 0, NULL };
    struct CmMutableBlob *fNames = NULL;
    struct CmBlob uri[MAX_LEN_URI];
    struct CmMutableBlob pathBlob = { sizeof(path), path };

    uint32_t uriArraryLen = MAX_LEN_URI * sizeof(struct CmMutableBlob);
    (void)memset_s(uri, uriArraryLen, 0, uriArraryLen);
    if (CertManagerGetFilenames(&fileNames, path, uri) < 0) {
        CM_LOG_E("Failed obtain filenames from path: %s", path);
        (void)CmFreeCaFileNames(&fileNames);
        return CM_FAILURE;
    }

    fNames = (struct CmMutableBlob *)fileNames.data;
    for (uint32_t i = 0; i < fileNames.size; i++) {
        ret = CertManagerFileRemove(path, (char *)fNames[i].data);
        if (ret != CMR_OK) {
            CM_LOG_E("User Cert %d remove failed, ret: %d", i, ret);
            continue;
        }
        ret = CmSetStatusEnable(context, &pathBlob, &uri[i], store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Update StatusFile %d fail, ret = %d", i, ret);
            continue;
        }
    }
    (void)CmFreeCaFileNames(&fileNames);
    return ret;
}

static int32_t RemoveAllUidDir(const char* path)
{
    return CM_ERROR(CmDirRemove(path));
}

int32_t CmRemoveAllUserCert(const struct CmContext *context, uint32_t store, const struct CmMutableBlob *certPathList)
{
    ASSERT_ARGS(certPathList && certPathList->data && certPathList->size);
    int32_t ret = CM_SUCCESS;
    struct CmMutableBlob *path = (struct CmMutableBlob *)certPathList.data;

    for (uint32_t i = 0; i < certPathList->size; i++) {
        ret = RemoveAllUserCert(context, store, (char *)path[i].data);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed remove usercert of path %s", (char *)path[i].data);
            continue;
        }
        ret = RemoveAllUidDir((char *)path[i].data);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Remove UidPath %s fail, ret = %d", (char *)path[i].data, ret);
            continue;
        }
    }
    return ret;
}

static int32_t NameHashFromUri(const char *fName, struct CmMutableBlob *nameDigest)
{
    uint32_t buffsize = (uint32_t)strlen(fName) + 1;
    struct HksBlob certName = {buffsize, (uint8_t *)fName};

    return NameHash(&certName, nameDigest);
}

static int32_t CreateCertFile(struct CertFile *certFile, const char *path, uint32_t *certCount)
{
    ASSERT_ARGS(path);
    int32_t ret = CM_SUCCESS;
    uint32_t i = *certCount;
    uint32_t fileNums = GetNumberOfFiles(path);

    void *d = CmOpenDir(path);
    if (d == NULL) {
        CM_LOG_E("Failed to open directory: %s", path);
        return CM_FAILURE;
    }

    struct CmFileDirentInfo dire = {0};
    while (CmGetDirFile(d, &dire) == CMR_OK) {
        uint32_t pathSize = strlen(path);
        certFile[i].path->size = pathSize;
        certFile[i].path->data = (uint8_t *) strdup(path);

        uint32_t fNameSize = strlen(dire.fileName);
        certFile[i].fileName->size = fNameSize;
        certFile[i].fileName->data = (uint8_t *) strdup(dire.fileName);

        i++;
    }

    if (i != fileNums) {
        return CM_FAILURE;
    }
    (void) CmCloseDir(d);
    *certCount += fileNums;
    return ret;
}

static int CmGetCertSubAndAlias(const char *fName, const char *path,
    struct CmBlob *subjectName, struct CmBlob *certAlias)
{
    int32_t ret = CM_SUCCESS;
    X509 *x509cert = NULL;
    int32_t subjectNameLen = 0;
    int32_t certAliasLen = 0;
    uint32_t certBuffSize = CertManagerFileSize(path, fName);
    struct CmMutableBlob certData = { 0, NULL };

    certData.data = CmMalloc(certBuffSize);
    if (certDataList[i].data == NULL) {
        CM_LOG_E("Failed to allocate memory for certificate: %s", fName);
        return CM_FAILURE;
    }
    certData->size = certBuffSize;
    if (CertManagerFileRead(path, fName, 0, certData.data, certBuffSize) != certBuffSize) {
        CM_LOG_E("Failed to read file: %s", fName);
        return CM_FAILURE;
    }

    x509cert = InitCertContext(certData.data, certData.size);
    subjectNameLen = GetX509SubjectNameLongFormat(x509cert, (char *)subjectName->data,
        MAX_LEN_SUBJECT_NAME);
    if (subjectNameLen == 0) {
        CM_LOG_E("Failed to get cert subjectName");
        return CM_FAILURE;
    }
    subjectName->.size = (uint32_t)subjectNameLen;

    certAliasLen = GetX509SubjectName(x509cert, CM_ORGANIZATION_NAME, (char *)certAlias->data,
         MAX_LEN_CERT_ALIAS);
    if (certAliasLen == 0) {
        certAliasLen = GetX509SubjectName(x509cert, CM_COMMON_NAME, (char *)certAlias->data,
        MAX_LEN_CERT_ALIAS);
    }
    if (certAliasLen == 0) {
        CM_LOG_E("Failed to get cert  CN name");
        return CM_FAILURE;
    }
    if (certAliasLen < 0) {
        return certAliasLen;
    }
    FreeCertContext(x509cert);
    certAlias->size = (uint32_t)certAliasLen;
    return ret;
}

int32_t CmGetCertListInfo(const struct CmContext *context, uint32_t store,
    const struct CmMutableBlob *certFileList, struct CertBlob *certBlob, uint32_t *status)
{
    int32_t ret = CM_SUCCESS;
    struct CertFile *certFile = (struct CertFile *)certFileList->data;

    ret = CmMallocCertInfo01(certBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("CmMallocCertInfo fail");
        return ret;
    }

    for (uint32_t i = 0; i < certFileList->size; i++) {
        /* status */
        ret = CertManagerStatusFile(context, certFile[i], store, CERT_STATUS_INVALID, &status[i]);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get cert status");
            return CM_FAILURE;
        }

        /* uri */
        certBlob->uri[i].size = certFile[i].fileName->size;
        if (memcpy_s(certBlob->uri[i].data, MAX_LEN_URI, certFile[i].fileName->data,
            certFile[i].fileName->size) != EOK) {
            CM_LOG_E("Failed to get cert uri");
            return CM_FAILURE;
        }

        /* subjectName + certAlias */
        ret = CmGetCertSubAndAlias((char *)certFile[i].fileName->data, (char *)certFile[i].path->data,
            &(certBlob->subjectName[i]), &(certBlob->certAlias[i]));
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get cert data");
            return CM_FAILURE;
        }
    }
    return ret;
}

static int32_t CreateCertFileList(const struct CmMutableBlob *certPathList, struct CmMutableBlob *certFileList)
{
    ASSERT_ARGS(certPathList && certPathList->data && certPathList->size);
    int32_t ret = CM_SUCCESS;
    struct CmMutableBlob *path = (struct CmMutableBlob *)certPathList.data;
    struct CertFile *certFile = (struct CertFile *)CmMalloc(sizeof(struct CertFile) * MAX_COUNT_CERTIFICATE);
    certFileList->data = (uint8_t *)certFile;
    uint32_t certCount = 0;

    for (uint32_t i = 0; i < certPathList->size; i++) {
        ret = CreateCertFile(certFile, path[i].data, &certCount);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CreateCertFile fail of %s", path[i].data);
            continue;
        }
    }
    certFileList->size = certCount;
    return ret;
}

int32_t CmServiceGetCertList(const struct CmContext *context, uint32_t store, struct CmMutableBlob *certFileList)
{
    int32_t ret = CM_SUCCESS;
    struct CmMutableBlob certPathList = { 0, NULL };

    do {
        ret = CmCheckCallerPermission(context);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Check caller permission fail");
            break;
        }

        /* get path of every uid */
        ret = CmGetCertPathList(context, store, &certPathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertPathList fail, ret = %d", ret);
            (void)CmFreeCertPaths(&certPathList);
            break;
        }

        /* create certFile(path + name) list from every uid */
        ret = CreateCertFileList(&certPathList, certFileList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CreateCertFileList fail, ret = %d", ret);
            (void)CmFreeCertPaths(&certPathList);
            break;
        }
    } while (0);

    (void)CmFreeCertPaths(&certPathList);
    return ret;
}

static int32_t CmGetCertData(const char *fName, const char *path, struct CmBlob *certificateData)
{
    int32_t ret = CM_SUCCESS;
    uint32_t certBuffSize = CertManagerFileSize(path, fName);

    certificateData->data = (uint8_t *)CmMalloc(certBuffSize);
    if (fName == NULL) {
        CM_LOG_E("Failed to allocate memory for certificate: %s", fName);
        return CM_FAILURE;
    }
    certificateData->size = certBuffSize;
    if (CertManagerFileRead(path, fName, 0, certificateData->data, certBuffSize) != certBuffSize) {
        CM_LOG_E("Failed to read file: %s", fName);
        return CM_FAILURE;
    }
    return ret;
}

static int32_t CmGetMatchedCertIndex(const struct CmMutableBlob *certFileList, const struct CmBlob *certUri)
{
    struct CertFile *certFile = (struct CertFile *)certFileList->data;
    uint32_t matchIndex = certFileList->size;

    for (uint32_t i = 0; i < certFileList->size; i++) {
        if (certFile[i].fileName->data == NULL) {
            CM_LOG_E("Corrupted file name at index: %d.\n", i);
            ret = CMR_ERROR_STORAGE;
            continue;
        }

        if ((certUri->size <= certFile[i].fileName->data) &&
            (memcmp(certUri->data, certFile[i].fileName->data, certUri->size) == 0)) {
            matchIndex = i;
            break;
        }
    }
    return matchIndex;
}

int32_t CmGetServiceCertInfo(const struct CmContext *context, const struct CmBlob *certUri,
    uint32_t store, struct CmBlob *certificateData, uint32_t *status)
{
    int32_t ret = CM_SUCCESS;
    struct CmMutableBlob certFileList = { 0, NULL };
    uint32_t matchIndex = 0;

    do {
        ret = CmCheckCallerPermission(context);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Check caller permission fail");
            break;
        }

        ret = CmServiceGetCertList(context, store, &certFileList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCertList fail, ret = %d", ret);
            break;
        }

        matchIndex = CmGetMatchedCertIndex(&certFileList, certUri);
        if (matchIndex == certFileList.size) {
            CM_LOG_E("certFile of certUri don't matched");
            return CM_FAILURE;
        }

        ret = CertManagerStatusFile(context, certFile[matchIndex], store, CERT_STATUS_INVALID, status);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get cert status");
            return CM_FAILURE;
        }

        ret = CmGetCertData((char *)certFile[matchIndex].fileName->data,
        (char *)certFile[matchIndex].path->data, certificateData);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get cert data");
            return CM_FAILURE;
        }
    } while (0);

    (void)CmFreeCertPaths(&certPathList);
    return ret;
}

int32_t BuildUserUri(char **userUri, const char *aliasName, uint32_t type, const struct CmContext *context)
{
    int32_t rc = CM_SUCCESS;
    struct CMUri uri = {0};
    uri.object = strdup(aliasName);
    uri.type = type;

    TRY_FUNC(UriSetIdStr(&uri.user, context->userId), rc);
    TRY_FUNC(UriSetIdStr(&uri.app, context->uid), rc);
    TRY_FUNC(EncodeUri(userUri, &uri), rc);

finally:
    CertManagerFreeUri(&uri);
    return rc;
}

static int32_t DirRemove(const char *path)
{
    if (access(path, F_OK) != 0) {
        return CMR_ERROR_NOT_EXIST;
    }

    struct stat tmp;
    if (stat(path, &tmp) != 0) {
        return CMR_ERROR_INTERNAL_ERROR;
    }

    DIR *dirp;
    struct dirent *dire;
    if (S_ISDIR(tmp.st_mode)) {
        uint32_t i = 0;
        dirp = opendir(path);
        while ((dire = readdir(dirp)) != NULL)) {
            if ((strcmp(dire->d_name, ".") == 0) || (strcmp(dire->d_name, "..") == 0)) {
                continue;
            }
            i++;
        }
        closedir(path);

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

int32_t CmGetSubDir(DIR *dirp, struct CmFileDirentInfo *direntInfo)
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
            return CMR_ERROR_BAD_STATE;
        }
        direntInfo->fileName[dirLen] = '\0';
        return CMR_OK;
    }

    return CMR_ERROR_NOT_EXIST;
}

static RbTreeKey GetRbTreeKey(uint32_t store, char *fn)
{
    uint8_t buff[MAX_NAME_DIGEST_LEN];
    struct CmMutableBlob nameDigest = {sizeof(buff), buff};
    if (store == CM_SYSTEM_TRUSTED_STORE) {
        RbTreeKey key = GetRbTreeKeyFromName(fn);
    } else {
        rc = NameHashFromUri(fn, &nameDigest);
        if (rc != CMR_OK) {
            return rc;
        }
        RbTreeKey key = GetRbTreeKeyFromName((char *)nameDigest.data);
    }
    return key;
}

int32_t CmSetStatusEnable(const struct CmContext *context, struct CmMutableBlob *pathBlob,
    const struct CmBlob *certUri, uint32_t store)
{
    struct CertFile certFile = { 0, 0 };
    certFile.path = &(CM_BLOB(pathBlob));
    certFile.fileName = &(CM_BLOB(certUri));

    return CertManagerStatusFile(context, certFile, store, CERT_STATUS_ENANLED, NULL);
}

#ifdef __cplusplus
}
#endif