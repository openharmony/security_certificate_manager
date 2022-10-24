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

#include "cert_manager_query.h"

#include "securec.h"
#include "cm_log.h"
#include "cm_type.h"
#include "cm_x509.h"
#include "cert_manager_file.h"
#include "cert_manager_mem.h"
#include "cert_manager_uri.h"
#include "cert_manager_storage.h"
#include "cert_manager_status.h"
#include "cert_manager_file_operator.h"

#define MAX_PATH_LEN                  256

int32_t CmGetCertData(const char *fName, const char *path, struct CmBlob *certData)
{
    int32_t ret = CM_SUCCESS;
    uint32_t dataSize = CertManagerFileSize(path, fName);
    if (dataSize == 0) {
        CM_LOG_E("cert %s is not exist", fName);
        return CMR_ERROR_NOT_EXIST;
    }

    certData->data = (uint8_t *)CMMalloc(dataSize);
    if (certData->data == NULL) {
        CM_LOG_E("allocate data memory for cert: %s", fName);
        return CM_FAILURE;
    }
    certData->size = dataSize;
    if (CertManagerFileRead(path, fName, 0, certData->data, dataSize) != dataSize) {
        CM_LOG_E("read cert %s failed", fName);
        CM_FREE_BLOB(*certData);
        return CM_FAILURE;
    }

    return ret;
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
    pathBlob->size = strlen(useridpath) + 1;
    return CMR_OK;
}

static int32_t MallocCertPathList(struct CmMutableBlob *cPath, const char *path)
{
    uint32_t pathSize = strlen(path) + 1;
    cPath->data = (uint8_t *)CMMalloc(pathSize);
    if (cPath->data == NULL) {
        CM_LOG_E("malloc cPathLists failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    cPath->size = pathSize;
    return CM_SUCCESS;
}

static int32_t ConstrutPathList(char *useridPath, struct CmMutableBlob *cPathList,
    uint32_t fileCount)
{
    int32_t ret = CM_SUCCESS;
    void *d = CmOpenDir(useridPath);
    if (d == NULL) {
        CM_LOG_E("Failed to open directory: %s", useridPath);
        return CM_FAILURE;
    }

    do {
        uint32_t i = 0;
        struct CmFileDirentInfo dire = {0};
        while (CmGetSubDir(d, &dire) == CMR_OK) {
            char pathBuf[MAX_PATH_LEN] = {0};
            if (snprintf_s(pathBuf, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s", useridPath, dire.fileName) < 0) {
                CM_LOG_E("mkdir uid path failed");
                ret = CM_FAILURE;
                break;
            }

            if (MallocCertPathList(&cPathList[i], pathBuf) != CM_SUCCESS) {
                ret = CMR_ERROR_MALLOC_FAIL;
                break;
            }
            char *path = (char *)cPathList[i].data;
            if (sprintf_s(path, cPathList[i].size, "%s", pathBuf) < 0) {
                ret = CM_FAILURE;
                break;
            }
            i++;
        }

        if (i != fileCount) {
            ret = CM_FAILURE;
            break;
        }
    } while (0);
    (void) CmCloseDir(d);
    return ret;
}

static int32_t CreateCertPathList(char *useridPath, struct CmMutableBlob *certPathList)
{
    int32_t ret = CM_SUCCESS;

    do {
        uint32_t uidCount = GetNumberOfDirs(useridPath);
        if (uidCount == 0) {
            CM_LOG_I("dir is empty");
            return CM_SUCCESS;
        }

        struct CmMutableBlob *cPathList = (struct CmMutableBlob *)CMMalloc(
            sizeof(struct CmMutableBlob) * uidCount);
        if (cPathList == NULL) {
            CM_LOG_E("malloc cPathList failed");
            ret = CMR_ERROR_MALLOC_FAIL;
            break;
        }
        (void)memset_s(cPathList, sizeof(struct CmMutableBlob) * uidCount, 0,
            sizeof(struct CmMutableBlob) * uidCount);

        ret = ConstrutPathList(useridPath, cPathList, uidCount);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("construct cPathList failed");
            break;
        }

        certPathList->data = (uint8_t *)cPathList;
        certPathList->size = uidCount;
    } while (0);

    return ret;
}

int32_t CmGetCertPathList(const struct CmContext *context, uint32_t store,
    struct CmMutableBlob *certPathList)
{
    int32_t ret = CM_SUCCESS;
    uint8_t pathBuf[MAX_PATH_LEN] = {0};
    struct CmMutableBlob pathBlob = { sizeof(pathBuf), pathBuf };

    do {
        ret = CmGetUserIdPath(context, store, &pathBlob);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed obtain userpath for store %u", store);
            break;
        }

        ret = CreateCertPathList((char *)pathBlob.data, certPathList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed create certPathList for userid %u", context->userId);
            break;
        }
    } while (0);
    return ret;
}

static int32_t MallocCertFilePath(struct CertFilePath *certFilePath, const char *path,
    const char *fName)
{
    uint32_t pathSize = strlen(path) + 1;
    certFilePath->path.data = (uint8_t *)CMMalloc(pathSize);
    if (certFilePath->path.data == NULL) {
        CM_LOG_E("malloc path data failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    certFilePath->path.size = pathSize;

    uint32_t nameSize = strlen(fName) + 1;
    certFilePath->fileName.data = (uint8_t *)CMMalloc(nameSize);
    if (certFilePath->fileName.data  == NULL) {
        CM_LOG_E("malloc filename data failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    certFilePath->fileName.size = nameSize;

    return CM_SUCCESS;
}

static int32_t CreateCertFile(struct CertFilePath *certFilePath, const char *path, uint32_t *certCount)
{
    ASSERT_ARGS(path);
    int32_t ret = CM_SUCCESS;
    uint32_t i = *certCount;
    int32_t fileNums = GetCertCount(path);
    if (fileNums == 0) {
        CM_LOG_I("no cert file in path");
        return CM_SUCCESS;
    }

    void *d = CmOpenDir(path);
    if (d == NULL) {
        CM_LOG_E("Failed to open directory: %s", path);
        return CM_FAILURE;
    }

    struct CmFileDirentInfo dire = {0};
    while (CmGetDirFile(d, &dire) == CMR_OK) {
        if (i > MAX_COUNT_CERTIFICATE) {
            CM_LOG_E("cert count beyond MAX_COUNT_CERTIFICATE");
            break;
        }

        ret = MallocCertFilePath(&certFilePath[i], path, dire.fileName);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("malloc certfilepath for cert %s failed", dire.fileName);
            return ret;
        }

        char *pathTmp = (char *)certFilePath[i].path.data;
        if (sprintf_s(pathTmp, certFilePath[i].path.size, "%s", path) < 0) {
            CM_LOG_E("copy path failed");
            break;
        }
        char *nameTmp = (char *)certFilePath[i].fileName.data;
        if (sprintf_s(nameTmp, certFilePath[i].fileName.size, "%s", dire.fileName) < 0) {
            CM_LOG_E("copy file name failed");
            break;
        }

        i++;
    }

    if ((i - *certCount) != (uint32_t)fileNums) {
        return CM_FAILURE;
    }
    (void) CmCloseDir(d);
    *certCount += (uint32_t)fileNums;
    return ret;
}

int32_t CreateCertFileList(const struct CmMutableBlob *certPathList, struct CmMutableBlob *certFileList)
{
    if (certPathList->size == 0) {
        CM_LOG_I("dir is empty");
        return CM_SUCCESS;
    }

    struct CertFilePath *certFilePath = (struct CertFilePath *)CMMalloc(sizeof(struct CertFilePath) *
        MAX_COUNT_CERTIFICATE);
    if (certFilePath == NULL) {
        CM_LOG_E("malloc certFilePath failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(certFilePath, sizeof(struct CertFilePath) * MAX_COUNT_CERTIFICATE, 0,
        sizeof(struct CertFilePath) * MAX_COUNT_CERTIFICATE);

    int32_t ret = CM_SUCCESS;
    uint32_t certCount = 0;
    struct CmMutableBlob *uidPath = (struct CmMutableBlob *)certPathList->data;

    for (uint32_t i = 0; i < certPathList->size; i++) {
        ret = CreateCertFile(certFilePath, (char *)uidPath[i].data, &certCount);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CreateCertFile fail of %s", (char *)uidPath[i].data);
            continue;
        }
    }
    certFileList->data = (uint8_t *)certFilePath;
    certFileList->size = certCount;
    return ret;
}

static int32_t CmMallocCertBlob(struct CertBlob *certBlob, uint32_t certCount)
{
    if (certBlob == NULL) {
        return CMR_ERROR_NULL_POINTER;
    }

    for (uint32_t i = 0; i < certCount; i++) {
        certBlob->uri[i].size = MAX_LEN_URI;
        certBlob->uri[i].data = (uint8_t *)CMMalloc(MAX_LEN_URI);
        if (certBlob->uri[i].data == NULL) {
            return CMR_ERROR_MALLOC_FAIL;
        }
        (void)memset_s(certBlob->uri[i].data, MAX_LEN_URI, 0, MAX_LEN_URI);

        certBlob->subjectName[i].size = MAX_LEN_SUBJECT_NAME;
        certBlob->subjectName[i].data = (uint8_t *)CMMalloc(MAX_LEN_SUBJECT_NAME);
        if (certBlob->subjectName[i].data == NULL) {
            return CMR_ERROR_MALLOC_FAIL;
        }
        (void)memset_s(certBlob->subjectName[i].data, MAX_LEN_SUBJECT_NAME, 0, MAX_LEN_SUBJECT_NAME);

        certBlob->certAlias[i].size = MAX_LEN_CERT_ALIAS;
        certBlob->certAlias[i].data = (uint8_t *)CMMalloc(MAX_LEN_CERT_ALIAS);
        if (certBlob->certAlias[i].data == NULL) {
            return CMR_ERROR_MALLOC_FAIL;
        }
        (void)memset_s(certBlob->certAlias[i].data, MAX_LEN_CERT_ALIAS, 0, MAX_LEN_CERT_ALIAS);
    }
    return CM_SUCCESS;
}

int32_t CmGetCertAlias(const char *uri, struct CmBlob *certAlias)
{
    int32_t ret = CM_SUCCESS;
    struct CMUri certUri;
    (void)memset_s(&certUri, sizeof(certUri), 0, sizeof(certUri));

    ret = CertManagerUriDecode(&certUri, uri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uri decode failed, ret = %d", ret);
        return ret;
    }

    uint32_t size = strlen(certUri.object);
    if (memcpy_s(certAlias->data, MAX_LEN_CERT_ALIAS, (uint8_t *)certUri.object, size) != EOK) {
        return CM_FAILURE;
    }
    certAlias->size = size + 1;
    (void)CertManagerFreeUri(&certUri);
    return ret;
}

static int32_t CmGetCertSubjectName(const char *fName, const char *path, struct CmBlob *subjectName)
{
    int32_t ret = CM_SUCCESS;
    struct CmBlob certData = { 0, NULL };
    ret = CmGetCertData(fName, path, &certData);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get cert data failed");
        return CM_FAILURE;
    }

    int32_t subjectNameLen = 0;
    X509 *cert = InitCertContext(certData.data, certData.size);
    if (cert == NULL) {
        CM_LOG_E("cert data can't convert x509 format");
        ret = CM_FAILURE;
    }
    subjectNameLen = GetX509SubjectNameLongFormat(cert, (char *)subjectName->data,
        MAX_LEN_SUBJECT_NAME);
    if (subjectNameLen == 0) {
        CM_LOG_E("get cert subjectName failed");
        ret = CM_FAILURE;
    }
    subjectName->size = (uint32_t)subjectNameLen + 1;

    CM_FREE_BLOB(certData);
    FreeCertContext(cert);
    return ret;
}

int32_t CmGetCertListInfo(const struct CmContext *context, uint32_t store,
    const struct CmMutableBlob *certFileList, struct CertBlob *certBlob, uint32_t *status)
{
    int32_t ret = CM_SUCCESS;
    struct CertFilePath *certFilePath = (struct CertFilePath *)certFileList->data;

    ret = CmMallocCertBlob(certBlob, certFileList->size);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("malloc certBlob failed");
        return ret;
    }

    for (uint32_t i = 0; i < certFileList->size; i++) {
        ret = CmGetCertStatus(context, &certFilePath[i], store, &status[i]); /* status */
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get cert status");
            return CM_FAILURE;
        }

        if (memcpy_s(certBlob->uri[i].data, MAX_LEN_URI, certFilePath[i].fileName.data,
            certFilePath[i].fileName.size) != EOK) {
            CM_LOG_E("Failed to get cert uri");
            return CM_FAILURE;
        }
        certBlob->uri[i].size = certFilePath[i].fileName.size; /* uri */

        ret = CmGetCertAlias((char *)certFilePath[i].fileName.data, &(certBlob->certAlias[i])); /* certAlias */
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get cert certAlias");
            return CM_FAILURE;
        }

        ret = CmGetCertSubjectName((char *)certFilePath[i].fileName.data, (char *)certFilePath[i].path.data,
            &(certBlob->subjectName[i])); /* subjectName */
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get cert subjectName");
            return CM_FAILURE;
        }
    }
    return ret;
}

void CmFreeCertBlob(struct CertBlob *certBlob)
{
    if (certBlob == NULL) {
        CM_LOG_E("certBlob is null");
        return;
    }

    for (uint32_t i = 0; i < MAX_COUNT_CERTIFICATE; i++) {
        CM_FREE_BLOB(certBlob->uri[i]);
        CM_FREE_BLOB(certBlob->subjectName[i]);
        CM_FREE_BLOB(certBlob->certAlias[i]);
    }
}

int32_t CmGetMatchedCertIndex(const struct CmMutableBlob *certFileList, const struct CmBlob *certUri)
{
    if (certFileList->size == 0) {
        CM_LOG_I("no cert file  exist");
        return MAX_COUNT_CERTIFICATE;
    }

    struct CertFilePath *certFilePath = (struct CertFilePath *)certFileList->data;
    uint32_t matchIndex = certFileList->size;

    for (uint32_t i = 0; i < certFileList->size; i++) {
        if (certFilePath[i].fileName.data == NULL) {
            CM_LOG_E("Corrupted file name at index: %d.\n", i);
            continue;
        }

        if ((certUri->size <= certFilePath[i].fileName.size) &&
            (memcmp(certUri->data, certFilePath[i].fileName.data, certUri->size) == 0)) {
            matchIndex = i;
            break;
        }
    }
    return matchIndex;
}

void CmFreeCertFiles(struct CmMutableBlob *certFiles)
{
    if ((certFiles == NULL) || (certFiles->data == NULL)) {
        return;
    }

    struct CertFilePath *cFilePaths = (struct CertFilePath *)certFiles->data;
    for (uint32_t i = 0; i < certFiles->size; i++) {
        cFilePaths[i].path.size = 0;
        CM_FREE_PTR(cFilePaths[i].path.data);

        cFilePaths[i].fileName.size = 0;
        CM_FREE_PTR(cFilePaths[i].fileName.data);
    }
    CMFree(cFilePaths);
    certFiles->size = 0;
}

void CmFreeCertPaths(struct CmMutableBlob *certPaths)
{
    if ((certPaths == NULL) || (certPaths->data == NULL)) {
        return;
    }

    struct CmMutableBlob *cPaths = (struct CmMutableBlob *)certPaths->data;
    for (uint32_t i = 0; i < certPaths->size; i++) {
        cPaths[i].size = 0;
        CM_FREE_PTR(cPaths[i].data);
    }
    CMFree(cPaths);
    certPaths->size = 0;
}
