/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "cm_cert_property_rdb.h"
#include "cm_log.h"
#include "cm_type.h"
#include "cm_x509.h"
#include "cert_manager_file.h"
#include "cert_manager_mem.h"
#include "cert_manager_uri.h"
#include "cert_manager_storage.h"
#include "cert_manager_status.h"
#include "cert_manager_file_operator.h"
#include "cm_util.h"

#define MAX_PATH_LEN                  256

static int32_t MallocCertPath(struct CmMutableBlob *cPath, const char *path)
{
    uint32_t pathSize = strlen(path) + 1;
    cPath->data = (uint8_t *)CMMalloc(pathSize);
    if (cPath->data == NULL) {
        CM_LOG_E("malloc cPathLists failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    cPath->size = pathSize;
    (void)memset_s(cPath->data, pathSize, 0, pathSize);
    return CM_SUCCESS;
}

void CmFreePathList(struct CmMutableBlob *pList, uint32_t pathCount)
{
    if (pList == NULL) {
        return;
    }

    for (uint32_t i = 0; i < pathCount; i++) {
        pList[i].size = 0;
        CM_FREE_PTR(pList[i].data);
    }
    CM_FREE_PTR(pList);
}

static int32_t ConstrutPathList(const char *useridPath, struct CmMutableBlob *cPathList, uint32_t dirCount)
{
    int32_t ret = CM_SUCCESS;
    void *d = CmOpenDir(useridPath);
    if (d == NULL) {
        CM_LOG_E("Failed to open directory");
        return CMR_ERROR_FILE_OPEN_DIR;
    }

    uint32_t dealCert = 0;
    struct CmFileDirentInfo dire = {0};
    while (CmGetSubDir(d, &dire) == CMR_OK) {
        if (dealCert >= dirCount) {
            CM_LOG_E("uid dir count beyond dirCount");
            break;
        }

        char pathBuf[MAX_PATH_LEN] = {0};
        if (sprintf_s(pathBuf, MAX_PATH_LEN, "%s/%s", useridPath, dire.fileName) < 0) {
            CM_LOG_E("copy uid path failed");
            ret = CMR_ERROR_MEM_OPERATION_PRINT;
            break;
        }

        ret = MallocCertPath(&cPathList[dealCert], pathBuf); /* uniformly free memory by caller */
        if (ret != CM_SUCCESS) {
            break;
        }

        if (sprintf_s((char *)cPathList[dealCert].data, cPathList[dealCert].size, "%s", pathBuf) < 0) {
            ret = CMR_ERROR_MEM_OPERATION_PRINT;
            break;
        }
        dealCert++;
    }

    (void) CmCloseDir(d);
    if (dealCert != dirCount) { /* real dir count less than dirCount */
        CM_LOG_E("cert count mismatch, dealCert(%u), dirCount(%u)", dealCert, dirCount);
        ret = CMR_ERROR_CERT_COUNT_MISMATCH;
    }
    return ret;
}

static int32_t CreateCertPathList(const char *useridPath, struct CmMutableBlob *pathList)
{
    int32_t uidCount = GetNumberOfDirs(useridPath);
    if (uidCount < 0) {
        CM_LOG_E("Failed to obtain number of uid from path");
        return CMR_ERROR_FILE_OPEN_DIR; /* when open dir failed return value will smaller than 0 */
    }

    if (uidCount == 0) {
        return CM_SUCCESS;
    }

    if (uidCount > MAX_COUNT_CERTIFICATE) {
        CM_LOG_E("uidCount beyond max, uidCount: %d", uidCount);
        return CMR_ERROR_MAX_CERT_COUNT_REACHED;
    }

    uint32_t arraySize = sizeof(struct CmMutableBlob) * (uint32_t)uidCount;
    struct CmMutableBlob *cPathList = (struct CmMutableBlob *)CMMalloc(arraySize);
    if (cPathList == NULL) {
        CM_LOG_E("malloc cPathList failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(cPathList, arraySize, 0, arraySize);

    int32_t ret = ConstrutPathList(useridPath, cPathList, (uint32_t)uidCount);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("construct cPathList failed");
        CmFreePathList(cPathList, uidCount);
        return ret;
    }

    pathList->data = (uint8_t *)cPathList;
    pathList->size = (uint32_t)uidCount;

    return CM_SUCCESS;
}

int32_t CmGetCertPathList(const struct CmContext *context, uint32_t store, struct CmMutableBlob *pathList)
{
    char userIdPath[MAX_PATH_LEN] = {0};

    int32_t ret = ConstructUserIdPath(context, store, userIdPath, MAX_PATH_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed obtain userpath for store %u", store);
        return ret;
    }

    ret = CreateCertPathList(userIdPath, pathList);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed create pathList for userid %u", context->userId);
        return ret;
    }

    return CM_SUCCESS;
}

static uint32_t GetSysCertPathCount(void)
{
    if (CmIsDirExist(SYSTEM_CA_STORE_GM) == CM_SUCCESS) {
        CM_LOG_D("exist gm system ca store path.");
        return SYSTEM_CA_PATH_COUNT_2;
    }

    return SYSTEM_CA_PATH_COUNT_1;
}

int32_t CmGetSysCertPathList(const struct CmContext *context, struct CmMutableBlob *pathList)
{
    uint32_t sysPathCnt = GetSysCertPathCount();
    uint32_t listSize = sizeof(struct CmMutableBlob) * sysPathCnt;
    struct CmMutableBlob *cPathList = (struct CmMutableBlob *)CMMalloc(listSize);
    if (cPathList == NULL) {
        CM_LOG_E("malloc cPathList failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(cPathList, listSize, 0, listSize);

    int32_t ret;
    do {
        ret = MallocCertPath(&cPathList[SYSTEM_CA_PATH_INDEX], SYSTEM_CA_STORE);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("malloc cPathList[0] failed");
            break;
        }

        if (sprintf_s((char *)cPathList[SYSTEM_CA_PATH_INDEX].data, cPathList[SYSTEM_CA_PATH_INDEX].size,
            "%s", SYSTEM_CA_STORE) < 0) {
            CM_LOG_E("sprintf_s path failed");
            ret = CMR_ERROR_MEM_OPERATION_PRINT;
            break;
        }

        if (sysPathCnt == SYSTEM_CA_PATH_COUNT_2) { /* has gm system ca store path */
            ret = MallocCertPath(&cPathList[SYSTEM_CA_GM_PATH_INDEX], SYSTEM_CA_STORE_GM);
            if (ret != CM_SUCCESS) {
                CM_LOG_E("malloc cPathList[1] failed");
                break;
            }

            if (sprintf_s((char *)cPathList[SYSTEM_CA_GM_PATH_INDEX].data, cPathList[SYSTEM_CA_GM_PATH_INDEX].size,
                "%s", SYSTEM_CA_STORE_GM) < 0) {
                CM_LOG_E("sprintf_s path failed");
                ret = CMR_ERROR_MEM_OPERATION_PRINT;
                break;
            }
        }
    } while (0);
    if (ret != CM_SUCCESS) {
        CmFreePathList(cPathList, sysPathCnt);
        return ret;
    }

    pathList->data = (uint8_t *)cPathList;
    pathList->size = sysPathCnt;
    return CM_SUCCESS;
}

void CmFreeCertFiles(struct CertFileInfo *cFileList, uint32_t certCount)
{
    if (cFileList == NULL) {
        return;
    }

    for (uint32_t i = 0; i < certCount; i++) {
        cFileList[i].path.size = 0;
        CM_FREE_PTR(cFileList[i].path.data);

        cFileList[i].fileName.size = 0;
        CM_FREE_PTR(cFileList[i].fileName.data);
    }
    CMFree(cFileList);
}

static int32_t MallocCertNameAndPath(struct CertFileInfo *certFile, const char *path,
    const char *fName)
{
    uint32_t pathSize = strlen(path) + 1;
    certFile->path.data = (uint8_t *)CMMalloc(pathSize);
    if (certFile->path.data == NULL) {
        CM_LOG_E("malloc path data failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    certFile->path.size = pathSize;
    (void)memset_s(certFile->path.data, pathSize, 0, pathSize);

    uint32_t nameSize = strlen(fName) + 1;
    certFile->fileName.data = (uint8_t *)CMMalloc(nameSize);
    if (certFile->fileName.data  == NULL) {
        CM_LOG_E("malloc filename data failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    certFile->fileName.size = nameSize;
    (void)memset_s(certFile->fileName.data, nameSize, 0, nameSize);

    return CM_SUCCESS;
}

static int32_t GetCertNameAndPath(struct CertFileInfo *certFile, const char *path, const char *fileName)
{
    int32_t ret = MallocCertNameAndPath(certFile, path, fileName); /* uniformly free memory by caller */
    if (ret != CM_SUCCESS) {
        CM_LOG_E("malloc certfile for cert failed");
        return ret;
    }

    if (sprintf_s((char *)certFile->path.data, certFile->path.size, "%s", path) < 0) {
        CM_LOG_E("copy path failed");
        return CM_FAILURE;
    }

    if (sprintf_s((char *)certFile->fileName.data, certFile->fileName.size, "%s", fileName) < 0) {
        CM_LOG_E("copy file name failed");
        return CM_FAILURE;
    }

    return ret;
}

static int32_t CreateCertFile(struct CertFileInfo *cFileList, const char *path, uint32_t *certCount)
{
    if (path == NULL) {
        CM_LOG_E("invaild path");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t fileNums = GetCertCount(path);
    if (fileNums == 0) {
        CM_LOG_D("no cert file in path");
        return CM_SUCCESS;
    }

    if (fileNums < 0) {
        CM_LOG_E("Failed to obtain number of files");
        return CMR_ERROR_FILE_OPEN_DIR; /* when open dir failed return value will smaller than 0 */
    }

    void *isOpen = CmOpenDir(path);
    if (isOpen == NULL) {
        CM_LOG_E("Failed to open directory");
        return CMR_ERROR_FILE_OPEN_DIR;
    }

    int32_t ret;
    uint32_t getCount = *certCount;
    struct CmFileDirentInfo dire = {0};
    while (CmGetDirFile(isOpen, &dire) == CMR_OK) {
        if (getCount >= MAX_COUNT_CERTIFICATE_ALL) {
            CM_LOG_E("cert count beyond MAX");
            break;
        }
        ret = GetCertNameAndPath(&cFileList[getCount], path, dire.fileName);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("malloc certfile for cert failed");
            break;
        }

        getCount++;
    }

    (void) CmCloseDir(isOpen);
    uint32_t realCount = getCount - *certCount;
    *certCount += realCount;
    if (realCount != (uint32_t)fileNums) {
        CM_LOG_E("cert count mismatch, realCount(%u), fileCount(%d)", realCount, fileNums);
        return CMR_ERROR_CERT_COUNT_MISMATCH;
    }
    return ret;
}

int32_t CreateCertFileList(const struct CmMutableBlob *pathList, struct CmMutableBlob *certFileList)
{
    if (pathList->size == 0) {
        return CM_SUCCESS;
    }

    uint32_t arraySize = sizeof(struct CertFileInfo) * MAX_COUNT_CERTIFICATE_ALL;
    struct CertFileInfo *cFileList = (struct CertFileInfo *)CMMalloc(arraySize);
    if (cFileList == NULL) {
        CM_LOG_E("malloc cFileList failed");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(cFileList, arraySize, 0, arraySize);

    int32_t ret = CM_SUCCESS;
    uint32_t certCount = 0;
    struct CmMutableBlob *uidPath = (struct CmMutableBlob *)pathList->data;

    for (uint32_t i = 0; i < pathList->size; i++) {
        ret = CreateCertFile(cFileList, (char *)uidPath[i].data, &certCount);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Create CertFile fail of %u_th", i);
            CmFreeCertFiles(cFileList, certCount);
            return ret;
        }
    }
    certFileList->data = (uint8_t *)cFileList;
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

static int32_t GetUserCertAlias(const char *uri, struct CmBlob *alias)
{
    int32_t ret = CM_SUCCESS;
    struct CMUri certUri;
    (void)memset_s(&certUri, sizeof(certUri), 0, sizeof(certUri));

    ret = CertManagerUriDecode(&certUri, uri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uri decode failed, ret = %d", ret);
        return ret;
    }
    if (certUri.object == NULL) {
        CM_LOG_E("uri's object is invalid after decode");
        (void)CertManagerFreeUri(&certUri);
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    struct CertProperty certProperty;
    (void)memset_s(&certProperty, sizeof(struct CertProperty), 0, sizeof(struct CertProperty));
    ret = QueryCertProperty(uri, &certProperty);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to QueryCertProperty, ret: %d", ret);
        (void)CertManagerFreeUri(&certUri);
        return ret;
    }

    uint32_t size = strlen(certProperty.alias) + 1;
    if (size <= 1) {
        size = strlen(certUri.object) + 1;
        if (memcpy_s(alias->data, size, certUri.object, size) != EOK) {
            (void)CertManagerFreeUri(&certUri);
            return CMR_ERROR_MEM_OPERATION_COPY;
        }
    } else {
        if (memcpy_s(alias->data, size, (uint8_t *)certProperty.alias, size) != EOK) {
            (void)CertManagerFreeUri(&certUri);
            return CMR_ERROR_MEM_OPERATION_COPY;
        }
    }
    alias->size = size;
    (void)CertManagerFreeUri(&certUri);
    return ret;
}

static int32_t GetSysCertAlias(const struct CmBlob *certData, struct CmBlob *alias)
{
    X509 *cert = InitCertContext(certData->data, certData->size);
    if (cert == NULL) {
        CM_LOG_E("cert data can't convert x509 format");
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }

    int32_t aliasLen = GetX509SubjectName(cert, CM_ORGANIZATION_NAME, (char *)alias->data, alias->size);
    if (aliasLen <= 0) {
        aliasLen = GetX509SubjectName(cert, CM_COMMON_NAME, (char *)alias->data, alias->size);
        if (aliasLen <= 0) {
            CM_LOG_E("Failed to get certificates CN name, aliasLen = %d", aliasLen);
            FreeCertContext(cert);
            return CMR_ERROR_GET_CERT_SUBJECT_ITEM;
        }
    }
    alias->size = (uint32_t)aliasLen + 1;

    FreeCertContext(cert);
    return CM_SUCCESS;
}

int32_t CmGetCertAlias(const uint32_t store, const char *uri, const struct CmBlob *certData, struct CmBlob *alias)
{
    int32_t ret;

    if (store == CM_USER_TRUSTED_STORE) {
        ret = GetUserCertAlias(uri, alias);
    } else if (store == CM_SYSTEM_TRUSTED_STORE) {
        ret = GetSysCertAlias(certData, alias);
    } else {
        CM_LOG_E("Invalid store");
        return CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE;
    }

    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get cert certAlias");
        return ret;
    }

    return CM_SUCCESS;
}

int32_t CmGetAliasFromSubjectName(const struct CmBlob *certData, struct CmBlob *alias)
{
    X509 *cert = InitCertContext(certData->data, certData->size);
    if (cert == NULL) {
        CM_LOG_E("cert data can't convert x509 format");
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }

    int32_t ret = GetX509FirstSubjectName(cert, alias);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("GetX509FirstSubjextName failed, ret = %d ", ret);
        FreeCertContext(cert);
        return CMR_ERROR_GET_CERT_SUBJECT_ITEM;
    }

    FreeCertContext(cert);
    return CM_SUCCESS;
}

static int32_t CmGetCertSubjectName(const struct CmBlob *certData, struct CmBlob *subjectName)
{
    X509 *cert = InitCertContext(certData->data, certData->size);
    if (cert == NULL) {
        CM_LOG_E("cert data can't convert x509 format");
        return CMR_ERROR_INVALID_CERT_FORMAT;
    }

    int32_t subjectLen = GetX509SubjectNameLongFormat(cert, (char *)subjectName->data, subjectName->size);
    if (subjectLen <= 0) {
        CM_LOG_E("get cert subjectName failed, subjectLen = %d", subjectLen);
        FreeCertContext(cert);
        return CMR_ERROR_GET_CERT_SUBJECT_ITEM;
    }
    subjectName->size = (uint32_t)subjectLen + 1;

    FreeCertContext(cert);
    return CM_SUCCESS;
}

static int32_t GetCertContext(const struct CmBlob *fileName, struct CmContext *certContext,
    const struct CmContext *context, uint32_t store)
{
    if (store != CM_USER_TRUSTED_STORE) {
        certContext->userId = context->userId;
        certContext->uid = context->uid;
        return CM_SUCCESS;
    }

    struct CMUri uriObj;
    int32_t ret = CertManagerUriDecode(&uriObj, (char *)fileName->data);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to decode uri, ret = %d", ret);
        return ret;
    }

    uint32_t userId = 0;
    uint32_t uid = 0;
    if (CmIsNumeric(uriObj.user, strlen(uriObj.user) + 1, &userId) != CM_SUCCESS ||
        CmIsNumeric(uriObj.app, strlen(uriObj.app) + 1, &uid) != CM_SUCCESS) {
        CM_LOG_E("parse string to uint32 failed.");
        (void)CertManagerFreeUri(&uriObj);
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }
    (void)CertManagerFreeUri(&uriObj);

    certContext->userId = userId;
    certContext->uid = uid;
    return CM_SUCCESS;
}

static int32_t GetCertInfo(const struct CertFileInfo *certFileInfo, uint32_t store, struct CmBlob *certAlias,
    struct CmBlob *certSubject)
{
    if (certFileInfo == NULL || certAlias == NULL || certSubject == NULL) {
        CM_LOG_E("null pointer error");
        return CMR_ERROR_NULL_POINTER;
    }
    struct CmBlob certData = { 0, NULL };
    int ret = CmStorageGetBuf((char *)certFileInfo->path.data, (char *)certFileInfo->fileName.data, &certData);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get cert data failed");
        return ret;
    }

    ret = CmGetCertAlias(store, (char *)certFileInfo->fileName.data, &certData, certAlias); /* alias */
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get cert alias, ret = %d", ret);
        CM_FREE_BLOB(certData);
        return ret;
    }

    ret = CmGetCertSubjectName(&certData, certSubject); /* subjectName */
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get cert subjectName, ret = %d", ret);
        CM_FREE_BLOB(certData);
        return ret;
    }
    CM_FREE_BLOB(certData);
    return ret;
}

int32_t CmGetCertListInfo(const struct CmContext *context, uint32_t store,
    const struct CmMutableBlob *certFileList, struct CertBlob *certBlob, uint32_t *status)
{
    int32_t ret = CM_SUCCESS;
    struct CertFileInfo *cFileList = (struct CertFileInfo *)certFileList->data;

    ret = CmMallocCertBlob(certBlob, certFileList->size);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("malloc certBlob failed");
        return ret;
    }

    for (uint32_t i = 0; i < certFileList->size; i++) {
        struct CmContext certContext = {0};
        ret = GetCertContext(&cFileList[i].fileName, &certContext, context, store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get cert context");
            return ret;
        }

        ret = GetCertInfo(&cFileList[i], store, &(certBlob->certAlias[i]), &(certBlob->subjectName[i]));
        if (ret != CM_SUCCESS) {
            certBlob->uri[i].size = 0;
            CM_LOG_D("get cert info failed");
            continue;
        }

        if (memcpy_s(certBlob->uri[i].data, MAX_LEN_URI, cFileList[i].fileName.data,
            cFileList[i].fileName.size) != EOK) {
            CM_LOG_E("Failed to get cert uri");
            return CMR_ERROR_MEM_OPERATION_COPY;
        }

        certBlob->uri[i].size = cFileList[i].fileName.size; /* uri */

        if (store == CM_SYSTEM_TRUSTED_STORE) {
            status[i] = CERT_STATUS_ENABLED;
            continue;
        }
        ret = CmGetCertConfigStatus((char *)cFileList[i].fileName.data, &status[i]);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get cert status, ret = %d", ret);
            return CMR_ERROR_GET_CERT_STATUS;
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

uint32_t CmGetMatchedCertIndex(const struct CmMutableBlob *certFileList, const struct CmBlob *certUri)
{
    if (certFileList->size == 0) {
        CM_LOG_D("no cert file  exist");
        return MAX_COUNT_CERTIFICATE;
    }

    struct CertFileInfo *cFileList = (struct CertFileInfo *)certFileList->data;
    uint32_t matchIndex = certFileList->size;

    for (uint32_t i = 0; i < certFileList->size; i++) {
        if (cFileList[i].fileName.data == NULL) {
            CM_LOG_E("Corrupted file name at index: %u.\n", i);
            continue;
        }

        if ((certUri->size <= cFileList[i].fileName.size) &&
            (memcmp(certUri->data, cFileList[i].fileName.data, certUri->size) == 0)) {
            matchIndex = i;
            break;
        }
    }
    return matchIndex;
}

int32_t GetRdbAuthStorageLevel(const struct CmBlob *keyUri, enum CmAuthStorageLevel *level)
{
    CM_LOG_D("enter GetRdbAuthStorageLevel");
    if (keyUri == NULL || level == NULL) {
        CM_LOG_E("Invalid input parameters: keyUri or level is NULL");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    struct CertProperty certProp;
    (void)memset_s(&certProp, sizeof(struct CertProperty), 0, sizeof(struct CertProperty));

    /* Even if the queried data is empty, the return value is also success,
     * this value is used to determine whether the query is successful
     */
    certProp.level = ERROR_LEVEL;
    int32_t ret = QueryCertProperty((char *)keyUri->data, &certProp);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to QueryCertProperty, ret: %d", ret);
        return ret;
    }

    *level = certProp.level;

    return ret;
}
