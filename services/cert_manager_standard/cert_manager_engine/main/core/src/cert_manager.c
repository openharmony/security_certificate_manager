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
#include "cert_manager.h"
#include "cert_manager_type.h"
#include "cert_manager_file.h"
#include "cert_manager_mem.h"
#include "cert_manager_status.h"
#include "cert_manager_file_operator.h"
#include "securec.h"
#include "cm_type.h"
#include "cm_asn1.h"
#include "cm_log.h"
#include "cm_x509.h"
#include "hks_type.h"
#include "hks_api.h"
#include "hks_param.h"

#define MAX_FILES_IN_DIR                    1000
#define CERT_MANAGER_MD5_SIZE               32
#define CERT_MANAGER_MAX_CERT_SIZE          4096

#define MAX_NAME_PREFIX                     32
#define MAX_NAME_DIGEST_LEN                 9

#define MAX_PATH_LEN                        256
#define NAME_DIGEST_SIZE                    4

#define EOK  (0)

#ifndef errno_t
typedef int errno_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

static bool g_hksInitialized = false;

struct CmMathedIndexPara {
    char *path;
    uint32_t store;
    uint32_t *status;
    uint32_t *count;
    uint8_t *indexes;
};

int32_t CertManagerInitialize(void)
{
    if (!g_hksInitialized) {
        ASSERT_CM_CALL(HksInitialize());
        g_hksInitialized = true;
    }

    if (CmMakeDir(CERT_DIR) == CMR_ERROR_MAKE_DIR_FAIL) {
        CM_LOG_E("Failed to create folder %s\n", CERT_DIR);
        return CMR_ERROR_WRITE_FILE_FAIL;
    }

    ASSERT_FUNC(CertManagerStatusInit());

    return CMR_OK;
}

int32_t CmFreeCaFileNames(struct CmMutableBlob *fileNames)
{
    uint32_t i;
    int32_t ret = 0;
    struct CmMutableBlob *fNames;

    if (fileNames == NULL) {
        CM_LOG_E("Failed to free memory for certificate names");
        return -1;
    }
    fNames = (struct CmMutableBlob *)fileNames->data;

    for (i = 0; i < fileNames->size; i++) {
        if (fNames[i].data == NULL) {
            CM_LOG_E("Failed to free memory for certificate name: %u", i);
            ret = -1;
        } else {
            if (memset_s(fNames[i].data, MAX_LEN_URI, 0, fNames[i].size) != EOK) {
                return CMR_ERROR;
            }
            fNames[i].size = 0;
            CMFree(fNames[i].data);
        }
    }
    CMFree(fNames);
    fileNames->size = 0;

    return ret;
}

int32_t GetFilePath(const struct CmContext *context, uint32_t store, char *pathPtr,
    char *suffix, uint32_t *suffixLen)
{
    int32_t ret, retVal;
    if (suffix == NULL || suffixLen == NULL) {
        CM_LOG_E("NULL pointer failure");
        return CMR_ERROR_NULL_POINTER;
    }

    switch (store) {
        if (context == NULL) {
            CM_LOG_E("Null pointer failture");
            return CMR_ERROR_NULL_POINTER;
        }
        case CM_CREDENTIAL_STORE:
        case CM_USER_TRUSTED_STORE:
        case CM_PRI_CREDENTIAL_STORE:
            if (store == CM_CREDENTIAL_STORE) {
                ret = sprintf_s(pathPtr, MAX_PATH_LEN, "%s%u", CREDNTIAL_STORE, context->userId);
            } else if (store == CM_PRI_CREDENTIAL_STORE) {
                ret = sprintf_s(pathPtr, MAX_PATH_LEN, "%s%u", APP_CA_STORE, context->userId);
            } else {
                ret = sprintf_s(pathPtr, MAX_PATH_LEN, "%s%u", USER_CA_STORE, context->userId);
            }

            retVal = sprintf_s(suffix, MAX_SUFFIX_LEN, "%u", context->uid);
            if (ret < 0 || retVal < 0) {
                CM_LOG_E("Construct file Path failed ret:%d, retVal:%d", ret, retVal);
                return CMR_ERROR;
            }
            break;
        case CM_SYSTEM_TRUSTED_STORE:
            ret = sprintf_s(pathPtr, MAX_PATH_LEN, "%s", SYSTEM_CA_STORE);
            if (ret < 0) {
                return CMR_ERROR;
            }
            break;

        default:
            return CMR_ERROR_NOT_SUPPORTED;
    }
    *suffixLen = (uint32_t)strlen(suffix);
    return CMR_OK;
}

int32_t CmGetFilePath(const struct CmContext *context, uint32_t store, struct CmMutableBlob *pathBlob)
{
    char pathPtr[MAX_PATH_LEN] = {0};
    uint32_t suffixLen = 0;
    char suffixBuf[MAX_SUFFIX_LEN] = {0};

    if ((pathBlob == NULL) || (pathBlob->data == NULL)) {
        CM_LOG_E("Null pointer failure");
        return CMR_ERROR_NULL_POINTER;
    }
    int32_t ret = GetFilePath(context, store, pathPtr, suffixBuf, &suffixLen);
    if (ret != CMR_OK) {
        CM_LOG_E("Get file path faild");
        return CMR_ERROR;
    }

    /* Create folder if it does not exist */
    if (CmMakeDir(pathPtr) == CMR_ERROR_MAKE_DIR_FAIL) {
        CM_LOG_E("Failed to create path folder:%s", pathPtr);
        return CMR_ERROR_WRITE_FILE_FAIL;
    }

    if (pathBlob->size - 1 < strlen(pathPtr) + suffixLen) {
        CM_LOG_E("Failed to copy path");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    char *path = (char *)pathBlob->data;
    if (suffixLen == 0) {
        if (sprintf_s(path, MAX_PATH_LEN, "%s", pathPtr) < 0) {
            return CM_FAILURE;
        }
    } else {
        if (sprintf_s(path, MAX_PATH_LEN, "%s/%s", pathPtr, suffixBuf) < 0) {
            return CM_FAILURE;
        }
    }

    pathBlob->size = strlen(path) + 1;
    if (CmMakeDir(path) == CMR_ERROR_MAKE_DIR_FAIL) {
        CM_LOG_E("Failed to create folder %s", path);
        return CMR_ERROR_WRITE_FILE_FAIL;
    }
    return CMR_OK;
}

static int32_t CreateCertificateMalloc(const struct CmMutableBlob *fileNames,
    struct CmMutableBlob **certDataList)
{
    uint32_t i;
    uint32_t blobLen = sizeof(struct CmMutableBlob);
    struct CmMutableBlob *certData = (struct CmMutableBlob *)CMMalloc(blobLen * (fileNames->size));
    if (certData == NULL) {
        CM_LOG_E("Failed to allocate memory for certificates");
        return CMR_ERROR_MALLOC_FAIL;
    }

    for (i = 0; i < fileNames->size; i++) {
        certData[i].data = NULL;
        certData[i].size = 0;
    }
    *certDataList = certData;

    return CMR_OK;
}

void CmCertificateListFree(struct CmMutableBlob *certListData, uint32_t certListSize)
{
    if (certListData == NULL || certListSize == 0) {
        return;
    }
    for (uint32_t i = 0; i < certListSize; i++) {
        if (certListData[i].data != NULL) {
            (void)memset_s(certListData[i].data, certListData[i].size, 0, certListData[i].size);
            CMFree(certListData[i].data);
            certListData[i].data = NULL;
            certListData[i].size = 0;
        }
    }

    CMFree(certListData);
    certListData = NULL;
}

static int32_t CmCreateCertificateList(struct CmBlob *certList,
    struct CmMutableBlob *fileNames, const char *path)
{
    uint32_t i;
    char *fName = NULL;
    uint32_t certBuffSize = 0;
    int32_t ret;
    struct CmMutableBlob *certDataList = NULL;

    if ((certList == NULL) || (fileNames == NULL) || (path == NULL) ||
        (fileNames->data == NULL) || (fileNames->size > MAX_FILES_IN_DIR)) {
        CM_LOG_E("Bad parameters: path = %s, ileNames->size = %u", path, fileNames->size);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    ret = CreateCertificateMalloc(fileNames, &certDataList);
    if (ret != CMR_OK) {
        CM_LOG_E("Malloc failed");
        return ret;
    }

    certList->data = (uint8_t *)certDataList;
    certList->size = fileNames->size;

    for (i = 0; i < fileNames->size; i++) {
        fName = (char *)((struct CmMutableBlob *)fileNames->data)[i].data;
        certBuffSize = CertManagerFileSize(path, fName);
        certDataList[i].data = CMMalloc(certBuffSize);
        if (certDataList[i].data == 0) {
            CM_LOG_E("Failed to allocate memory for certificate: %s", fName);
            goto cleanup;
        }
        certDataList[i].size = certBuffSize;

        if (CertManagerFileRead(path, fName, 0, certDataList[i].data, certBuffSize) != certBuffSize) {
            CM_LOG_E("Failed to read file: %s", fName);
            goto cleanup;
        }
    }

    return CMR_OK;
cleanup:
    CmCertificateListFree(certDataList, i);
    return CMR_ERROR;
}

static int32_t CmGetSubjectNameAsn1(const struct CmBlob *certificate, struct CmAsn1Obj *subjectName)
{
    ASSERT_ARGS(certificate && certificate->size && certificate->data);
    ASSERT_ARGS(subjectName);

    struct CmAsn1Obj obj;
    struct CmBlob next = { 0, NULL };
    struct CmBlob cert = CM_BLOB(certificate);

    (void)memset_s(&obj, sizeof(struct CmAsn1Obj), 0, sizeof(struct CmAsn1Obj));
    ASSERT_CM_CALL(CmAsn1ExtractTag(&next, &obj, &cert, ASN_1_TAG_TYPE_SEQ));
    struct CmBlob val = { obj.value.size, obj.value.data };

    ASSERT_CM_CALL(CmAsn1ExtractTag(&val, &obj, &val, ASN_1_TAG_TYPE_SEQ));
    struct CmBlob in_val = { obj.value.size, obj.value.data };

    ASSERT_CM_CALL(CmAsn1ExtractTag(&in_val, &obj, &in_val, ASN_1_TAG_TYPE_CTX_SPEC0));
    ASSERT_CM_CALL(CmAsn1ExtractTag(&in_val, &obj, &in_val, ASN_1_TAG_TYPE_INT));
    ASSERT_CM_CALL(CmAsn1ExtractTag(&in_val, &obj, &in_val, ASN_1_TAG_TYPE_SEQ));
    ASSERT_CM_CALL(CmAsn1ExtractTag(&in_val, subjectName, &in_val, ASN_1_TAG_TYPE_SEQ));

    return CMR_OK;
}

static int32_t CertMangerGetCertificateList(const struct CmContext *context,
    const struct CmBlob *certificateList, uint32_t store, struct CertBlob *certBlob, uint32_t *status)
{
    uint32_t i;
    int32_t ret;
    X509 *x509cert = NULL;
    int32_t subjectNameLen = 0;
    int32_t certAliasLen = 0;
    struct CmBlob *blob = (struct CmBlob *)certificateList->data;
    for (i = 0; i < certificateList->size; i++) {
        ret = CertManagerGetCertificatesStatus(context, &blob[i], store, &status[i]);
        if (ret != 0) {
            CM_LOG_E("Failed to get certificates status");
            return CMR_ERROR;
        }
        x509cert = InitCertContext(blob[i].data, blob[i].size);
        subjectNameLen = GetX509SubjectNameLongFormat(x509cert, (char *)certBlob->subjectName[i].data,
            MAX_LEN_SUBJECT_NAME);
        if (subjectNameLen == 0) {
            CM_LOG_E("Failed to get certificatessubjectName");
            return CMR_ERROR;
        }
        certBlob->subjectName[i].size = (uint32_t)subjectNameLen;

        certAliasLen = GetX509SubjectName(x509cert, CM_ORGANIZATION_NAME, (char *)certBlob->certAlias[i].data,
            MAX_LEN_CERT_ALIAS);
        if (certAliasLen == 0) {
            certAliasLen = GetX509SubjectName(x509cert, CM_COMMON_NAME, (char *)certBlob->certAlias[i].data,
            MAX_LEN_CERT_ALIAS);
        }
        if (certAliasLen == 0) {
            CM_LOG_E("Failed to get certificates CN name");
            return CMR_ERROR;
        }
        if (certAliasLen < 0) {
            return certAliasLen;
        }
        FreeCertContext(x509cert);
        certBlob->certAlias[i].size = (uint32_t)certAliasLen;
    }
    return CMR_OK;
}

int32_t CertManagerListTrustedCertificates(const struct CmContext *context, struct CmBlob *certificateList,
    uint32_t store, struct CertBlob *certBlob, uint32_t *status)
{
    int32_t ret = CMR_OK;
    struct CmMutableBlob fileNames;
    char path[CERT_MAX_PATH_LEN] = {0};

    struct CmMutableBlob pathBlob = { sizeof(path), (uint8_t *)path };
    ret = CmGetFilePath(context, store, &pathBlob);
    if (ret != CMR_OK) {
        CM_LOG_E("Failed obtain path fot store %x", store);
        return CMR_ERROR;
    }
    ret = CertManagerGetFilenames(&fileNames, path, certBlob->uri);
    if (ret < 0) {
        CM_LOG_E("Failed to read certificates from directory: %s", path);
        ret = CMR_ERROR_STORAGE;
        goto cleanup;
    }
    ret = CmCreateCertificateList(certificateList, &fileNames, path);
    if (ret < 0) {
        CM_LOG_E("Failed to create certificates list: %s", path);
        ret = CMR_ERROR_STORAGE;
        goto cleanup;
    }

    ret = CertMangerGetCertificateList(context, certificateList, store, certBlob, status);
    if (ret != CMR_OK) {
        CM_LOG_E("Failed to get certificates info");
        ret = CMR_ERROR_STORAGE;
        goto cleanup;
    }

cleanup:
    CmFreeCaFileNames(&fileNames);
    return ret;
}

static int32_t CertManagerFreeTrustedCertificatesList(struct CmBlob *certificateList)
{
    uint32_t i;
    int32_t ret = CMR_OK;
    struct CmMutableBlob *certificateDataList = NULL;

    if (certificateList == NULL) {
        CM_LOG_E("Failed to CMFree certificateList");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    certificateDataList = (struct CmMutableBlob *)certificateList->data;
    if (certificateDataList == NULL) {
        CM_LOG_E("CertificateList data is null");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    for (i = 0; i < certificateDataList->size; i++) {
        if (certificateDataList[i].data == NULL) {
            CM_LOG_E("Corrupted data in certificate list");
            ret = CMR_ERROR_NOT_FOUND;
        } else {
            CMFree(certificateDataList[i].data);
            certificateDataList[i].data = NULL;
            certificateDataList[i].size = 0;
        }
    }

    CMFree(certificateList->data);
    certificateList->data = NULL;

    return ret;
}

static int32_t InitParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramcount)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != CMR_OK) {
        CM_LOG_E("HksInitParamSet failed");
        return ret;
    }

    ret = HksAddParams(*paramSet, params, paramcount);
    if (ret != CMR_OK) {
        CM_LOG_E("HksAddParams failed");
        return ret;
    }

    ret = HksBuildParamSet(paramSet);
    if (ret != CMR_OK) {
        CM_LOG_E("HksBuildParamSet failed");
        return ret;
    }

    return ret;
}

static int32_t NameHash(struct HksBlob *subjectName, struct CmMutableBlob *nameDigest)
{
    if ((nameDigest == NULL) || (nameDigest->data == NULL) || (nameDigest->size < NAME_DIGEST_SIZE)) {
        CM_LOG_E("Invalid parameter");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    int32_t ret = CMR_OK;

    struct HksParam hashParam = {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_MD5
    };
    struct HksParamSet *hashParamSet;
    ret = InitParamSet(&hashParamSet, &hashParam, sizeof(hashParam) / sizeof(struct HksParam));
    if (ret != CMR_OK) {
        ret = CMR_ERROR;
        goto cleanup;
    }

    uint8_t hashBuff[CERT_MANAGER_MD5_SIZE];
    struct HksBlob hash = { sizeof(hashBuff), hashBuff};
    struct HksBlob tmp = HKS_BLOB(subjectName);
    ret = HksHash(hashParamSet, &tmp, &hash);
    if (ret != CMR_OK) {
        ret = CMR_ERROR;
        goto cleanup;
    }
    nameDigest->size = NAME_DIGEST_SIZE;
    if (sprintf_s((char*)nameDigest->data, MAX_NAME_PREFIX, "%02x%02x%02x%02x",
        hashBuff[3], hashBuff[2], hashBuff[1], hashBuff[0]) < 0) { /* 2 3 is array index */
            ret = CMR_ERROR;
            goto cleanup;
        }

cleanup:
    if (hashParamSet != NULL) {
        HksFreeParamSet(&hashParamSet);
    }
    return ret;
}

static int32_t NameHashFromAsn1(const struct CmAsn1Obj *subject, struct CmMutableBlob *nameDigest)
{
    if (subject == NULL) {
        CM_LOG_E("NULL pointer error");
        return CMR_ERROR_NULL_POINTER;
    }

    uint8_t nameBuf[subject->header.size + subject->value.size];
    struct HksBlob subjectName = {sizeof(nameBuf), nameBuf};
    int32_t ret = memcpy_s(nameBuf, sizeof(nameBuf), subject->header.data, subject->header.size);
    if (ret != EOK) {
        CM_LOG_E("Memory copy failed");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    ret = memcpy_s(nameBuf + subject->header.size, sizeof(nameBuf) - subject->header.size,
        subject->value.data, subject->value.size);
    if (ret != EOK) {
        CM_LOG_E("Memory copy failed");
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    return NameHash(&subjectName, nameDigest);
}

static int32_t CmGetFilenames(const struct CmContext *context, struct CmMutableBlob *pathBlob,
    uint32_t store, struct CmMutableBlob *fileNames, const char *path)
{
    int32_t ret = CmGetFilePath(context, store, pathBlob);
    if (ret != CMR_OK) {
        CM_LOG_E("Failed obtain path for store %x", store);
        return CMR_ERROR;
    }

    struct CmBlob uri[MAX_COUNT_CERTIFICATE];
    uint32_t len = MAX_COUNT_CERTIFICATE * sizeof(struct CmBlob);
    (void)memset_s(uri, len, 0, len);
    if (CertManagerGetFilenames(fileNames, path, uri) < 0) {
        CM_LOG_E("Failed to read certificates from directory: %s\n", path);
        ret = CMR_ERROR_STORAGE;
    }

    CmFreeFileNameUri(uri, MAX_COUNT_CERTIFICATE);

    return ret;
}

static int32_t CmDifferentiateStore(const struct CmContext *context, const struct CmBlob *certificate,
    uint32_t store, uint32_t *status)
{
    if (store != CM_CREDENTIAL_STORE) {
    int32_t ret = CertManagerGetCertificatesStatus(context, certificate, store, status);
        if (ret != CMR_OK) {
            CM_LOG_E("Failed to CertManagerGetCertificatesStatus");
            return CMR_ERROR_READ_FILE_ERROR;
        }
    }
    return CMR_OK;
}

static int32_t CmGetMatchedFileNameIndex(const struct CmContext *context, const struct CmBlob *nameDigest,
    const struct CmMutableBlob *fileNames, struct CmMathedIndexPara indexPara)
{
    uint32_t i;
    uint32_t fileSize;
    int32_t ret;
    uint8_t certBuff[CERT_MANAGER_MAX_CERT_SIZE];
    struct CmBlob certificate;
    uint32_t store = indexPara.store;
    char *path = indexPara.path;
    uint32_t *status = indexPara.status;
    uint8_t *indexes = indexPara.indexes;
    uint32_t *count = indexPara.count;
    struct CmMutableBlob *fname = (struct CmMutableBlob *)fileNames->data;

    for (i = 0; i < fileNames->size; i++) {
        if (memcmp(fname[i].data, nameDigest->data, nameDigest->size) == 0) {
            fileSize = CmFileRead(path, (char *)fname[i].data, 0, certBuff, sizeof(certBuff));
            if (fileSize == 0) {
                CM_LOG_E("Failed to read file: %s/%s", path, fname[i].data);
                return CMR_ERROR_READ_FILE_ERROR;
            }

            certificate.data = certBuff;
            certificate.size = fileSize;
            ret = CmDifferentiateStore(context, &certificate, store, status);
            if (ret != CMR_OK) {
                CM_LOG_E("Failed to CmDifferentiateStore");
                return CMR_ERROR_READ_FILE_ERROR;
            }
            indexes[*count] = i;
            (*count)++;
        }
    }
    return CMR_OK;
}

static int32_t CmGetMatchedFileNames(struct CmMutableBlob *matchName, const struct CmMutableBlob *fname,
    uint32_t count, uint8_t *indexes)
{
    uint32_t i;
    uint32_t index;
    if (matchName == NULL || fname == NULL || indexes == NULL) {
        CM_LOG_E("Paramset is NULL");
        return CMR_ERROR_NULL_POINTER;
    }

    for (i = 0; i < count; i++) {
        index = indexes[i];
        matchName[i].size = fname[index].size + 1;
        matchName[i].data = malloc(matchName[i].size);
        if (matchName[i].data == NULL) {
            CM_LOG_E("Failed to allocate memory for filename: %s", fname[index].data);
            return CMR_ERROR_MALLOC_FAIL;
        }

        if (strcpy_s((char *)matchName[i].data, (size_t)matchName[i].size, (char*)fname[index].data) != EOK) {
            CM_LOG_E("strcpy_s failed for: %s", fname[index].data);
            return CMR_ERROR_BUFFER_TOO_SMALL;
        }
    }
    return CMR_OK;
}

static int32_t CmInitFileNameIndexArray(uint8_t **indexes, struct CmMutableBlob fileNames)
{
    uint8_t *fileNameIndex = (uint8_t *)malloc(fileNames.size);
    if (fileNameIndex == NULL) {
        CM_LOG_E("Failed to allocate memory for indexes");
        return CMR_ERROR_MALLOC_FAIL;
    }

    if (memset_s(fileNameIndex, fileNames.size, 0, fileNames.size) != EOK) {
        CM_LOG_E("Failed to memset memory");
        return CMR_ERROR;
    }

    *indexes = fileNameIndex;

    return CMR_OK;
}

static void CmFreeCertificatesInfo(struct CmMutableBlob *fileNames, struct CmMutableBlob *matchingFiles,
    uint8_t *indexes, struct CmBlob *certificateList, int32_t retVal)
{
    CmFreeCaFileNames(fileNames);
    CmFreeCaFileNames(matchingFiles);
    CMFree(indexes);
    if (retVal != CMR_OK) {
        CertManagerFreeTrustedCertificatesList(certificateList);
    }
}

int32_t CmGetCertificatesByUri(const struct CmContext *context, struct CmBlob *certificateList,
    uint32_t store, const struct CmBlob *nameDigest, uint32_t *status)
{
    int32_t retVal = 0;
    uint32_t count = 0;
    uint8_t *indexes = NULL;
    char path[CERT_MAX_PATH_LEN];
    struct CmMutableBlob pathBlob = {sizeof(path), (uint8_t *)path};
    struct CmMutableBlob fileNames = {0, NULL}, matchingFiles = {0, NULL};

    retVal = CmGetFilenames(context, &pathBlob, store, &fileNames, path);
    if (retVal != CMR_OK) {
        CM_LOG_E("Failed to get file names");
        return retVal;
    }
    if (CmInitFileNameIndexArray(&indexes, fileNames) != CMR_OK) {
        CM_LOG_E("Failed to init file name indexes arrary");
        retVal = CMR_ERROR_MALLOC_FAIL;
        goto cleanup;
    }

    struct CmMathedIndexPara indexPara = {path, store, status, &count, indexes};
    if (CmGetMatchedFileNameIndex(context, nameDigest, &fileNames, indexPara) != EOK) {
        CM_LOG_E("GetCertificatesByUri Failed to get matched file name indexes");
        retVal = CMR_ERROR;
        goto cleanup;
    }

    matchingFiles.size = count;
    matchingFiles.data = malloc(sizeof(struct CmMutableBlob) * count);
    if (matchingFiles.data == NULL) {
        CM_LOG_E("GetCertificatesByUri Failed to allocate memory for files");
        retVal = CMR_ERROR_MALLOC_FAIL;
        goto cleanup;
    }

    struct CmMutableBlob *fname = (struct CmMutableBlob *)fileNames.data;
    struct CmMutableBlob *matchName = (struct CmMutableBlob *)matchingFiles.data;
    if (CmGetMatchedFileNames(matchName, fname, count, indexes) != EOK) {
        CM_LOG_E("GetCertificatesByUri Failed to get matched file Name indexes");
        retVal = CMR_ERROR;
        goto cleanup;
    }

    if (CmCreateCertificateList(certificateList, &matchingFiles, path) < 0) {
        CM_LOG_E("GetCertificatesByUri Failed to create certificates: %s", path);
        retVal = CMR_ERROR_STORAGE;
        goto cleanup;
    }

cleanup:
    CmFreeCertificatesInfo(&fileNames, &matchingFiles, indexes, certificateList, retVal);
    return retVal;
}

static int32_t CmGetMatchedFileSubjectNameIndex(const struct CmMutableBlob *nameDigest,
    const struct CmMutableBlob *fileNames, const struct CmAsn1Obj *subjectName, struct CmMathedIndexPara indexPara)
{
    uint32_t i;
    struct CmAsn1Obj subjectFromList;
    uint8_t certBuff[CERT_MANAGER_MAX_CERT_SIZE];
    struct CmBlob certificate = {sizeof(certBuff), certBuff};
    char *path = indexPara.path;
    uint8_t *indexes = indexPara.indexes;
    uint32_t *count = indexPara.count;
    struct CmMutableBlob *fname = (struct CmMutableBlob *)fileNames->data;

    (void)memset_s(&subjectFromList, sizeof(struct CmAsn1Obj), 0, sizeof(struct CmAsn1Obj));
    for (i = 0; i < fileNames->size; i++) {
        if (memcmp(fname[i].data, nameDigest->data, nameDigest->size) == 0) {
            if (CmFileRead(path, (char *)fname[i].data, 0, certBuff, sizeof(certBuff)) == 0) {
                CM_LOG_E("Failed to read file: %s/%s", path, fname[i].data);
                return CMR_ERROR_READ_FILE_ERROR;
            }

            if (CmGetSubjectNameAsn1(&certificate, &subjectFromList) != CMR_OK) {
                CM_LOG_E("Failed to obtain subjectName");
                return CMR_ERROR_NOT_FOUND;
            }
            if ((subjectName->value.size == subjectFromList.value.size) ||
                (memcmp(subjectName->value.data, subjectFromList.value.data, subjectName->value.size))) {
                indexes[*count] = i;
                count++;
            }
        }
    }
    return  CMR_OK;
}

static int32_t CmListCertificatesBySubjectNameAsn1(const struct CmContext *context,
    struct CmBlob *certificateList, uint32_t store, const struct CmAsn1Obj *subjectName)
{
    int32_t retVal = 0;
    uint32_t count = 0;
    uint8_t *indexes = NULL;
    uint32_t *status = NULL;
    struct CmMutableBlob fileNames = {0, NULL}, matchingFiles = {0, NULL};
    char path[CERT_MAX_PATH_LEN];
    uint8_t buff[MAX_NAME_DIGEST_LEN];
    struct CmMutableBlob nameDigest = {sizeof(buff), buff}, pathBlob = {sizeof(path), (uint8_t *)path};

    retVal = NameHashFromAsn1(subjectName, &nameDigest);
    if (retVal != CMR_OK) {
        return retVal;
    }

    if (CmGetFilenames(context, &pathBlob, store, &fileNames, path) != CMR_OK) {
        return CMR_ERROR_STORAGE;
    }

    if (CmInitFileNameIndexArray(&indexes, fileNames) != CMR_OK) {
        retVal = CMR_ERROR_MALLOC_FAIL;
        goto cleanup;
    }

    struct CmMathedIndexPara indexPara = {path, store, status, &count, indexes};
    if (CmGetMatchedFileSubjectNameIndex(&nameDigest, &fileNames, subjectName, indexPara) != CMR_OK) {
        CM_LOG_E("Failed to get matched file name indexes");
        retVal = CMR_ERROR;
        goto cleanup;
    }

    matchingFiles.size = count;
    matchingFiles.data = malloc(sizeof(struct CmMutableBlob) * count);
    if (matchingFiles.data == NULL) {
        CM_LOG_E("Failed to allocate memory for files");
        retVal = CMR_ERROR_MALLOC_FAIL;
        goto cleanup;
    }

    struct CmMutableBlob *fname = (struct CmMutableBlob *)fileNames.data;
    struct CmMutableBlob *matchName = (struct CmMutableBlob *)matchingFiles.data;

    if (CmGetMatchedFileNames(matchName, fname, count, indexes) != CMR_OK) {
        CM_LOG_E("Failed to get matched file Name indexes");
        retVal = CMR_ERROR;
        goto cleanup;
    }

    if (CmCreateCertificateList(certificateList, &matchingFiles, path) < 0) {
        CM_LOG_E("Failed to create certificates: %s", path);
        retVal = CMR_ERROR_STORAGE;
        goto cleanup;
    }

cleanup:
    CmFreeCertificatesInfo(&fileNames, &matchingFiles, indexes, certificateList, retVal);
    return retVal;
}

int32_t CertManagerListCertificatesBySubjectName(const struct CmContext *context,
    struct CmBlob *certificateList, uint32_t store, const struct CmBlob *subjectName)
{
    struct CmAsn1Obj subjectAsn1;
    struct CmBlob skip = {0, NULL};
    errno_t ret;

    (void)memset_s(&subjectAsn1, sizeof(struct CmAsn1Obj), 0, sizeof(struct CmAsn1Obj));
    ret = CmAsn1ExtractTag(&skip, &subjectAsn1, &CM_BLOB(subjectName), ASN_1_TAG_TYPE_SEQ);
    if (ret != CMR_OK) {
        CM_LOG_E("Subject name in bad format");
        return CMR_ERROR_NOT_FOUND;
    }
    return CmListCertificatesBySubjectNameAsn1(context, certificateList, store, &subjectAsn1);
}

/* This function constructes md5 hash part of filename for storing certificate.
 * All cetificates are stored in files namePrefix.count. where namePrefix = md5(subjectName)
 * and count is = 0, 1.... needed fpr potential hash collisions.
 */
static int32_t CertManagerGetFileNamePrefix(const struct CmBlob *certificate, struct CmMutableBlob *namePrefix)
{
    struct CmAsn1Obj subjectAsn1;

    (void)memset_s(&subjectAsn1, sizeof(struct CmAsn1Obj), 0, sizeof(struct CmAsn1Obj));
    int32_t retVal = CmGetSubjectNameAsn1(certificate, &subjectAsn1);
    if (retVal != CMR_OK) {
        CM_LOG_E("Failed to obtain subjectName");
        return CMR_ERROR_NOT_FOUND;
    }
    /* Compute name prefix for the certificate */
    return NameHashFromAsn1(&subjectAsn1, namePrefix);
}

int32_t CertManagerFindCertFileNameByUri(const struct CmContext *context, const struct CmBlob *certUri,
    uint32_t store, struct CmMutableBlob *path)
{
    ASSERT_ARGS(context && certUri && certUri->data);
    int32_t ret = CMR_ERROR_NOT_FOUND;
    struct CmMutableBlob *fNames = NULL;
    struct CmMutableBlob fileNames = {0, NULL};
    struct CmBlob uri[MAX_COUNT_CERTIFICATE];

    if (CmGetFilePath(context, store, path) != CMR_OK) {
        CM_LOG_E("Failed obtain path for store %x\n", store);
        return CMR_ERROR;
    }

    uint32_t len = MAX_COUNT_CERTIFICATE * sizeof(struct CmBlob);
    (void)memset_s(uri, len, 0, len);
    if (CertManagerGetFilenames(&fileNames, (char*)path->data, uri) < 0) {
        CM_LOG_E("Failed obtain filenames from path: %s", (char *)path->data);
        ret = CMR_ERROR_STORAGE;
        goto cleanup;
    }

    fNames = (struct CmMutableBlob *)fileNames.data;

    for (uint32_t i = 0; i < fileNames.size; i++) {
        if (fNames[i].data == NULL) {
            CM_LOG_E("Corrupted file name at index: %u", i);
            ret = CMR_ERROR_STORAGE;
            goto cleanup;
        }
        /* Check if url is matching with the cert filename */
        if ((certUri->size <= fNames[i].size) && (memcmp(certUri->data, fNames[i].data, certUri->size) == 0)) {
            ret = CMR_OK;
            break;
        }
    }

cleanup:
    CmFreeFileNameUri(uri, MAX_COUNT_CERTIFICATE);
    if (fileNames.data != NULL) {
        (void)CmFreeCaFileNames(&fileNames);
    }

    return ret;
}

static int32_t GetMathedCertificateFileName(const struct CmBlob *certificate, const struct CmMutableBlob *fNames,
    const struct CmMutableBlob *path, struct CmMutableBlob *fileName, uint32_t index)
{
    uint32_t fsize;
    int32_t ret = CMR_ERROR;
    uint8_t certBuff[CERT_MANAGER_MAX_CERT_SIZE] = {0};

    fsize = CertManagerFileRead((char *)path->data, (char *)fNames[index].data, 0, certBuff, sizeof(certBuff));
    if (fsize == 0) {
        CM_LOG_E("Failed to read file: %s/%s", (char *)path->data, fNames[index].data);
        return CMR_ERROR_READ_FILE_ERROR;
    }

    /* Verify that this file contains certificate to be removed. i.e. we don't just have hash collision */
    if ((certificate->size == fsize) && (memcmp(certificate->data, certBuff, fsize) == 0)) {
        CM_LOG_I("Matching certificate found: %s\n", (char*)fNames[index].data);
        /* this is the certificate, return the filename */
        if (fileName->size < fNames[index].size + 1) {
            /* shouldn't happen */
            CM_LOG_E("File name buffer too small");
            ret = CMR_ERROR_READ_FILE_ERROR;
        }

        if (memcpy_s(fileName->data, fileName->size, fNames[index].data, fNames[index].size) != EOK) {
            CM_LOG_E("Failed to copy file name.\n");
            ret = CMR_ERROR;
        } else {
            fileName->data[fNames[index].size] = '\0';
            fileName->size = fNames[index].size;
            ret = CMR_OK;
        }
    }
    return ret;
}

static int32_t FindCertFileName(const struct CmMutableBlob *fileNames,  const struct CmBlob *certificate,
    struct CmMutableBlob nameDigest, const struct CmMutableBlob *path, struct CmMutableBlob *fileName)
{
    uint32_t i;
    int32_t retVal = CMR_ERROR_NOT_FOUND;
    struct CmMutableBlob *fNames = (struct CmMutableBlob *)fileNames->data;

    for (i = 0; i < fileNames->size; i++) {
        if (fNames[i].data == NULL) {
            CM_LOG_E("Corrupted file name at index: %u", i);
            retVal = CMR_ERROR_STORAGE;
        }
        /* Check if file content is matching with the certificate */
        if ((nameDigest.size < fNames[i].size) && (memcmp(nameDigest.data, fNames[i].data, nameDigest.size) == 0)) {
            retVal = GetMathedCertificateFileName(certificate, fNames, path, fileName, i);
            if (retVal != CMR_OK) {
                CM_LOG_E("Failed to get matched file");
            } else {
                break;
            }
        }
    }
    return retVal;
}

int32_t CertManagerFindCertFileName(const struct CmContext *context, const struct CmBlob *certificate,
    uint32_t store, struct CmMutableBlob *path, struct CmMutableBlob *fileName)
{
    ASSERT_ARGS(context && certificate && fileName);
    struct CmMutableBlob fileNames = {0, NULL};
    struct CmBlob uri[MAX_COUNT_CERTIFICATE];
    uint8_t namePrefix[MAX_NAME_PREFIX] = {0};
    struct CmMutableBlob nameDigest = {sizeof(namePrefix), namePrefix};
    /* Compute name prefix for the certificate */
    int32_t ret = CertManagerGetFileNamePrefix(certificate, &nameDigest);
    if (ret != CMR_OK) {
        CM_LOG_E("Failed to compute for removed certificate");
        return ret;
    }

    do {
        if (CmGetFilePath(context, store, path) != CMR_OK) {
            CM_LOG_E("Failed obtain path for store %u", store);
            ret = CMR_ERROR;
            break;
        }
        uint32_t len = MAX_COUNT_CERTIFICATE * sizeof(struct CmBlob);
        (void)memset_s(uri, len, 0, len);
        if (CertManagerGetFilenames(&fileNames, (char *)path->data, uri) < 0) {
            CM_LOG_E("Failed obtain filenames from path: %s", (char *)path->data);
            ret = CMR_ERROR_STORAGE;
            break;
        }

        ret = FindCertFileName(&fileNames, certificate, nameDigest, path, fileName);
        if (ret != CMR_OK) {
            CM_LOG_E("Failed find files");
            break;
        }
    } while (0);

    CmFreeFileNameUri(uri, MAX_COUNT_CERTIFICATE);
    if (fileNames.data != NULL) {
        (void) CmFreeCaFileNames(&fileNames);
    }
    return ret;
}

int32_t CmRemoveAppCert(const struct CmContext *context, const struct CmBlob *keyUri,
    const uint32_t store)
{
    ASSERT_ARGS(context && keyUri && keyUri->data && keyUri->size);
    int32_t ret;
    char pathBuf[CERT_MAX_PATH_LEN] = {0};
    struct CmMutableBlob path = { sizeof(pathBuf), (uint8_t*) pathBuf };

    ret = CmGetFilePath(context, store, &path);
    if (ret != CMR_OK) {
        CM_LOG_E("Failed obtain path for store %u", store);
        return ret;
    }

    ret = CertManagerFileRemove(pathBuf, (char *)keyUri->data);
    if (ret != CMR_OK) {
        CM_LOG_E("CertManagerFileRemove failed ret: %d", ret);
        return ret;
    }
    /* ignore the return of HksDeleteKey */
    ret = HksDeleteKey(&HKS_BLOB(keyUri), NULL);
    if (ret != HKS_SUCCESS && ret != HKS_ERROR_NOT_EXIST) {
        CM_LOG_I("CertManagerKeyRemove failed, ret: %d", ret);
    }

    return CMR_OK;
}

static int32_t CmAppCertGetFilePath(const struct CmContext *context, const uint32_t store, struct CmBlob *path)
{
    int32_t ret = CM_FAILURE;

    switch (store) {
        case CM_CREDENTIAL_STORE :
            ret = sprintf_s((char*)path->data, MAX_PATH_LEN, "%s%u", CREDNTIAL_STORE, context->userId);
            break;
        case CM_PRI_CREDENTIAL_STORE :
            ret = sprintf_s((char*)path->data, MAX_PATH_LEN, "%s%u", APP_CA_STORE, context->userId);
            break;
        default:
            break;
    }
    if (ret < 0) {
        return CM_FAILURE;
    }
    return CM_SUCCESS;
}

void CmFreeFileNames(struct CmBlob *fileNames, const uint32_t fileSize)
{
    if (fileNames == NULL) {
        CM_LOG_E("CmFreeFileNames fileNames is null");
    }

    for (uint32_t i = 0; i < fileSize; i++) {
        if (fileNames[i].data != NULL) {
            CMFree(fileNames[i].data);
            fileNames[i].size = 0;
        }
    }
}

int32_t CmGetUri(const char *filePath, struct CmBlob *uriBlob)
{
    uint32_t i;
    if ((filePath == NULL) || (uriBlob == NULL) || (uriBlob->data == NULL)) {
        CM_LOG_E("CmGetUri param is null");
        return CM_FAILURE;
    }

    uint32_t filePathLen = strlen(filePath);
    if (filePathLen == 0) {
        return CM_FAILURE;
    }

    for (i = filePathLen - 1; i >= 0; i--) {
        if (filePath[i] == '/') {
            break;
        }
    }

    uint32_t uriLen = filePathLen - i - 1;
    if ((uriLen == 0) || (memcpy_s(uriBlob->data, MAX_LEN_URI, &filePath[i + 1], uriLen) != EOK)) {
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    uriBlob->size = uriLen;

    return CM_SUCCESS;
}

static int32_t CmRemoveSpecifiedAppCert(const struct CmContext *context, const uint32_t store)
{
    uint32_t fileCount = 0;
    int32_t retCode, ret = CM_SUCCESS;
    char pathBuf[CERT_MAX_PATH_LEN] = {0};
    char uriBuf[MAX_LEN_URI] = {0};
    struct CmBlob fileNames[MAX_COUNT_CERTIFICATE];
    struct CmBlob path = { sizeof(pathBuf), (uint8_t*)pathBuf };
    struct CmBlob uriBlob = { sizeof(uriBuf), (uint8_t*)uriBuf };
    uint32_t len = MAX_COUNT_CERTIFICATE * sizeof(struct CmBlob);
    (void)memset_s(fileNames, len, 0, len);

    do {
        if (CmAppCertGetFilePath(context, store, &path) != CM_SUCCESS) {
            ret = CM_FAILURE;
            CM_LOG_E("Get file path for store:%u faild", store);
            break;
        }

        if (CmUserIdLayerGetFileCountAndNames(pathBuf, fileNames, MAX_COUNT_CERTIFICATE, &fileCount) != CM_SUCCESS) {
            ret = CM_FAILURE;
            CM_LOG_E("Get file count and names from path faild: %s", pathBuf);
            break;
        }

        CM_LOG_I("CmRemoveSpecifiedAppCert fileCount:%u", fileCount);

        for (uint32_t i = 0; i < fileCount; i++) {
            if (CertManagerFileRemove(NULL, (char *)fileNames[i].data) != CM_SUCCESS) {
                CM_LOG_E("App cert %u remove faild, ret: %d", i, ret);
                continue;
            }

            (void)memset_s(uriBuf, MAX_LEN_URI, 0, MAX_LEN_URI);
            if (CmGetUri((char *)fileNames[i].data, &uriBlob) != CM_SUCCESS) {
                CM_LOG_E("Get uri failed");
                continue;
            }

            CM_LOG_I("CmRemoveSpecifiedAppCert i:%d, uri:%s", i, (char *)uriBlob.data);

            /* ignore the return of HksDeleteKey */
            retCode = HksDeleteKey(&HKS_BLOB(&uriBlob), NULL);
            if (retCode != HKS_SUCCESS && retCode != HKS_ERROR_NOT_EXIST) {
                CM_LOG_I("App key %u remove failed ret: %d", i, ret);
            }
        }
    } while (0);

    CmFreeFileNames(fileNames, MAX_COUNT_CERTIFICATE);
    return ret;
}

int32_t CmRemoveAllAppCert(const struct CmContext *context)
{
    /* Only public and private credential removed can be returned */
    /* remove pubic credential app cert */
    int32_t ret = CmRemoveSpecifiedAppCert(context, CM_CREDENTIAL_STORE);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("remove pubic credential app cert faild");
    }

    /* remove private credential app cert */
    ret = CmRemoveSpecifiedAppCert(context, CM_PRI_CREDENTIAL_STORE);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("remove private credential app cert faild");
    }

    return ret;
}

void CmFreeFileNameUri(struct CmBlob *uri, uint32_t size)
{
    for (uint32_t i = 0; i < size; i++) {
        CM_FREE_BLOB(uri[i]);
    }
}

int32_t CmServiceGetAppCertList(const struct CmContext *context, uint32_t store, struct CmBlob *fileNames,
    const uint32_t fileSize, uint32_t *fileCount)
{
    char pathBuf[CERT_MAX_PATH_LEN] = {0};
    struct CmBlob path = { sizeof(pathBuf), (uint8_t*)pathBuf };

    if (store != CM_CREDENTIAL_STORE && store != CM_PRI_CREDENTIAL_STORE) {
        CM_LOG_E("Parm is invalid store:%u", store);
        return CM_FAILURE;
    }

    int32_t ret = CmAppCertGetFilePath(context, store, &path);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get file path for store:%u faild", store);
        return CM_FAILURE;
    }

    ret = CmUserIdLayerGetFileCountAndNames(pathBuf, fileNames, fileSize, fileCount);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Get file count and names from path faild ret:%d:path:%s", ret, pathBuf);
        return ret;
    }

    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif