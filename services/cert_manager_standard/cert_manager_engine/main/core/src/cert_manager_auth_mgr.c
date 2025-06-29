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

#include "cert_manager_auth_mgr.h"

#include <pthread.h>

#include "securec.h"

#include "cert_manager_auth_list_mgr.h"
#include "cert_manager_key_operation.h"
#include "cert_manager_mem.h"
#include "cert_manager_session_mgr.h"
#include "cert_manager_crypto_operation.h"
#include "cert_manager_uri.h"
#include "cert_manager_query.h"
#include "cm_log.h"
#include "cm_util.h"

#define MAC_SHA256_LEN 32

#define NUMBER_9_IN_DECIMAL 9
#define BYTE_TO_HEX_OPER_LENGTH 2
#define OUT_OF_HEX 16
#define DEC 10

static pthread_mutex_t g_authMgrLock = PTHREAD_MUTEX_INITIALIZER;

// LCOV_EXCL_START
static char HexToChar(uint8_t hex)
{
    return (hex > NUMBER_9_IN_DECIMAL) ? (hex + 0x37) : (hex + 0x30); /* Convert to the corresponding character */
}

static uint8_t CharToHex(char c)
{
    if ((c >= 'A') && (c <= 'F')) {
        return (c - 'A' + DEC);
    } else if ((c >= 'a') && (c <= 'f')) {
        return (c - 'a' + DEC);
    } else if ((c >= '0') && (c <= '9')) {
        return (c - '0');
    } else {
        return OUT_OF_HEX;
    }
}

static int32_t ByteToHexString(const uint8_t *byte, uint32_t byteLen, char *hexStr, uint32_t hexLen)
{
    if (hexLen < (byteLen * BYTE_TO_HEX_OPER_LENGTH + 1)) { /* The terminator('\0') needs 1 bit */
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    for (uint32_t i = 0; i < byteLen; ++i) {
        hexStr[i * BYTE_TO_HEX_OPER_LENGTH] = HexToChar((byte[i] & 0xF0) >> 4); /* 4: shift right for filling */
        hexStr[i * BYTE_TO_HEX_OPER_LENGTH + 1] = HexToChar(byte[i] & 0x0F); /* get low four bits */
    }
    hexStr[byteLen * BYTE_TO_HEX_OPER_LENGTH] = '\0';

    return CM_SUCCESS;
}

static int32_t HexStringToByte(const char *hexStr, uint8_t *byte, uint32_t byteLen)
{
    uint32_t realHexLen = strlen(hexStr);
    /* odd number or len too small */
    if ((realHexLen % BYTE_TO_HEX_OPER_LENGTH != 0) || (byteLen < realHexLen / BYTE_TO_HEX_OPER_LENGTH)) {
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    for (uint32_t i = 0; i < realHexLen / BYTE_TO_HEX_OPER_LENGTH; ++i) {
        uint8_t high = CharToHex(hexStr[i * BYTE_TO_HEX_OPER_LENGTH]);
        uint8_t low = CharToHex(hexStr[i * BYTE_TO_HEX_OPER_LENGTH + 1]);
        if ((high == OUT_OF_HEX) || (low == OUT_OF_HEX)) {
            return CMR_ERROR_INVALID_ARGUMENT_URI;
        }
        byte[i] = high << 4; /* 4: Set the high nibble */
        byte[i] |= low; /* Set the low nibble */
    }
    return CM_SUCCESS;
}

static int32_t GetAndCheckUriObj(struct CMUri *uriObj, const struct CmBlob *uri, uint32_t type)
{
    int32_t ret = CertManagerUriDecode(uriObj, (char *)uri->data);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uri decode failed, ret = %d", ret);
        return ret;
    }

    if ((uriObj->object == NULL) || (uriObj->user == NULL) || (uriObj->app == NULL) || (uriObj->type != type)) {
        CM_LOG_E("uri format invalid");
        (void)CertManagerFreeUri(uriObj);
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    return CM_SUCCESS;
}

static int32_t CheckCallerIsProducer(const struct CmContext *context, const struct CMUri *uriObj)
{
    /* check caller is Producer: user and app has been checked not null */
    uint32_t userId = 0;
    uint32_t uid = 0;
    if (CmIsNumeric(uriObj->user, strlen(uriObj->user) + 1, &userId) != CM_SUCCESS ||
        CmIsNumeric(uriObj->app, strlen(uriObj->app) + 1, &uid) != CM_SUCCESS) {
        CM_LOG_E("parse string to uint32 failed.");
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    if ((userId == context->userId) && (uid == context->uid)) {
        CM_LOG_D("caller is producer.");
        return CM_SUCCESS;
    }

    return CMR_ERROR_NOT_PERMITTED;
}

static int32_t UintToString(uint32_t input, char *out, uint32_t outLen)
{
    if (snprintf_s(out, outLen, outLen - 1, "%u", input) < 0) {
        return CMR_ERROR_MEM_OPERATION_PRINT;
    }
    return CM_SUCCESS;
}

static int32_t ConstructToBeAuthedUri(const struct CMUri *uriObj, uint32_t clientUid, struct CmBlob *toBeAuthedUri)
{
    struct CMUri uri;
    (void)memcpy_s(&uri, sizeof(uri), uriObj, sizeof(uri));

    char uidStr[MAX_UINT32_LEN] = { 0 };
    int32_t ret = UintToString(clientUid, uidStr, MAX_UINT32_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("construct client uid to string failed");
        return ret;
    }

    uri.clientApp = uidStr;
    uri.clientUser = NULL;
    uri.mac = NULL;

    return CmConstructUri(&uri, toBeAuthedUri);
}

static int32_t ConstructMacKeyUri(const struct CMUri *uriObj, uint32_t clientUid, struct CmBlob *macKeyUri)
{
    struct CMUri uri;
    (void)memcpy_s(&uri, sizeof(uri), uriObj, sizeof(uri));

    char uidStr[MAX_UINT32_LEN] = { 0 };
    int32_t ret = UintToString(clientUid, uidStr, MAX_UINT32_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("construct client uid to string failed");
        return ret;
    }

    uri.type = CM_URI_TYPE_MAC_KEY; /* type is 'm' */
    uri.clientApp = uidStr;
    uri.clientUser = NULL;
    uri.mac = NULL;

    return CmConstructUri(&uri, macKeyUri);
}

static int32_t ConstructCommonUri(const struct CMUri *uriObj, struct CmBlob *commonUri, uint32_t store)
{
    struct CMUri uri;
    (void)memcpy_s(&uri, sizeof(uri), uriObj, sizeof(uri));

    if (store != CM_SYS_CREDENTIAL_STORE) {
        uri.type = CM_URI_TYPE_APP_KEY; /* type is 'ak' */
    } else {
        uri.type = CM_URI_TYPE_SYS_KEY; /* type is 'sk' */
    }

    uri.clientApp = NULL;
    uri.clientUser = NULL;
    uri.mac = NULL;

    return CmConstructUri(&uri, commonUri);
}
static int32_t CalcUriMac(const struct CMUri *uriObj, uint32_t clientUid, struct CmBlob *mac,
    bool isNeedGenKey, enum CmAuthStorageLevel level)
{
    struct CmBlob toBeAuthedUri = { 0, NULL };
    struct CmBlob macKeyUri = { 0, NULL };
    int32_t ret;

    do {
        /* construct to be authed URI */
        ret = ConstructToBeAuthedUri(uriObj, clientUid, &toBeAuthedUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("construct to be authed uri failed, ret = %d", ret);
            break;
        }

        /* construct mac key URI */
        ret = ConstructMacKeyUri(uriObj, clientUid, &macKeyUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("construct mac key uri, ret = %d", ret);
            break;
        }

        if (isNeedGenKey) {
            ret = CmKeyOpGenMacKey(&macKeyUri, level);
            if (ret != CM_SUCCESS) {
                CM_LOG_E("generate mac key failed, ret = %d", ret);
                break;
            }
        }

        ret = CmKeyOpCalcMac(&macKeyUri, &toBeAuthedUri, mac, level);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("calc mac failed, ret = %d", ret);
            break;
        }
    } while (0);

    CM_FREE_PTR(toBeAuthedUri.data);
    CM_FREE_PTR(macKeyUri.data);
    return ret;
}

static int32_t DeleteMacKey(const struct CMUri *uriObj, uint32_t clientUid, enum CmAuthStorageLevel level)
{
    struct CmBlob macKeyUri = { 0, NULL };
    int32_t ret;

    do {
        /* construct mac key URI */
        ret = ConstructMacKeyUri(uriObj, clientUid, &macKeyUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("construct mac key uri, ret = %d", ret);
            break;
        }

        ret = CmKeyOpDeleteKey(&macKeyUri, level);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("delete mac key failed, ret = %d", ret);
            break;
        }

        ret = CM_SUCCESS; /* ret is success if key not exist */
    } while (0);

    CM_FREE_PTR(macKeyUri.data);
    return ret;
}


static int32_t ConstructAuthUri(const struct CMUri *uriObj, uint32_t clientUid, const struct CmBlob *mac,
    struct CmBlob *authUri)
{
    struct CMUri uri;
    (void)memcpy_s(&uri, sizeof(uri), uriObj, sizeof(uri));

    char uidStr[MAX_UINT32_LEN] = { 0 };
    int32_t ret = UintToString(clientUid, uidStr, MAX_UINT32_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("construct client uid to string failed");
        return ret;
    }

    uint32_t macHexLen = mac->size * BYTE_TO_HEX_OPER_LENGTH + 1;
    char *macHex = (char *)CMMalloc(macHexLen);
    if (macHex == NULL) {
        CM_LOG_E("malloc mac hex buffer failed");
        return CMR_ERROR_MALLOC_FAIL;
    }

    ret = ByteToHexString(mac->data, mac->size, macHex, macHexLen);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("byte to hex string failed, ret = %d", ret);
        CMFree(macHex);
        return ret;
    }

    uri.clientApp = uidStr;
    uri.clientUser = NULL;
    uri.mac = macHex;

    ret = CmConstructUri(&uri, authUri);
    CMFree(macHex);
    return ret;
}

static int32_t GenerateAuthUri(const struct CMUri *uriObj, uint32_t clientUid,
    struct CmBlob *authUri, enum CmAuthStorageLevel level)
{
    struct CmBlob tempAuthUri = { 0, NULL };
    int32_t ret;
    do {
        /* calc uri mac */
        uint8_t macData[MAC_SHA256_LEN] = {0};
        struct CmBlob mac = { sizeof(macData), macData };
        ret = CalcUriMac(uriObj, clientUid, &mac, true, level);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("calc uri mac failed, ret = %d", ret);
            break;
        }

        /* construct auth URI */
        ret = ConstructAuthUri(uriObj, clientUid, &mac, &tempAuthUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("construct auth uri failed, ret = %d", ret);
            break;
        }

        if (authUri->size < tempAuthUri.size) {
            CM_LOG_E("auth uri out size[%u] too small, need at least[%u]", authUri->size, tempAuthUri.size);
            ret = CMR_ERROR_BUFFER_TOO_SMALL;
            break;
        }
        if (memcpy_s(authUri->data, authUri->size, tempAuthUri.data, tempAuthUri.size) != EOK) {
            CM_LOG_E("copy auth uri failed");
            ret = CMR_ERROR_MEM_OPERATION_COPY;
            break;
        }
        authUri->size = tempAuthUri.size;
        ret = CM_SUCCESS;
    } while (0);

    CM_FREE_PTR(tempAuthUri.data);
    return ret;
}

int32_t CmAuthGrantAppCertificate(const struct CmContext *context, const struct CmBlob *keyUri,
    uint32_t appUid, struct CmBlob *authUri)
{
    pthread_mutex_lock(&g_authMgrLock);
    int32_t ret = CmCheckCredentialExist(context, keyUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("credential not exist when grant auth, ret = %d", ret);
        pthread_mutex_unlock(&g_authMgrLock);
        return ret;
    }

    struct CMUri uriObj;
    (void)memset_s(&uriObj, sizeof(uriObj), 0, sizeof(uriObj));
    ret = GetAndCheckUriObj(&uriObj, keyUri, CM_URI_TYPE_APP_KEY);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uri decode failed, ret = %d", ret);
        pthread_mutex_unlock(&g_authMgrLock);
        return ret;
    }

    do {
        enum CmAuthStorageLevel level;
        ret = GetRdbAuthStorageLevel(keyUri, &level);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get rdb auth storage level failed, ret = %d", ret);
            break;
        }
        if (level == ERROR_LEVEL) {
            level = CM_AUTH_STORAGE_LEVEL_EL1;
            CM_LOG_I("grant level is ERROR_LEVEL, change to default level el1");
        }

        ret = CheckCallerIsProducer(context, &uriObj);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("check caller userId/uid failed when grant, ret = %d", ret);
            break;
        }

        /* auth URI */
        ret = GenerateAuthUri(&uriObj, appUid, authUri, level);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("construct auth URI failed, ret = %d", ret);
            break;
        }

        /* add auth uid */
        ret = CmAddAuthUid(context, keyUri, appUid);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("add auth uid to auth list failed, ret = %d", ret);
            break;
        }
    } while (0);

    pthread_mutex_unlock(&g_authMgrLock);
    if (ret != CM_SUCCESS) {
        (void)CmAuthRemoveGrantedApp(context, keyUri, appUid); /* clear auth info */
    }
    (void)CertManagerFreeUri(&uriObj);
    return ret;
}

int32_t CmAuthGetAuthorizedAppList(const struct CmContext *context, const struct CmBlob *keyUri,
    struct CmAppUidList *appUidList)
{
    pthread_mutex_lock(&g_authMgrLock);
    struct CMUri uriObj;
    (void)memset_s(&uriObj, sizeof(uriObj), 0, sizeof(uriObj));
    int32_t ret = GetAndCheckUriObj(&uriObj, keyUri, CM_URI_TYPE_APP_KEY);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uri decode failed, ret = %d", ret);
        pthread_mutex_unlock(&g_authMgrLock);
        return ret;
    }

    struct CmAppUidList tempAppUidList = { 0, NULL };
    do {
        ret = CheckCallerIsProducer(context, &uriObj);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("check caller userId/uid failed, ret = %d", ret);
            break;
        }

        ret = CmGetAuthList(context, keyUri, &tempAppUidList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get auth list failed, ret = %d", ret);
            break;
        }

        if (tempAppUidList.appUidCount != 0) {
            if (appUidList->appUidCount < tempAppUidList.appUidCount) {
                CM_LOG_E("out auth list buffer too small, input[%u] < expect[%u]",
                    appUidList->appUidCount, tempAppUidList.appUidCount);
                ret = CMR_ERROR_BUFFER_TOO_SMALL;
                break;
            }
            if (memcpy_s(appUidList->appUid, appUidList->appUidCount * sizeof(uint32_t),
                tempAppUidList.appUid, tempAppUidList.appUidCount * sizeof(uint32_t)) != EOK) {
                ret = CMR_ERROR_MEM_OPERATION_COPY;
                break;
            }
        }
        appUidList->appUidCount = tempAppUidList.appUidCount;
        ret = CM_SUCCESS;
    } while (0);

    CM_FREE_PTR(tempAppUidList.appUid);
    (void)CertManagerFreeUri(&uriObj);
    pthread_mutex_unlock(&g_authMgrLock);
    return ret;
}

static int32_t GetMacByteFromString(const char *macString, struct CmBlob *macByte)
{
    uint32_t size = strlen(macString) / BYTE_TO_HEX_OPER_LENGTH;
    if ((size == 0) || (size > MAX_OUT_BLOB_SIZE)) {
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    uint8_t *data = (uint8_t *)CMMalloc(size);
    if (data  == NULL) {
        CM_LOG_E("malloc mac in byte failed");
        return CMR_ERROR_MALLOC_FAIL;
    }

    int32_t ret = HexStringToByte(macString, data, size);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("mac hex string to byte failed, ret = %d", ret);
        CM_FREE_PTR(data);
        return ret;
    }

    macByte->data = data;
    macByte->size = size;
    return CM_SUCCESS;
}

static int32_t CheckIsAuthorizedApp(const struct CMUri *uriObj, enum CmAuthStorageLevel level)
{
    if ((uriObj->clientApp == NULL) || (uriObj->mac == NULL)) {
        CM_LOG_E("invalid input auth uri");
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    struct CmBlob macByte = { 0, NULL };
    int32_t ret = GetMacByteFromString(uriObj->mac, &macByte);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get mac byte from string failed, ret = %d", ret);
        return ret;
    }

    /* calc uri mac */
    uint8_t macData[MAC_SHA256_LEN] = {0};
    struct CmBlob mac = { sizeof(macData), macData };
    uint32_t clientUid = 0;
    if (CmIsNumeric(uriObj->clientApp, strlen(uriObj->clientApp) + 1, &clientUid) != CM_SUCCESS) {
        CM_LOG_E("parse string to uint32 failed.");
        CM_FREE_PTR(macByte.data);
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    ret = CalcUriMac(uriObj, clientUid, &mac, false, level);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("calc uri mac failed, ret = %d", ret);
        CM_FREE_PTR(macByte.data);
        return CMR_ERROR_AUTH_FAILED_MAC_FAILED;
    }

    if ((macByte.size != mac.size) || (memcmp(macByte.data, mac.data, macByte.size) != 0)) {
        CM_LOG_E("mac size[%u] invalid or mac check failed", macByte.size);
        CM_FREE_PTR(macByte.data);
        return CMR_ERROR_AUTH_FAILED_MAC_MISMATCH;
    }

    CM_FREE_PTR(macByte.data);
    return CM_SUCCESS;
}

int32_t CmAuthIsAuthorizedApp(const struct CmContext *context, const struct CmBlob *authUri)
{
    struct CMUri uriObj;
    (void)memset_s(&uriObj, sizeof(uriObj), 0, sizeof(uriObj));
    int32_t ret = GetAndCheckUriObj(&uriObj, authUri, CM_URI_TYPE_APP_KEY);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uri decode failed, ret = %d", ret);
        return ret;
    }
    struct CmBlob commonUri = { 0, NULL };

    do {
        ret = ConstructCommonUri(&uriObj, &commonUri, CM_CREDENTIAL_STORE);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("construct common uri failed, ret = %d", ret);
            break;
        }

        enum CmAuthStorageLevel level;
        ret = GetRdbAuthStorageLevel(&commonUri, &level);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get rdb auth storage level failed, ret = %d", ret);
            break;
        }
        if (level == ERROR_LEVEL) {
            level = CM_AUTH_STORAGE_LEVEL_EL1;
            CM_LOG_I("Is authed app level is ERROR_LEVEL, change to default level el1");
        }

        ret = CheckIsAuthorizedApp(&uriObj, level);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("check is authed app failed, ret = %d", ret);
            break;
        }
    } while (0);

    CM_FREE_PTR(commonUri.data);
    (void)CertManagerFreeUri(&uriObj);
    return ret;
}

int32_t CmAuthRemoveGrantedApp(const struct CmContext *context, const struct CmBlob *keyUri, uint32_t appUid)
{
    pthread_mutex_lock(&g_authMgrLock);
    struct CMUri uriObj;
    (void)memset_s(&uriObj, sizeof(uriObj), 0, sizeof(uriObj));
    int32_t ret = GetAndCheckUriObj(&uriObj, keyUri, CM_URI_TYPE_APP_KEY);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uri decode failed, ret = %d", ret);
        pthread_mutex_unlock(&g_authMgrLock);
        return ret;
    }

    do {
        enum CmAuthStorageLevel level;
        ret = GetRdbAuthStorageLevel(keyUri, &level);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get rdb auth storage level failed, ret = %d", ret);
            break;
        }
        if (level == ERROR_LEVEL) {
            level = CM_AUTH_STORAGE_LEVEL_EL1;
            CM_LOG_I("Remove granted app level is ERROR_LEVEL, change to default level el1");
        }

        ret = CheckCallerIsProducer(context, &uriObj);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("check caller userId/uid failed when remove grant, ret = %d", ret);
            break;
        }

        /* delete mac key */
        ret = DeleteMacKey(&uriObj, appUid, level);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("delete mac key failed, ret = %d", ret);
            break;
        }

        /* remove auth uid */
        ret = CmRemoveAuthUid(context, keyUri, appUid);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("remove auth uid from auth list failed, ret = %d", ret);
            break;
        }

        /* remove session node */
        struct CmSessionNodeInfo info = { context->userId, context->uid, *keyUri };
        CmDeleteSessionByNodeInfo(DELETE_SESSION_BY_ALL, &info);
    } while (0);

    (void)CertManagerFreeUri(&uriObj);
    pthread_mutex_unlock(&g_authMgrLock);
    return ret;
}

static int32_t DeleteAuthInfo(uint32_t userId, const struct CmBlob *uri, const struct CmAppUidList *appUidList,
    enum CmAuthStorageLevel level)
{
    struct CMUri uriObj;
    (void)memset_s(&uriObj, sizeof(uriObj), 0, sizeof(uriObj));
    int32_t ret = GetAndCheckUriObj(&uriObj, uri, CM_URI_TYPE_APP_KEY);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uri decode failed, ret = %d", ret);
        return ret;
    }

    do {
        for (uint32_t i = 0; i < appUidList->appUidCount; ++i) {
            ret = DeleteMacKey(&uriObj, appUidList->appUid[i], level);
            if (ret != CM_SUCCESS) {
                CM_LOG_E("delete mac key failed, ret = %d", ret);
                break;
            }
        }
    } while (0);

    (void)CertManagerFreeUri(&uriObj);
    return ret;
}

/* clear auth info when delete public credential */
int32_t CmAuthDeleteAuthInfo(const struct CmContext *context, const struct CmBlob *uri, enum CmAuthStorageLevel level)
{
    pthread_mutex_lock(&g_authMgrLock);
    struct CmAppUidList appUidList = { 0, NULL };
    int32_t ret;
    do {
        ret = CmGetAuthList(context, uri, &appUidList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get auth list failed, ret = %d", ret);
            break;
        }

        ret = DeleteAuthInfo(context->userId, uri, &appUidList, level);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("delete auth failed, ret = %d", ret);
            break;
        }

        ret = CmDeleteAuthListFile(context, uri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("delete auth list file failed, ret = %d", ret);
            break;
        }

        /* remove session node by uri */
        struct CmSessionNodeInfo info = { context->userId, 0, *uri };
        CmDeleteSessionByNodeInfo(DELETE_SESSION_BY_URI, &info);
    } while (0);

    CM_FREE_PTR(appUidList.appUid);
    pthread_mutex_unlock(&g_authMgrLock);
    return ret;
}

/* clear auth info when delete user */
int32_t CmAuthDeleteAuthInfoByUserId(uint32_t userId, const struct CmBlob *uri)
{
    pthread_mutex_lock(&g_authMgrLock);
    struct CmAppUidList appUidList = { 0, NULL };
    enum CmAuthStorageLevel level;
    int32_t ret;
    do {
        ret = CmGetAuthListByUserId(userId, uri, &appUidList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get auth list by user id failed, ret = %d", ret);
            break;
        }

        ret = GetRdbAuthStorageLevel(uri, &level);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get rdb auth storage level failed, ret = %d", ret);
            break;
        }
        if (level == ERROR_LEVEL) {
            level = CM_AUTH_STORAGE_LEVEL_EL1;
            CM_LOG_I("Delete auth user level is ERROR_LEVEL, change to default level el1");
        }

        ret = DeleteAuthInfo(userId, uri, &appUidList, level);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("delete auth failed, ret = %d", ret);
            break;
        }

        ret = CmDeleteAuthListFileByUserId(userId, uri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("delete auth list file failed, ret = %d", ret);
            break;
        }
    } while (0);

    CM_FREE_PTR(appUidList.appUid);
    pthread_mutex_unlock(&g_authMgrLock);
    return ret;
}

/* clear auth info when delete application */
int32_t CmAuthDeleteAuthInfoByUid(uint32_t userId, uint32_t targetUid, const struct CmBlob *uri)
{
    pthread_mutex_lock(&g_authMgrLock);
    int32_t ret;
    do {
        bool isInAuthList = false;
        ret = CmCheckIsAuthUidExistByUserId(userId, targetUid, uri, &isInAuthList);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("check is in auth list failed, ret = %d", ret);
            break;
        }

        if (!isInAuthList) {
            ret = CM_SUCCESS;
            break;
        }

        enum CmAuthStorageLevel level;
        ret = GetRdbAuthStorageLevel(uri, &level);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("get rdb auth storage level failed, ret = %d", ret);
            break;
        }
        if (level == ERROR_LEVEL) {
            level = CM_AUTH_STORAGE_LEVEL_EL1;
            CM_LOG_I("Delete auth app level is ERROR_LEVEL, change to default level el1");
        }

        uint32_t appUid[] = { targetUid };
        struct CmAppUidList appUidList = { sizeof(appUid) / sizeof(uint32_t), appUid };
        ret = DeleteAuthInfo(userId, uri, &appUidList, level);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("delete mac key info failed, ret = %d", ret);
            break;
        }

        ret = CmRemoveAuthUidByUserId(userId, targetUid, uri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("remove auth uid by user id failed, ret = %d", ret);
            break;
        }
    } while (0);
    pthread_mutex_unlock(&g_authMgrLock);
    return ret;
}

static int32_t CheckCommonPermission(const struct CmContext *context, const struct CMUri *uriObj,
    const struct CmBlob *commonUri)
{
    enum CmAuthStorageLevel level;
    int32_t ret = GetRdbAuthStorageLevel(commonUri, &level);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get rdb auth storage level failed, ret = %d", ret);
        return ret;
    }
    if (level == ERROR_LEVEL) {
        level = CM_AUTH_STORAGE_LEVEL_EL1;
        CM_LOG_I("Check permission level is ERROR_LEVEL, change to default level el1");
    }

    ret = CheckCallerIsProducer(context, uriObj);
    if (ret == CM_SUCCESS) {
        return ret;
    }

    if (uriObj->clientApp == NULL) {
        CM_LOG_E("invalid uri client app");
        return CMR_ERROR_NOT_PERMITTED;
    }

    uint32_t clientUid = 0;
    if (CmIsNumeric(uriObj->clientApp, strlen(uriObj->clientApp) + 1, &clientUid) != CM_SUCCESS) {
        CM_LOG_E("parse string to uint32 failed.");
        return CMR_ERROR_INVALID_ARGUMENT_URI;
    }

    if (clientUid != context->uid) {
        CM_LOG_E("caller uid not match client uid");
        return CMR_ERROR_NOT_PERMITTED;
    }

    CM_LOG_D("caller may be authed app, need check");
    return CheckIsAuthorizedApp(uriObj, level);
}

int32_t CmCheckAndGetCommonUri(const struct CmContext *context, uint32_t store, const struct CmBlob *uri,
    struct CmBlob *commonUri)
{
    struct CMUri uriObj;
    (void)memset_s(&uriObj, sizeof(uriObj), 0, sizeof(uriObj));
    int32_t ret = CM_SUCCESS;
    uint32_t type = (store == CM_SYS_CREDENTIAL_STORE) ? CM_URI_TYPE_SYS_KEY : CM_URI_TYPE_APP_KEY;
    ret = GetAndCheckUriObj(&uriObj, uri, type);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uri decode failed, ret = %d", ret);
        return ret;
    }

    do {
        ret = ConstructCommonUri(&uriObj, commonUri, store);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("construct common uri failed, ret = %d", ret);
            break;
        }

        if (store != CM_SYS_CREDENTIAL_STORE) {
            ret = CheckCommonPermission(context, &uriObj, commonUri);
            if (ret != CM_SUCCESS) {
                CM_FREE_PTR(commonUri->data);
                break;
            }
        }
    } while (0);

    (void)CertManagerFreeUri(&uriObj);
    return ret;
}

int32_t CmCheckCallerIsProducer(const struct CmContext *context, const struct CmBlob *uri)
{
    struct CMUri uriObj;
    (void)memset_s(&uriObj, sizeof(uriObj), 0, sizeof(uriObj));
    int32_t ret = GetAndCheckUriObj(&uriObj, uri, CM_URI_TYPE_APP_KEY);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uri decode failed, ret = %d", ret);
        return ret;
    }

    ret = CheckCallerIsProducer(context, &uriObj);
    (void)CertManagerFreeUri(&uriObj);
    return ret;
}
// LCOV_EXCL_STOP
