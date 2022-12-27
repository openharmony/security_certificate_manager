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

#include "cert_manager_uri.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "securec.h"

#include "cm_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IS_TYPE_VALID(t) ((t) <= CM_URI_TYPE_MAX)

#define SCHEME "oh:"
#define P_OBJECT "o="
#define P_TYPE "t="
#define P_USER "u="
#define P_APP "a="
#define Q_MAC "m="
#define Q_CLIENT_USER "cu="
#define Q_CLIENT_APP "ca="

// characters do not need to be encoded in path, other than digits and algabets
#define P_RES_AVAIL "-._~:[]@!$'()*+,=&"
// characters do not need to be encoded in query, other than digits and algabets
#define Q_RES_AVAIL "-._~:[]@!$'()*+,=/?|"

int32_t CertManagerFreeUri(struct CMUri *uri)
{
    if (uri == NULL) {
        return CMR_OK;
    }
    CM_FREE_PTR(uri->object);
    CM_FREE_PTR(uri->user);
    CM_FREE_PTR(uri->app);
    CM_FREE_PTR(uri->mac);
    CM_FREE_PTR(uri->clientUser);
    CM_FREE_PTR(uri->clientApp);
    return CMR_OK;
}

inline bool CertManagerIsKeyObjectType(uint32_t type)
{
    return (type == CM_URI_TYPE_APP_KEY || type == CM_URI_TYPE_WLAN_KEY);
}

static int IsUnreserved(const char *resAvail, size_t resAvailLen, char c)
{
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
        return 1;
    }
    if (resAvail != NULL) {
        for (size_t i = 0; i < resAvailLen; i++) {
            if (c == resAvail[i]) {
                return 1;
            }
        }
    }
    return 0;
}

static uint32_t GetComponentEncodedLen(const char *key, const char *value,
    const char *resAvail, uint32_t *sep)
{
    if (value == NULL) {
        return 0;
    }
    size_t resAvailLen = strlen(resAvail);
    size_t keyLen = strlen(key);
    size_t valueLen = strlen(value);
    size_t reserved = 0;
    for (size_t i = 0; i < valueLen; i++) {
        if (!IsUnreserved(resAvail, resAvailLen, value[i])) {
            reserved++;
        }
    }
    // each reserved character requires 2 extra bytes to percent-encode
    uint32_t len = (uint32_t) (keyLen + valueLen + reserved * 2 + *sep);
    *sep = 1;
    return len;
}

static uint32_t GetEncodedLen(const struct CMUri *uri)
{
    if (uri == NULL) {
        return 0;
    }

    uint32_t sep = 0;
    uint32_t len = strlen(SCHEME);

    len += GetComponentEncodedLen(P_TYPE, g_types[uri->type], P_RES_AVAIL, &sep);
    len += GetComponentEncodedLen(P_OBJECT, uri->object, P_RES_AVAIL, &sep);
    len += GetComponentEncodedLen(P_USER, uri->user, P_RES_AVAIL, &sep);
    len += GetComponentEncodedLen(P_APP, uri->app, P_RES_AVAIL, &sep);

    uint32_t qlen = 0;
    sep = 0;
    qlen += GetComponentEncodedLen(Q_CLIENT_USER, uri->clientUser, Q_RES_AVAIL, &sep);
    qlen += GetComponentEncodedLen(Q_CLIENT_APP, uri->clientApp, Q_RES_AVAIL, &sep);
    qlen += GetComponentEncodedLen(Q_MAC, uri->mac, Q_RES_AVAIL, &sep);

    return len + sep + qlen;
}

// encode the last 4 bits of an integer to a hex char
static inline uint32_t HexEncode(uint32_t v)
{
    v &= 0xf;
    if (v < DEC_LEN) {
        return ('0' + v);
    } else {
        return ('A' + v - DEC_LEN);
    }
}

static int32_t EncodeComp(
    char *buf, uint32_t *offset, uint32_t *available,
    const char *key, const char *value,
    const char *resAvail,
    uint32_t *sep, char sepChar)
{
    if (value == NULL) {
        return CMR_OK;
    }

    size_t resAvailLen = strlen(resAvail);
    size_t keyLen = strlen(key);
    size_t valueLen = strlen(value);
    uint32_t off = *offset;
    uint32_t avail = *available;

    if (avail < *sep + keyLen + valueLen) {
        return CMR_ERROR;
    }

    if (*sep) {
        buf[off] = sepChar;
        off++;
    }

    if (memcpy_s(buf + off, avail, key, keyLen) != EOK) {
        return CMR_ERROR;
    }
    off += keyLen;
    avail -= keyLen;

    for (size_t i = 0; i < valueLen; i++) {
        if (IsUnreserved(resAvail, resAvailLen, value[i])) {
            if (avail < 1) {
                return CMR_ERROR;
            }
            buf[off] = value[i];
            off++;
            avail--;
        } else {
            // each percent-encoded character requires 3 bytes
            if (avail < 3) {
                return CMR_ERROR;
            }
            buf[off] = '%';
            off++;
            buf[off] = (char) HexEncode(value[i] >> 4); // higher 4 bits of the char byte
            off++;
            buf[off] = (char) HexEncode(value[i]); // lower 4 bits of the char byte
            off++;
            // each percent-encoded character requires 3 bytes
            avail -= 3;
        }
    }

    *sep = 1;
    *offset = off;
    *available = avail;
    return CMR_OK;
}

static int32_t EncodePathComp(char *encoded, uint32_t *offset, uint32_t *availLen,
    const struct CMUri *uri)
{
    int32_t ret = CM_FAILURE;
    uint32_t sep = 0;
    uint32_t off = *offset;
    uint32_t avail = *availLen;

    do {
        ret = EncodeComp(encoded, &off, &avail, P_TYPE, g_types[uri->type], P_RES_AVAIL, &sep, ';');
        if (ret != CM_SUCCESS) {
            CM_LOG_E("encode <t=> failed");
            break;
        }

        ret = EncodeComp(encoded, &off, &avail, P_OBJECT, uri->object, P_RES_AVAIL, &sep, ';');
        if (ret != CM_SUCCESS) {
            CM_LOG_E("encode <o=> failed");
            break;
        }

        ret = EncodeComp(encoded, &off, &avail, P_USER, uri->user, P_RES_AVAIL, &sep, ';');
        if (ret != CM_SUCCESS) {
            CM_LOG_E("encode <u=> failed");
            break;
        }

        ret = EncodeComp(encoded, &off, &avail, P_APP, uri->app, P_RES_AVAIL, &sep, ';');
        if (ret != CM_SUCCESS) {
            CM_LOG_E("encode <a=> failed");
            break;
        }
    } while (0);

    *offset = off;
    *availLen = avail;
    return ret;
}

static int32_t EncodeQueryComp(char *encoded, uint32_t *offset, uint32_t *availLen,
    const struct CMUri *uri)
{
    if (uri->clientUser == NULL && uri->clientApp == NULL && uri->mac == NULL) {
        // no query. we are done.
        return CM_SUCCESS;
    }

    int32_t ret = CM_FAILURE;
    uint32_t sep = 0;
    uint32_t off = *offset;
    uint32_t avail = *availLen;
    encoded[off] = '?';
    off++;
    avail--;

    do {
        ret = EncodeComp(encoded, &off, &avail, Q_CLIENT_USER, uri->clientUser, Q_RES_AVAIL, &sep, '&');
        if (ret != CM_SUCCESS) {
            CM_LOG_E("encode <cu=> failed");
            break;
        }

        ret = EncodeComp(encoded, &off, &avail, Q_CLIENT_APP, uri->clientApp, Q_RES_AVAIL, &sep, '&');
        if (ret != CM_SUCCESS) {
            CM_LOG_E("encode <ca=> failed");
            break;
        }

        ret = EncodeComp(encoded, &off, &avail, Q_MAC, uri->mac, Q_RES_AVAIL, &sep, '&');
        if (ret != CM_SUCCESS) {
            CM_LOG_E("encode <m=> failed");
            break;
        }
    } while (0);

    *offset = off;
    *availLen = avail;
    return ret;
}

int32_t CertManagerUriEncode(char *encoded, uint32_t *encodedLen, const struct CMUri *uri)
{
    if (encodedLen == NULL || uri == NULL || !IS_TYPE_VALID(uri->type)) {
        CM_LOG_E("input params is invaild");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    uint32_t encLen = GetEncodedLen(uri) + 1;
    if (encoded == NULL) {
        *encodedLen = encLen;
        return CM_SUCCESS;
    }

    if (*encodedLen < encLen) {
        CM_LOG_W("Buffer to small for encoded URI (%u < %u).\n", *encodedLen, encLen);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }

    uint32_t off = 0;
    uint32_t avail = *encodedLen;

    if (memcpy_s(encoded, avail, SCHEME, strlen(SCHEME)) != EOK) {
        return CM_FAILURE;
    }
    off += strlen(SCHEME);
    avail -= strlen(SCHEME);

    int32_t ret = EncodePathComp(encoded, &off, &avail, uri);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    ret = EncodeQueryComp(encoded, &off, &avail, uri);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    *encodedLen = off;
    return CM_SUCCESS;
}

static uint32_t HexDecode(uint32_t h)
{
    h &= 0xff;
    if (h >= '0' && h <= '9') {
        return h - '0';
    }
    if (h >= 'a' && h <= 'f') {
        return h - 'a' + DEC_LEN;
    }
    if (h >= 'A' && h <= 'F') {
        return h - 'A' + DEC_LEN;
    }
    return 0;
}

static inline uint32_t HexDecode2(uint32_t h1, uint32_t h2)
{
    return ((HexDecode(h1) << 4) | HexDecode(h2)) & 0xff; /* 4 is number of shifts */
}

static inline uint32_t IndexOf(char sep, const char *data, uint32_t start, uint32_t end)
{
    for (uint32_t i = start; i < end; i++) {
        if (data[i] == sep) {
            return i;
        }
    }
    return end;
}

static char *DecodeValue(const char *s, uint32_t off, uint32_t len)
{
    if (s == NULL || len == 0 || len > MAX_AUTH_LEN_URI) {
        CM_LOG_E("input value failed");
        return NULL;
    }
    char *buf = MALLOC(len + 1);
    if (buf == NULL) {
        CM_LOG_E("malloc buf failed");
        return NULL;
    }
    (void)memset_s(buf, len + 1, 0, len + 1);

    uint32_t bufOff = 0;
    for (uint32_t i = off; i < off + len; i++, bufOff++) {
        if (s[i] != '%') {
            buf[bufOff] = s[i];
        } else {
            buf[bufOff] = HexDecode2(s[i + 1], s[i + 2]); /* 2 is array index */
            i += 2; /* 2 is array index */
        }
    }
    char *ret = strndup(buf, bufOff);
    free(buf);
    return ret;
}

static uint32_t DecodeEnum(const char *s, uint32_t off, uint32_t len, const char *values[], uint32_t valueCount)
{
    for (uint32_t i = 0; i < valueCount; i++) {
        size_t valLen = strlen(values[i]);
        if (valLen == len && memcmp(s + off, values[i], len) == 0) {
            return i;
        }
    }
    // no match found, default value is an invalid enum value
    return valueCount + 1;
}

static int32_t DecodePath(struct CMUri *uri, const char *path, uint32_t start, uint32_t end)
{
    while (start < end) {
        uint32_t i = IndexOf(';', path, start, end);
        if (i <= start) {
            // something is wrong
            CM_LOG_W("Invalid uri path\n");
            return CMR_ERROR_INVALID_ARGUMENT;
        }

        uint32_t valueOff = 0;
        uint32_t valueLen = 0;

        // for string field
        char **field = NULL;

        // for enum field
        uint32_t *e = NULL;
        const char **values = NULL;
        uint32_t valueCount = 0;

        if (!strncmp(P_OBJECT, path + start, strlen(P_OBJECT))) {
            valueOff = start + strlen(P_OBJECT);
            valueLen = i - start - strlen(P_OBJECT);
            field = &uri->object;
        } else if (!strncmp(P_TYPE, path + start, strlen(P_TYPE))) {
            valueOff = start + strlen(P_TYPE);
            valueLen = i - start - strlen(P_TYPE);
            e = &uri->type;
            values = g_types;
            valueCount = TYPE_COUNT;
        } else if (!strncmp(P_USER, path + start, strlen(P_USER))) {
            valueOff = start + strlen(P_USER);
            valueLen = i - start - strlen(P_USER);
            field = &uri->user;
        } else if (!strncmp(P_APP, path + start, strlen(P_APP))) {
            valueOff = start + strlen(P_APP);
            valueLen = i - start - strlen(P_APP);
            field = &uri->app;
        }

        if (field != NULL) {
            if (valueLen == 0) {
                *field = NULL;
            } else {
                *field = DecodeValue(path, valueOff, valueLen);
            }
        } else if (e != NULL) {
            *e = DecodeEnum(path, valueOff, valueLen, values, valueCount);
        } else {
            CM_LOG_W("Invalid field in path\n");
            return CMR_ERROR_INVALID_ARGUMENT;
        }

        start = i + 1;
    }

    return CMR_OK;
}

static int32_t DecodeQuery(struct CMUri *uri, const char *query, uint32_t start, uint32_t end)
{
    while (start < end) {
        uint32_t i = IndexOf('&', query, start, end);
        if (i <= start) {
            // something is wrong
            CM_LOG_W("Invalid uri query\n");
            return CMR_ERROR_INVALID_ARGUMENT;
        }

        uint32_t valueOff = 0;
        uint32_t valueLen = 0;
        char **field = NULL;
        if (!strncmp(Q_CLIENT_USER, query + start, strlen(Q_CLIENT_USER))) {
            valueOff = start + strlen(Q_CLIENT_USER);
            valueLen = i - start - strlen(Q_CLIENT_USER);
            field = &uri->clientUser;
        } else if (!strncmp(Q_CLIENT_APP, query + start, strlen(Q_CLIENT_APP))) {
            valueOff = start + strlen(Q_CLIENT_APP);
            valueLen = i - start - strlen(Q_CLIENT_APP);
            field = &uri->clientApp;
        } else if (!strncmp(Q_MAC, query + start, strlen(Q_MAC))) {
            valueOff = start + strlen(Q_MAC);
            valueLen = i - start - strlen(Q_MAC);
            field = &uri->mac;
        }

        if (field != NULL) {
            if (valueLen == 0) {
                *field = NULL;
            } else {
                *field = DecodeValue(query, valueOff, valueLen);
            }
        } else {
            CM_LOG_W("Invalid field in query\n");
            return CMR_ERROR_INVALID_ARGUMENT;
        }

        start = i + 1;
    }
    return CMR_OK;
}

int32_t CertManagerUriDecode(struct CMUri *uri, const char *encoded)
{
    if (uri == NULL || encoded == NULL) {
        CM_LOG_E("input params is invaild");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    (void)memset_s(uri, sizeof(*uri), 0, sizeof(*uri));
    uri->type = CM_URI_TYPE_INVALID;

    uint32_t len = strlen(encoded);
    uint32_t off = 0;
    if (len < strlen(SCHEME) || memcmp(encoded, SCHEME, strlen(SCHEME))) {
        CM_LOG_E("Scheme mismatch. Not a cert manager URI");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    off += strlen(SCHEME);

    uint32_t pathStart = off;
    uint32_t pathEnd = IndexOf('?', encoded, off, len);
    uint32_t queryStart = (pathEnd == len) ? len : pathEnd + 1;
    uint32_t queryEnd = len;

    int32_t ret = DecodePath(uri, encoded, pathStart, pathEnd);
    if (ret != CM_SUCCESS) {
        CertManagerFreeUri(uri);
        return ret;
    }

    ret = DecodeQuery(uri, encoded, queryStart, queryEnd);
    if (ret != CM_SUCCESS) {
        CertManagerFreeUri(uri);
        return ret;
    }

    return CM_SUCCESS;
}

int32_t CertManagerGetUidFromUri(const struct CmBlob *uri, uint32_t *uid)
{
    struct CMUri uriObj;
    (void)memset_s(&uriObj, sizeof(uriObj), 0, sizeof(uriObj));
    int32_t ret = CertManagerUriDecode(&uriObj, (char *)uri->data);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("uri decode failed, ret = %d", ret);
        return ret;
    }

    if (uriObj.app == NULL) {
        CM_LOG_E("uri app invalid");
        (void)CertManagerFreeUri(&uriObj);
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    *uid = atoi(uriObj.app);
    (void)CertManagerFreeUri(&uriObj);
    return CM_SUCCESS;
}

int32_t CmConstructUri(const struct CMUri *uriObj, struct CmBlob *outUri)
{
    uint32_t outLen = 0;
    int32_t ret = CertManagerUriEncode(NULL, &outLen, uriObj);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get uriObj len failed, ret = %d", ret);
        return ret;
    }

    if ((outLen == 0) || (outLen > MAX_OUT_BLOB_SIZE)) {
        CM_LOG_E("invalid outLen[%u]", outLen);
        return CMR_ERROR_INVALID_OPERATION;
    }

    char *data = (char *)CMMalloc(outLen);
    if (data == NULL) {
        CM_LOG_E("malloc uri buf failed");
        return CMR_ERROR_INVALID_OPERATION;
    }
    (void)memset_s(data, outLen, 0, outLen);
    outUri->size = outLen; /* include 1 byte: the terminator('\0')  */

    ret = CertManagerUriEncode(data, &outLen, uriObj); /* outLen not include '\0' */
    if (ret != CM_SUCCESS) {
        CM_LOG_E("encord uri failed");
        outUri->size = 0;
        CMFree(data);
        return ret;
    }

    outUri->data = (uint8_t *)data;
    return CM_SUCCESS;
}

static int32_t UintToStr(uint32_t input, char *out, uint32_t outLen)
{
    if (snprintf_s(out, outLen, outLen - 1, "%u", input) < 0) {
        return CMR_ERROR_INVALID_OPERATION;
    }
    return CM_SUCCESS;
}

int32_t CmConstructCommonUri(const struct CmContext *context, const uint32_t type,
    const struct CmBlob *certAlias, struct CmBlob *outUri)
{
    struct CMUri uriObj;
    (void)memset_s(&uriObj, sizeof(struct CMUri), 0, sizeof(struct CMUri));

    char userIdStr[MAX_UINT32_LEN] = { 0 };
    int32_t ret = UintToStr(context->userId, userIdStr, MAX_UINT32_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("construct userId to str failed");
        return ret;
    }

    char uidStr[MAX_UINT32_LEN] = { 0 };
    ret = UintToStr(context->uid, uidStr, MAX_UINT32_LEN);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("construct uid to str failed");
        return ret;
    }

    uriObj.object = (char *)certAlias->data;
    uriObj.type = type;
    uriObj.user = userIdStr;
    uriObj.app = uidStr;

    ret = CmConstructUri(&uriObj, outUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("construct uri failed, ret = %d", ret);
    }
    return ret;
}

#ifdef __cplusplus
}
#endif

