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

#ifndef CERT_MANAGER_URI_H
#define CERT_MANAGER_URI_H

#include "cert_manager_mem.h"
#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEC_LEN 10

// maximum length of object names for cert manager
#define CM_NAME_MAX_LEN 32
// maximum length of URI
#define CM_URI_MAX_LEN 256

#define CM_URI_TYPE_CERTIFICATE ((uint32_t)0)
#define CM_URI_TYPE_MAC_KEY ((uint32_t)1)
#define CM_URI_TYPE_APP_KEY ((uint32_t)2)
#define CM_URI_TYPE_WLAN_KEY ((uint32_t)3)
#define CM_URI_TYPE_MAX CM_URI_TYPE_WLAN_KEY
#define CM_URI_TYPE_INVALID (CM_URI_TYPE_MAX + 1)

#define MALLOC CMMalloc
#define FREE CMFree

#define ASSERT_MALLOC(p, sz) do { (p) = MALLOC(sz); if ( (p) == NULL) { \
    CM_LOG_E("Failed to allocate memory of size: %u\n", (uint32_t) (sz)); return CMR_ERROR_MALLOC_FAIL; } } while (0)

// object types: certificate, mac-key, app-key, WLAN-key
static const char *g_types[] = { "c", "m", "ak", "wk" };
static const uint32_t TYPE_COUNT = 4;

struct CMUri {
    // path components
    char *object;
    uint32_t type;
    char *user;
    char *app;

    // query components
    char *clientUser;
    char *clientApp;
    char *mac;
};

// check if object type is a normal key type (APP_KEY or WLAN_KEY)
bool CertManagerIsKeyObjectType(uint32_t type);

// Encode a URI to a char string. If (encoded) is NULL, only the required length is returned.
int32_t CertManagerUriEncode(char *encoded, uint32_t *encodedLen, const struct CMUri *uri);

// Free memory allocated during CertManagerUriDecode.
int32_t CertManagerFreeUri(struct CMUri *uri);

int32_t CertManagerUriDecode(struct CMUri *uri, const char *encoded);

int32_t CertManagerGetUidFromUri(const struct CmBlob *uri, uint32_t *uid);

int32_t CmConstructUri(const struct CMUri *uriObj, struct CmBlob *outUri);

int32_t CmConstructCommonUri(const struct CmContext *context, const uint32_t type,
    const struct CmBlob *certAlias, struct CmBlob *outUri);

#ifdef __cplusplus
}
#endif

#endif // CERT_MANAGER_URI_H