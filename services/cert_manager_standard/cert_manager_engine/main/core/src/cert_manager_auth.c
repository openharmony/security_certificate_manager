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

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "securec.h"
#include "cert_manager.h"
#include "cm_log.h"
#include "cert_manager_status.h"
#include "cert_manager_util.h"
#include "cert_manager_uri.h"
#include "hks_api.h"
#include "hks_param.h"
#include "hks_type.h"

#define MAX_UID_LEN 10
#define MAX_MAC_LEN 32

#define KEY_INFO_LIST_MAX_SIZE 4096 // maximum number of keys (including mac-keys)

#ifdef __cplusplus
extern "C" {
#endif

static int32_t UriSetIdStr(char **str, uint32_t value)
{
    char *s = NULL;
    ASSERT_MALLOC(s, MAX_UID_LEN);
    if (snprintf_s(s, MAX_UID_LEN, MAX_UID_LEN - 1, "%u", value) < 0) {
        return CMR_ERROR_INVALID_OPERATION;
    }
    s[MAX_UID_LEN - 1] = 0;
    *str = s;
    return CMR_OK;
}

static int32_t UriAddQuery(struct CMUri *uri, const struct CMApp *clientApp, const char *mac)
{
    if (clientApp != NULL) {
        ASSERT_FUNC(UriSetIdStr(&uri->clientUser, clientApp->userId));
        ASSERT_FUNC(UriSetIdStr(&uri->clientApp, clientApp->uid));
    }
    if (mac != NULL) {
        uri->mac = strdup(mac);
    }
    return CMR_OK;
}

static int32_t EncodeUri(char **s, const struct CMUri *uri)
{
    int rc = CMR_OK;
    char *encoded = NULL;
    uint32_t len = 0;

    ASSERT_FUNC(CertManagerUriEncode(NULL, &len, uri));
    ASSERT_MALLOC(encoded, len);
    (void)memset_s(encoded, len, 0, len);

    TRY_FUNC(CertManagerUriEncode(encoded, &len, uri), rc);

    CM_LOG_D("Has uri: %s\n", encoded);

finally:
    if (rc == CMR_OK) {
        *s = encoded;
    } else if (encoded != NULL) {
        FREE(encoded);
    }
    return rc;
}

struct CmClient {
    const struct CMApp *clientApp;
    const char *mac;
};

static int32_t BuildUri(
    char **objUri, const char *name, uint32_t type,
    const struct CMApp *app, const struct CmClient *clientInfo)
{
    int32_t rc = CMR_OK;
    const struct CMApp *clientApp = clientInfo->clientApp;
    const char *mac = clientInfo->mac;
    struct CMUri uri = {0};
    uri.object = strdup(name);
    uri.type = type;

    TRY_FUNC(UriSetIdStr(&uri.user, app->userId), rc);
    TRY_FUNC(UriSetIdStr(&uri.app, app->uid), rc);
    TRY_FUNC(UriAddQuery(&uri, clientApp, mac), rc);
    TRY_FUNC(EncodeUri(objUri, &uri), rc);

finally:
    CertManagerFreeUri(&uri);
    return rc;
}

int32_t BuildObjUri(char **objUri, const char *name, uint32_t type, const struct CMApp *app)
{
    const struct CmClient clientInfo = { NULL, NULL };
    return BuildUri(objUri, name, type, app, &clientInfo);
}

static inline int32_t CheckKeyObjectType(uint32_t type)
{
    if (! CertManagerIsKeyObjectType(type)) {
        CM_LOG_W("Not a valid key object type: %u\n", type);
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CMR_OK;
}

int32_t CertManagerImportKeyPair(
    const struct CMApp *caller,
    const struct CmBlob *keyPair,
    const struct CMKeyProperties *properties,
    const char *name)
{
    ASSERT_ARGS(caller && keyPair && properties && name);
    ASSERT_ARGS(strlen(name) > 0);
    ASSERT_ARGS(strlen(name) <= CM_NAME_MAX_LEN);

    uint32_t type = properties->type;
    ASSERT_FUNC(CheckKeyObjectType(type));

    int rc = CMR_OK;
    char *objUri = NULL;
    struct HksParamSet *params = NULL;

    TRY_FUNC(CertManagerBuildKeySpec(&params, properties), rc);
    TRY_FUNC(BuildObjUri(&objUri, name, type, caller), rc);

    struct HksBlob alias = { .size = strlen(objUri), .data = (uint8_t *) objUri };
    TRY_CM_CALL(HksImportKey(&alias, params, &HKS_BLOB(keyPair)), rc);

finally:
    if (params != NULL) {
        HksFreeParamSet(&params);
    }
    if (objUri != NULL) {
        FREE(objUri);
    }
    return rc;
}

#ifdef __cplusplus
}
#endif
