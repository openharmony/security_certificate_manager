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

#ifndef CERT_MANAGER_STATUS_H
#define CERT_MANAGER_STATUS_H

#include "cert_manager_mem.h"

#include "rbtree.h"

#include "cm_type.h"

#define  CERT_STATUS_ENANLED           ((uint32_t) 0)
#define  CERT_STATUS_DISABLED          ((uint32_t) 1)
#define  CERT_STATUS_MAX                CERT_STATUS_DISABLED
#define  CERT_STATUS_INVALID            ((uint32_t)(CERT_STATUS_MAX + 1))

// integrity protection key for internal use only.
#define CM_INTEGRITY_KEY_URI        "oh:o=ik;t=mk;a=cm"
#define CM_INTEGRITY_TAG_LEN        ((uint32_t) 32)
#define CM_INTEGRITY_SALT_LEN       ((uint32_t) 32)
#define VERSION_1                   ((uint32_t) 0)
#define VERSION_1                   ((uint32_t) 0)

#define CERT_STATUS_ENABLED    ((uint32_t) 0)
#define CERT_STATUS_DISABLED   ((uint32_t) 1)

#define DECODE_UINT32(_b) (uint32_t)(((_b)[0] << 24) | ((_b)[1] << 16) | ((_b)[2] << 8) | (_b)[3])
#define ENCODE_UINT32(_b, _i) do { (_b)[0] = ((_i) >> 24) & 0xff; (_b)[1] = ((_i) >> 16) & 0xff; \
    (_b)[2] = ((_i) >> 8) & 0xff; (_b)[3] = (_i) & 0xff; } while (0)

#define  CERT_STATUS_DIR                    "/data/service/el1/public/cert_manager_service/status"
#define  CERT_STATUS_SYSTEM_STORE           "system"
#define  CERT_STATUS_USER_STORE             "user"
#define  CERT_STATUS_APPLICATION_STORE      "app"

#define CM_ERROR(rc)  (int32_t) (rc)

#define ASSERT_ARGS(c) if (!(c)) { CM_LOG_W("Invalid args: %s\n", #c); return CMR_ERROR_INVALID_ARGUMENT; }
#define ASSERT_FUNC(f) if (CMR_OK != (f)) { CM_LOG_W("Failed: %s\n", #f); return CMR_ERROR; }

#define ASSERT_CM_CALL(f) do {int32_t _rc = (f); if ((_rc) != CM_SUCCESS) { return CM_ERROR((_rc)); }} while (0)

#define TRY_FUNC(f, rc) do { \
    (rc) = (f); if ((rc)) { CM_LOG_W("Failed: %s, %d\n", #f, (rc)); goto finally; }} while (0)

#define  FREE_PTR(p)   if ((p) != NULL) { CMFree((p)); (p) = NULL; }

#define  CM_BLOB(b)   (struct CmBlob) { .size = (b)->size, .data = (uint8_t *) (b)->data }

#define  HKS_BLOB(b)   (struct HksBlob) { .size = (b)->size, .data = (uint8_t *) (b)->data }

#define TRY_HKS_CALL(f, rc) do {int32_t _rc = (f); if ((_rc) != HKS_SUCCESS) { \
    CM_LOG_W("Failed: %s, %d\n", #f, (_rc)); (rc) = CM_ERROR((_rc)); goto finally; }} while (0)

typedef int (*RbTreeValueEncoder)(RbTreeValue value, uint8_t *buf, uint32_t *size);

#ifdef __cplusplus
extern "C" {
#endif

struct CertStatus {
    uint32_t userId;
    uint32_t uid;
    uint32_t status;
    char *fileName;
};

int32_t CertManagerStatusInit(void);

int32_t SetcertStatus(const struct CmContext *context, const struct CmBlob *certUri,
    uint32_t store, uint32_t status, uint32_t *stp);

int32_t CmSetStatusEnable(const struct CmContext *context, struct CmMutableBlob *pathBlob,
    const struct CmBlob *certUri, uint32_t store);

int32_t CmGetCertStatus(const struct CmContext *context, struct CertFileInfo *cFile,
    uint32_t store, uint32_t *status);

#ifdef __cplusplus
}
#endif

#endif // CERT_MANAGER_STATUS_H