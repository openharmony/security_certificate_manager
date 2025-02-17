/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CM_CERT_PROPERTY_RDB_H
#define CM_CERT_PROPERTY_RDB_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

struct CertProperty {
    char uri[MAX_LEN_URI];
    char alias[MAX_LEN_CERT_ALIAS];
    char subjectName[MAX_LEN_SUBJECT_NAME];
    char certType[MAX_LEN_CERT_TYPE];
    int32_t certStore;
    int32_t userId;
    int32_t uid;
    enum CmAuthStorageLevel level;
};

int32_t CreateCertPropertyRdb(void);

int32_t InsertCertProperty(const struct CertProperty *certProperty);

int32_t DeleteCertProperty(const char *uri);

int32_t UpdateCertProperty(const struct CertProperty *certProperty);

int32_t QueryCertProperty(const char *uri, struct CertProperty *certProperty);

#ifdef __cplusplus
}
#endif
#endif // CM_CERT_PROPERTY_RDB_H