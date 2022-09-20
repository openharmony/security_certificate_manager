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

#ifndef CERT_MANAGER_TYPES_H
#define CERT_MANAGER_TYPES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "stdbool.h"

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

// Authentication related macros. These have to follow the definitions in HUKS.
#define CM_AUTH_TYPE_NONE       0
#define CM_AUTH_TYPE_BIO        1
#define CM_AUTH_TYPE_PASSCODE   2

enum CMErrorCode {
    CMR_OK = 0,
    CMR_ERROR = -1,
};

#define CM_AUTH_TYPE_NONE   0
#define CM_HMAC_KEY_SIZE_256 256

struct CMKeyProperties {
    uint32_t type;
    uint32_t alg;
    uint32_t size;
    uint32_t padding;
    uint32_t purpose;
    uint32_t digest;
    uint32_t authType;
    uint32_t authTimeout;
};

#ifdef __cplusplus
}
#endif

#endif