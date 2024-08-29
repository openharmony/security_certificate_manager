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

#include "cm_util.h"

#include "cm_type.h"
#include "cm_log.h"

#define CARRY       10
#define STR_MAX_LEN 10

int32_t CmIsNumeric(const char *str, const size_t length, uint32_t *value)
{
    if (str == NULL || length == 0 || length > STR_MAX_LEN || value == NULL) {
        CM_LOG_D("input parameter error");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    for (size_t i = 0; i < length; i++) {
        if (str[i] == '\0') {
            break;
        }
        if (i == length - 1) {
            CM_LOG_D("the string does not have an terminator");
            return CMR_ERROR_INVALID_ARGUMENT;
        }
    }

    char *endptr = NULL;
    unsigned long num = strtoul(str, &endptr, CARRY);
    if (endptr == NULL || *endptr != '\0') {
        CM_LOG_D("str is not numeric string");
        return CMR_ERROR_INVALID_ARGUMENT;
    } else {
        *value = (uint32_t)num;
        return CM_SUCCESS;
    }
}
