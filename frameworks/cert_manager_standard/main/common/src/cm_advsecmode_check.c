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

#include "cm_advsecmode_check.h"

#include <string.h>

#include "parameter.h"
#include "sysparam_errno.h"

#include "cm_log.h"

#define ADVSECMODE_PARAM_SIZE 32

static const char g_advSecModePropKey[] = "ohos.boot.advsecmode.state";
static const char g_advSecModePropTrue[] = "1";

int32_t CheckAdvSecMode(bool *isAdvSecMode)
{
    if (isAdvSecMode == NULL) {
        CM_LOG_E("invalid input param");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    *isAdvSecMode = false;
    char param[ADVSECMODE_PARAM_SIZE] = { 0 };
    uint32_t paramSize = sizeof(param);
    int ret = GetParameter(g_advSecModePropKey, NULL, param, paramSize);
    if (ret < 0) {
        if (ret == SYSPARAM_NOT_FOUND) {
            CM_LOG_D("advsecmode param is no found");
            return CM_SUCCESS;
        }
        CM_LOG_E("Failed to get advsecmode param");
        return CMR_ERROR_GET_ADVSECMODE_PARAM_FAIL;
    }

    if (strcmp(param, g_advSecModePropTrue) == 0) {
        *isAdvSecMode = true;
    }
    return CM_SUCCESS;
}