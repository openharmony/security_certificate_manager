/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "cert_manager_status.h"

#include <pthread.h>

#include "securec.h"

#include "cert_manager.h"
#include "cert_manager_crypto_operation.h"
#include "cert_manager_file.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_key_operation.h"
#include "cert_manager_mem.h"
#include "cm_log.h"
#include "cm_type.h"
#include "cert_manager_uri.h"
#include "cert_manager_storage.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t CmGetCertConfigStatus(const char *fileName, uint32_t *status)
{
    if (fileName == NULL || status == NULL) {
        CM_LOG_E("Check param invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    struct CMUri uriObj = { 0 };
    int32_t ret = CertManagerUriDecode(&uriObj, fileName);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to decode uri, ret = %d", ret);
        return ret;
    }
    char confFilePath[CERT_MAX_PATH_LEN] = { 0 };
    if (sprintf_s(confFilePath, CERT_MAX_PATH_LEN, "%s/%s/%s/%s%s", CERT_BACKUP_CONFIG_ROOT_DIR, uriObj.user,
        uriObj.app, fileName, CERT_CONFIG_FILE_SUFFIX) < 0) {
        CM_LOG_E("Failed sprintf conf file path");
        (void)CertManagerFreeUri(&uriObj);
        return CMR_ERROR_BUFFER_TOO_SMALL;
    }
    (void)CertManagerFreeUri(&uriObj);

    ret = CmIsFileExist(NULL, confFilePath);
    if (ret != CM_SUCCESS) {
        CM_LOG_I("Cert config file not exist");
        *status = CERT_STATUS_DISABLED;
    } else {
        CM_LOG_I("Cert config file exist");
        *status = CERT_STATUS_ENABLED;
    }
    return CM_SUCCESS;
}
#ifdef __cplusplus
}
#endif
