/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef CERT_MANAGER_UPDATEFLAG_H
#define CERT_MANAGER_UPDATEFLAG_H

#include <stdint.h>
#include <stdbool.h>

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Check whether the certificate needs to backup
 *
 * @param[in] userId User ID
 * @param[in] uid User identifier
 * @param[in] certUri Certificate uri
 * @param[out] needUpdate Returns the result of whether the backup needs to backup
 * @return int32_t result
 * @retval 0 success
 * @retval <0 failure
 */
int32_t IsCertNeedBackup(uint32_t userId, uint32_t uid, const struct CmBlob *certUri, bool *needUpdate);

/**
 * @brief Read the user certificate data
 *
 * @param store Storage type
 * @param context Context information
 * @param certUri Certificate uri
 * @param userCertData Certificate data
 * @return int32_t result
 * @retval 0 success
 * @retval <0 failure
 */
int32_t CmReadCertData(uint32_t store, const struct CmContext *context, const struct CmBlob *certUri,
                       struct CmBlob *userCertData);

/**
 * @brief Back up the specified user certificate
 *
 * @param[in] context Context information
 * @param[in] certUri Certificate uri
 * @param[in] certData Certificate data
 * @return int32_t result
 * @retval 0 success
 * @retval <0 failure
 */
int32_t CmBackupUserCert(const struct CmContext *context, const struct CmBlob *certUri, const struct CmBlob *certData);

/**
 * @brief Back up all user certificates
 *
 * @return int32_t result
 * @retval 0 success
 * @retval <0 failure
 */
int32_t CmBackupAllSaUserCerts(void);

#ifdef __cplusplus
}
#endif

#endif