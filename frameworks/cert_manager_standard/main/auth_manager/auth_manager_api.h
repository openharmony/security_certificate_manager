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

#ifndef AUTH_MANGAGER_API_H
#define AUTH_MANGAGER_API_H

#include "cm_type.h"

enum AuthErrorCode {
    CMR_ERROR_SESSION_REACHED_LIMIT = -38,
    CMR_ERROR_PERMISSION_DENIED = -39,
    CMR_ERROR_AUTH_CHECK_FAILED = -40,
    CMR_ERROR_KEY_OPERATION_FAILED = -41,
};

enum AutMsgCode {
    CM_MSG_GRANT_APP_CERT, // CmIpcServiceGrantAppCertificate_g_cmIpcHandler
    CM_MSG_GET_AUTHED_LIST, // CmIpcServiceGetAuthorizedAppList
    CM_MSG_CHECK_IS_AUTHED_APP, // CmIpcServiceIsAuthorizedApp
    CM_MSG_REMOVE_GRANT_APP, // CmIpcServiceRemoveGrantedApp
    CM_MSG_INIT, // CmIpcServiceInit
    CM_MSG_UPDATE, // CmIpcServiceUpdate
    CM_MSG_FINISH, // CmIpcServiceFinish
    CM_MSG_ABORT, // CmIpcServiceAbort
    CM_MSG_INSTALL_USER_CERTIFICATE, // CmIpcServiceInstallUserCert
    CM_MSG_UNINSTALL_USER_CERTIFICATE, // CmIpcServiceUninstallUserCert
    CM_MSG_UNINSTALL_ALL_USER_CERTIFICATE, // CmIpcServiceUninstallAllUserCert
};

struct CmAppUidList {
    uint32_t appUidCount;
    uint32_t *appUid;
};

struct CmSignatureSpec {
    uint32_t purpose;
};

#ifdef __cplusplus
extern "C" {
#endif

CM_API_EXPORT int32_t CmGrantAppCertificate(const struct CmBlob *keyUri, uint32_t appUid, struct CmBlob *authUri);

CM_API_EXPORT int32_t CmGetAuthorizedAppList(const struct CmBlob *keyUri, struct CmAppUidList *appUidList);

CM_API_EXPORT int32_t CmIsAuthorizedApp(const struct CmBlob *authUri);

CM_API_EXPORT int32_t CmRemoveGrantedApp(const struct CmBlob *keyUri, uint32_t appUid);

CM_API_EXPORT int32_t CmInit(const struct CmBlob *authUri, const struct CmSignatureSpec *spec, struct CmBlob *handle);

CM_API_EXPORT int32_t CmUpdate(const struct CmBlob *handle, const struct CmBlob *inData);

CM_API_EXPORT int32_t CmFinish(const struct CmBlob *handle, const struct CmBlob *inData, struct CmBlob *outData);

CM_API_EXPORT int32_t CmAbort(const struct CmBlob *handle);

#ifdef __cplusplus
}
#endif

#endif /* AUTH_MANGAGER_API_H */