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

#include "cert_manager_service.h"

#include "securec.h"

#include "cert_manager_auth_mgr.h"
#include "cert_manager_key_operation.h"
#include "cert_manager_mem.h"
#include "cert_manager_permission_check.h"
#include "cert_manager_storage.h"
#include "cm_log.h"
#include "cm_type.h"

#include "cm_event_process.h"

static int32_t CheckUri(const struct CmBlob *keyUri)
{
    if (CmCheckBlob(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid uri");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    for (uint32_t i = 1; i < keyUri->size; ++i) { /* from index 1 has '\0' */
        if (keyUri->data[i] == 0) {
            return CM_SUCCESS;
        }
    }
    return CMR_ERROR_INVALID_ARGUMENT;
}

int32_t CmServiceGetAppCert(const struct CmContext *context, uint32_t store,
    struct CmBlob *keyUri, struct CmBlob *certBlob)
{
    if (CheckUri(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    struct CmBlob commonUri = { 0, NULL };
    int32_t ret = CmCheckAndGetCommonUri(context, keyUri, &commonUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("check and get common uri when get app cert failed, ret = %d", ret);
        return ret;
    }

    ret = CmStorageGetAppCert(context, store, &commonUri, certBlob);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get app cert from storage failed, ret = %d", ret);
    }

    CM_FREE_PTR(commonUri.data);
    return ret;
}

int32_t CmServiceGrantAppCertificate(const struct CmContext *context, const struct CmBlob *keyUri,
    uint32_t appUid, struct CmBlob *authUri)
{
    if (CheckUri(keyUri) != CM_SUCCESS || CmCheckBlob(authUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasPrivilegedPermission() || !CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    return CmAuthGrantAppCertificate(context, keyUri, appUid, authUri);
}

int32_t CmServiceGetAuthorizedAppList(const struct CmContext *context, const struct CmBlob *keyUri,
    struct CmAppUidList *appUidList)
{
    if (CheckUri(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasPrivilegedPermission() || !CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    return CmAuthGetAuthorizedAppList(context, keyUri, appUidList);
}

int32_t CmServiceIsAuthorizedApp(const struct CmContext *context, const struct CmBlob *authUri)
{
    if (CheckUri(authUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    return CmAuthIsAuthorizedApp(context, authUri);
}

int32_t CmServiceRemoveGrantedApp(const struct CmContext *context, const struct CmBlob *keyUri, uint32_t appUid)
{
    if (CheckUri(keyUri) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasPrivilegedPermission() || !CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    return CmAuthRemoveGrantedApp(context, keyUri, appUid);
}

int32_t CmServiceInit(const struct CmContext *context, const struct CmBlob *authUri,
    const struct CmSignatureSpec *spec, struct CmBlob *handle)
{
    if (CheckUri(authUri) != CM_SUCCESS || CmCheckBlob(handle) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    struct CmBlob commonUri = { 0, NULL };
    int32_t ret = CmCheckAndGetCommonUri(context, authUri, &commonUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("check and get common uri failed, ret = %d", ret);
        return ret;
    }

    ret = CmKeyOpInit(context, &commonUri, spec, handle);
    CM_FREE_PTR(commonUri.data);
    return ret;
}

int32_t CmServiceUpdate(const struct CmContext *context, const struct CmBlob *handle,
    const struct CmBlob *inData)
{
    if (CmCheckBlob(handle) != CM_SUCCESS || CmCheckBlob(inData) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    return CmKeyOpProcess(SIGN_VERIFY_CMD_UPDATE, context, handle, inData, NULL);
}

int32_t CmServiceFinish(const struct CmContext *context, const struct CmBlob *handle,
    const struct CmBlob *inData, struct CmBlob *outData)
{
    if (CmCheckBlob(handle) != CM_SUCCESS) { /* inData.data and outData.data can be null */
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    return CmKeyOpProcess(SIGN_VERIFY_CMD_FINISH, context, handle, inData, outData);
}

int32_t CmServiceAbort(const struct CmContext *context, const struct CmBlob *handle)
{
    if (CmCheckBlob(handle) != CM_SUCCESS) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    if (!CmHasCommonPermission()) {
        CM_LOG_E("permission check failed");
        return CMR_ERROR_PERMISSION_DENIED;
    }

    return CmKeyOpProcess(SIGN_VERIFY_CMD_ABORT, context, handle, NULL, NULL);
}

