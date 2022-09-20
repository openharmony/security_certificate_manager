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

#include "auth_manager_api.h"

#include "cm_client_ipc.h"
#include "cm_log.h"
#include "cm_type.h"

CM_API_EXPORT int32_t CmGrantAppCertificate(const struct CmBlob *keyUri, uint32_t appUid, struct CmBlob *authUri)
{
    CM_LOG_I("enter grant app certificate");
    if ((keyUri == NULL) || (authUri == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGrantAppCertificate(keyUri, appUid, authUri);
    CM_LOG_I("leave grant app certificate, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmGetAuthorizedAppList(const struct CmBlob *keyUri, struct CmAppUidList *appUidList)
{
    CM_LOG_I("enter get authorized app list");
    if ((keyUri == NULL) || (appUidList == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientGetAuthorizedAppList(keyUri, appUidList);
    CM_LOG_I("leave get authorized app list, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmIsAuthorizedApp(const struct CmBlob *authUri)
{
    CM_LOG_I("enter check is app authed");
    if (authUri == NULL) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientIsAuthorizedApp(authUri);
    CM_LOG_I("leave check is app authed, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmRemoveGrantedApp(const struct CmBlob *keyUri, uint32_t appUid)
{
    CM_LOG_I("enter remove granted app");
    if (keyUri == NULL) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientRemoveGrantedApp(keyUri, appUid);
    CM_LOG_I("leave remove granted app, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmInit(const struct CmBlob *authUri, const struct CmSignatureSpec *spec, struct CmBlob *handle)
{
    CM_LOG_I("enter cert manager init");
    if ((authUri == NULL) || (spec == NULL) || (handle == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientInit(authUri, spec, handle);
    CM_LOG_I("leave cert manager init, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmUpdate(const struct CmBlob *handle, const struct CmBlob *inData)
{
    CM_LOG_I("enter cert manager update");
    if ((handle == NULL) || (inData == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientUpdate(handle, inData);
    CM_LOG_I("leave cert manager update, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmFinish(const struct CmBlob *handle, const struct CmBlob *inData, struct CmBlob *outData)
{
    CM_LOG_I("enter cert manager finish");
    if ((handle == NULL) || (inData == NULL) || (outData == NULL)) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientFinish(handle, inData, outData);
    CM_LOG_I("leave cert manager finish, result = %d", ret);
    return ret;
}

CM_API_EXPORT int32_t CmAbort(const struct CmBlob *handle)
{
    CM_LOG_I("enter cert manager abort");
    if (handle == NULL) {
        CM_LOG_E("invalid input arguments");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = CmClientAbort(handle);
    CM_LOG_I("leave cert manager abort, result = %d", ret);
    return ret;
}
