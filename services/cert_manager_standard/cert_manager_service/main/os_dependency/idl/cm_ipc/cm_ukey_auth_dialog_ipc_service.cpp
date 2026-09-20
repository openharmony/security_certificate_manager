/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "cm_ukey_auth_dialog_ipc_service.h"

#include <string>

#include "accesstoken_kit.h"
#include "errors.h"
#include "ipc_skeleton.h"

#include "cm_ipc_service_serialization.h"
#include "cm_log.h"
#include "cm_mem.h"
#include "cm_param.h"
#include "cm_ukey_auth_dialog_manager.h"

namespace OHOS::Security::CertManager {
using namespace OHOS::Security::AccessToken;

namespace {
/* Parsed paramSet result of the ForDriver OPEN request (blobs point into
 * the paramSet buffer; the paramSet is held by the caller and released
 * after the handler consumes it synchronously) */
struct DriverDialogIpcParams {
    struct CmBlob abilityName;
    uint32_t abilityType = 0;
    struct CmBlob keyUri;
    uint32_t timeoutSec = 0;
    struct CmBlob customData;
};

/* On parse success *paramSet is owned by the caller (never freed inside, on either the success or the failure path) */
int32_t ParseOpenDriverDialogParams(const struct CmBlob *paramSetBlob,
    DriverDialogIpcParams &out, struct CmParamSet **paramSet)
{
    *paramSet = nullptr;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &out.abilityName },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = &out.abilityType },
        { .tag = CM_TAG_PARAM2_BUFFER, .blob = &out.keyUri },
        { .tag = CM_TAG_PARAM3_UINT32, .uint32Param = &out.timeoutSec },
    };
    int32_t ret = CmGetParamSet(reinterpret_cast<struct CmParamSet *>(paramSetBlob->data),
        paramSetBlob->size, paramSet);
    if (ret != CM_SUCCESS) {
        return ret;
    }
    ret = CmParamSetToParams(*paramSet, params, CM_ARRAY_SIZE(params));
    if (ret == CM_SUCCESS) {
        struct CmParam *customDataParam = nullptr;
        if (CmGetParam(*paramSet, CM_TAG_PARAM4_BUFFER, &customDataParam) == CM_SUCCESS) {
            out.customData = customDataParam->blob;
        }
    }
    return ret;
}

/* ForDriver caller validation (spec v4 D23): server-side permission check
 * (defense in depth beyond the NAPI precheck) + caller bundle identity; on
 * failure returns the response code to send, on success fills hapInfo */
int32_t CheckDriverDialogCaller(HapTokenInfo &hapInfo)
{
    if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(),
        "ohos.permission.CRYPTO_EXTENSION_REGISTER") != PERMISSION_GRANTED) {
        CM_LOG_E("open driver dialog permission denied");
        return CMR_DIALOG_ERROR_PERMISSION_DENIED;
    }
    /* Caller bundle: only HAP tokens pass (the bundle can only come from the
     * IPC token, not declarable by the client, D20/D23) */
    if (AccessTokenKit::GetHapTokenInfo(IPCSkeleton::GetCallingTokenID(), hapInfo) != ERR_OK) {
        CM_LOG_E("open driver dialog caller is not hap token, callingUid = %d",
            static_cast<int32_t>(IPCSkeleton::GetCallingUid()));
        return CMR_DIALOG_ERROR_INTERNAL;
    }
    return CM_SUCCESS;
}
} // namespace

/* Unlike the other handlers in cm_ipc_service.c, the handlers in this file
 * do not build a CmContext: UKey dialog sessions touch no storage data
 * isolated per user/uid; the caller identity is obtained via IPCSkeleton
 * (uid/tokenId) and permission + HAP identity validation is already done. */

void CmIpcServiceOpenUkeyAuthDialog(uint32_t code, const struct CmBlob *paramSetBlob,
    const struct CmContext *context, const sptr<IRemoteObject> &clientCallback)
{
    (void)code;
    struct CmParamSet *paramSet = nullptr;
    struct CmBlob keyUri = { 0, nullptr };
    uint32_t timeoutSec = 0; /* 0 = not passed (seconds); SA side takes the
                              * default 300s, explicit values clamped to [3min, 10min] */
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &keyUri },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = &timeoutSec },
    };
    int32_t ret = CmGetParamSet(reinterpret_cast<struct CmParamSet *>(paramSetBlob->data),
        paramSetBlob->size, &paramSet);
    if (ret == CM_SUCCESS) {
        ret = CmParamSetToParams(paramSet, params, CM_ARRAY_SIZE(params));
    }
    struct CmBlob customData = { 0, nullptr }; /* optional: delivered to the custom dialog only (spec D18/D19) */
    if (ret == CM_SUCCESS) {
        struct CmParam *customDataParam = nullptr;
        if (CmGetParam(paramSet, CM_TAG_PARAM2_BUFFER, &customDataParam) == CM_SUCCESS) {
            customData = customDataParam->blob;
        }
    }
    if (ret != CM_SUCCESS) {
        CM_LOG_E("open ukey dialog get params failed, ret = %d", ret);
        CmFreeParamSet(&paramSet);
        CmSendResponse(context, CMR_ERROR_INVALID_ARGUMENT, nullptr);
        return;
    }

    /* Server-side permission check (defense in depth; already done once on the NAPI side) */
    if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(),
        "ohos.permission.ACCESS_CERT_MANAGER") != PERMISSION_GRANTED) {
        CM_LOG_E("open ukey dialog permission denied");
        CmFreeParamSet(&paramSet);
        CmSendResponse(context, CMR_DIALOG_ERROR_PERMISSION_DENIED, nullptr);
        return;
    }

    CmUkeyAuthDialogManager::GetInstance().InitRealDependencies();
    /* customData points into the paramSet buffer; OpenDialog consumes it
     * synchronously (written into dialog params) and never references it after */
    ret = CmUkeyAuthDialogManager::GetInstance().OpenDialog(&keyUri,
        static_cast<uint32_t>(IPCSkeleton::GetCallingUid()), timeoutSec, &customData,
        clientCallback);
    CmFreeParamSet(&paramSet);
    CmSendResponse(context, ret, nullptr);
}

void CmIpcServiceOpenUkeyAuthDialogForDriver(uint32_t code, const struct CmBlob *paramSetBlob,
    const struct CmContext *context, const sptr<IRemoteObject> &clientCallback)
{
    (void)code;
    DriverDialogIpcParams ipc;
    struct CmParamSet *paramSet = nullptr;
    int32_t ret = ParseOpenDriverDialogParams(paramSetBlob, ipc, &paramSet);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("open driver dialog get params failed, ret = %d", ret);
        CmFreeParamSet(&paramSet); /* non-null when CmGetParamSet succeeded but a later parse step failed */
        CmSendResponse(context, CMR_ERROR_INVALID_ARGUMENT, nullptr);
        return;
    }

    /* Server-side caller validation (spec v4 D23) */
    HapTokenInfo hapInfo;
    int32_t callerRet = CheckDriverDialogCaller(hapInfo);
    if (callerRet != CM_SUCCESS) {
        CmFreeParamSet(&paramSet);
        CmSendResponse(context, callerRet, nullptr);
        return;
    }

    CmUkeyAuthDialogManager::GetInstance().InitRealDependencies();
    /* userId for the BMS query: resolved via CmGetProcessInfoForIPC (same
     * pattern as cm_sa.cpp OnRemoteRequest; the incoming context is actually
     * the reply parcel and must not be used for this) */
    struct CmContext procContext = {0};
    (void)CmGetProcessInfoForIPC(&procContext);
    /* abilityName/keyUri/customData point into the paramSet buffer;
     * OpenDriverDialog consumes them synchronously and never references them after */
    UkeyDriverDialogRequest req;
    req.abilityName = ipc.abilityName;
    req.abilityType = ipc.abilityType;
    req.keyUri = ipc.keyUri;
    req.callerUid = static_cast<uint32_t>(IPCSkeleton::GetCallingUid());
    req.callerBundleName = hapInfo.bundleName;
    req.userId = static_cast<int32_t>(procContext.userId);
    req.timeoutSec = ipc.timeoutSec;
    req.customData = ipc.customData;
    req.clientCallback = clientCallback;
    ret = CmUkeyAuthDialogManager::GetInstance().OpenDriverDialog(req);
    CmFreeParamSet(&paramSet);
    CmSendResponse(context, ret, nullptr);
}

void CmIpcServiceReportUkeyAuthResult(uint32_t code, const struct CmBlob *paramSetBlob,
    const struct CmContext *context)
{
    (void)code;
    struct CmParamSet *paramSet = nullptr;
    struct CmBlob requestId = { 0, nullptr };
    uint32_t resultCode = 0;
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &requestId },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = &resultCode },
    };
    int32_t ret = CmGetParamSet(reinterpret_cast<struct CmParamSet *>(paramSetBlob->data),
        paramSetBlob->size, &paramSet);
    if (ret == CM_SUCCESS) {
        ret = CmParamSetToParams(paramSet, params, CM_ARRAY_SIZE(params));
    }
    if (ret != CM_SUCCESS) {
        CM_LOG_E("report ukey result get params failed, ret = %d", ret);
        CmFreeParamSet(&paramSet);
        CmSendResponse(context, CMR_ERROR_INVALID_ARGUMENT, nullptr);
        return;
    }

    /* Identity check: only HAP tokens may report (bundleName is matched by the manager against the session driver) */
    HapTokenInfo hapInfo;
    if (AccessTokenKit::GetHapTokenInfo(IPCSkeleton::GetCallingTokenID(), hapInfo) != ERR_OK) {
        CM_LOG_E("report ukey result caller is not hap token, callingUid = %d",
            static_cast<int32_t>(IPCSkeleton::GetCallingUid()));
        CmFreeParamSet(&paramSet);
        CmSendResponse(context, CMR_DIALOG_ERROR_INTERNAL, nullptr);
        return;
    }

    std::string reqId(reinterpret_cast<char *>(requestId.data), requestId.size);
    ret = CmUkeyAuthDialogManager::GetInstance().OnReport(reqId, hapInfo.bundleName,
        static_cast<int32_t>(resultCode));
    CmFreeParamSet(&paramSet);
    CmSendResponse(context, ret, nullptr);
}
} // namespace OHOS::Security::CertManager
