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
/* ForDriver OPEN 请求 paramSet 解析结果（blob 指向 paramSet 缓冲，paramSet 由
 * 调用方持有并在处理器同步消费后释放） */
struct DriverDialogIpcParams {
    struct CmBlob abilityName;
    uint32_t abilityType = 0;
    struct CmBlob keyUri;
    uint32_t timeoutSec = 0;
    struct CmBlob customData;
};

/* 解析成功时 *paramSet 由调用方持有（成功/失败路径内部均不释放） */
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
} // namespace

/* 与 cm_ipc_service.c 其他处理器不同，本文件处理器不构造 CmContext：UKey 弹框
 * 会话不触及按用户/uid 隔离的存储数据，调用方身份经 IPCSkeleton（uid/tokenId）
 * 获取并已完成权限与 HAP 身份校验。 */

void CmIpcServiceOpenUkeyAuthDialog(uint32_t code, const struct CmBlob *paramSetBlob,
    const struct CmContext *context, const sptr<IRemoteObject> &clientCallback)
{
    (void)code;
    struct CmParamSet *paramSet = nullptr;
    struct CmBlob keyUri = { 0, nullptr };
    uint32_t timeoutSec = 0; /* 0 = 未传（秒），SA 侧取默认 300s，显式值 clamp 到 [3min, 10min] */
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &keyUri },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = &timeoutSec },
    };
    int32_t ret = CmGetParamSet(reinterpret_cast<struct CmParamSet *>(paramSetBlob->data),
        paramSetBlob->size, &paramSet);
    if (ret == CM_SUCCESS) {
        ret = CmParamSetToParams(paramSet, params, CM_ARRAY_SIZE(params));
    }
    struct CmBlob customData = { 0, nullptr }; /* 可选：仅自定义弹框下发（spec D18/D19） */
    if (ret == CM_SUCCESS) {
        struct CmParam *customDataParam = nullptr;
        if (CmGetParam(paramSet, CM_TAG_PARAM2_BUFFER, &customDataParam) == CM_SUCCESS) {
            customData = customDataParam->blob;
        }
    }
    if (ret != CM_SUCCESS) {
        CM_LOG_E("open ukey dialog get params failed, ret = %d", ret);
        CmFreeParamSet(&paramSet);
        CmSendResponse(context, CMR_ERROR_INVALID_ARGUMENT, NULL);
        return;
    }

    /* 服务端权限校验（纵深防御；NAPI 侧已有一次） */
    if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(),
        "ohos.permission.ACCESS_CERT_MANAGER") != PERMISSION_GRANTED) {
        CM_LOG_E("open ukey dialog permission denied");
        CmFreeParamSet(&paramSet);
        CmSendResponse(context, CMR_DIALOG_ERROR_PERMISSION_DENIED, NULL);
        return;
    }

    CmUkeyAuthDialogManager::GetInstance().InitRealDependencies();
    /* customData 指向 paramSet 缓冲，OpenDialog 同步消费（写入弹框参数）后即不再引用 */
    ret = CmUkeyAuthDialogManager::GetInstance().OpenDialog(&keyUri,
        static_cast<uint32_t>(IPCSkeleton::GetCallingUid()), timeoutSec, &customData,
        clientCallback);
    CmFreeParamSet(&paramSet);
    CmSendResponse(context, ret, NULL);
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
        CmFreeParamSet(&paramSet); /* CmGetParamSet 成功而后续解析失败时非空 */
        CmSendResponse(context, CMR_ERROR_INVALID_ARGUMENT, NULL);
        return;
    }

    /* 服务端权限校验（spec v4 D23：NAPI 预检之外的纵深防御） */
    if (AccessTokenKit::VerifyAccessToken(IPCSkeleton::GetCallingTokenID(),
        "ohos.permission.CRYPTO_EXTENSION_REGISTER") != PERMISSION_GRANTED) {
        CM_LOG_E("open driver dialog permission denied");
        CmFreeParamSet(&paramSet);
        CmSendResponse(context, CMR_DIALOG_ERROR_PERMISSION_DENIED, NULL);
        return;
    }
    /* 调用方包名：仅 HAP token 放行（bundle 只能来自 IPC token，客户端不可声明，D20/D23） */
    HapTokenInfo hapInfo;
    if (AccessTokenKit::GetHapTokenInfo(IPCSkeleton::GetCallingTokenID(), hapInfo) != ERR_OK) {
        CM_LOG_E("open driver dialog caller is not hap token, callingUid = %d",
            static_cast<int32_t>(IPCSkeleton::GetCallingUid()));
        CmFreeParamSet(&paramSet);
        CmSendResponse(context, CMR_DIALOG_ERROR_INTERNAL, NULL);
        return;
    }

    CmUkeyAuthDialogManager::GetInstance().InitRealDependencies();
    /* BMS 查询用 userId：经 CmGetProcessInfoForIPC 解出（模式同 cm_sa.cpp
     * OnRemoteRequest；入参 context 实为 reply parcel，不得用于此） */
    struct CmContext procContext = {0};
    (void)CmGetProcessInfoForIPC(&procContext);
    /* abilityName/keyUri/customData 指向 paramSet 缓冲，OpenDriverDialog 同步消费后不再引用 */
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
    CmSendResponse(context, ret, NULL);
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
        CmSendResponse(context, CMR_ERROR_INVALID_ARGUMENT, NULL);
        return;
    }

    /* 身份校验：仅 HAP token 可上报（bundleName 由 manager 与会话驱动比对） */
    HapTokenInfo hapInfo;
    if (AccessTokenKit::GetHapTokenInfo(IPCSkeleton::GetCallingTokenID(), hapInfo) != ERR_OK) {
        CM_LOG_E("report ukey result caller is not hap token, callingUid = %d",
            static_cast<int32_t>(IPCSkeleton::GetCallingUid()));
        CmFreeParamSet(&paramSet);
        CmSendResponse(context, CMR_DIALOG_ERROR_INTERNAL, NULL);
        return;
    }

    std::string reqId(reinterpret_cast<char *>(requestId.data), requestId.size);
    ret = CmUkeyAuthDialogManager::GetInstance().OnReport(reqId, hapInfo.bundleName,
        static_cast<int32_t>(resultCode));
    CmFreeParamSet(&paramSet);
    CmSendResponse(context, ret, NULL);
}
} // namespace OHOS::Security::CertManager
