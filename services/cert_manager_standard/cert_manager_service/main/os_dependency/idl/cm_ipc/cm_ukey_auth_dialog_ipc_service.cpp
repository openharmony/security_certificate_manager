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

/* 与 cm_ipc_service.c 其他处理器不同，本文件处理器不构造 CmContext：UKey 弹框
 * 会话不触及按用户/uid 隔离的存储数据，调用方身份经 IPCSkeleton（uid/tokenId）
 * 获取并已完成权限与 HAP 身份校验。 */

void CmIpcServiceOpenUkeyAuthDialog(uint32_t code, const struct CmBlob *paramSetBlob,
    const struct CmContext *context, const sptr<IRemoteObject> &clientCallback)
{
    (void)code;
    struct CmParamSet *paramSet = nullptr;
    struct CmBlob keyUri = { 0, nullptr };
    uint32_t timeoutMs = 0; /* 0 = 未传，SA 侧取默认最大值 */
    struct CmParamOut params[] = {
        { .tag = CM_TAG_PARAM0_BUFFER, .blob = &keyUri },
        { .tag = CM_TAG_PARAM1_UINT32, .uint32Param = &timeoutMs },
    };
    int32_t ret = CmGetParamSet(reinterpret_cast<struct CmParamSet *>(paramSetBlob->data),
        paramSetBlob->size, &paramSet);
    if (ret == CM_SUCCESS) {
        ret = CmParamSetToParams(paramSet, params, CM_ARRAY_SIZE(params));
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
    ret = CmUkeyAuthDialogManager::GetInstance().OpenDialog(&keyUri,
        static_cast<uint32_t>(IPCSkeleton::GetCallingUid()), timeoutMs, clientCallback);
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
