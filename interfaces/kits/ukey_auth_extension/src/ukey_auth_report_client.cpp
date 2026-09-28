/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ukey_auth_report_client.h"

#include <chrono>
#include <thread>

#include "securec.h"

#include "cert_manager_service_ipc_interface_code.h"
#include "cm_log.h"
#include "cm_type.h"

#include "iservice_registry.h"
#include "message_option.h"
#include "message_parcel.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr int32_t CM_SA_ID = 3512;
constexpr int32_t LOAD_SA_TIMEOUT_SECONDS = 3;
const std::u16string CM_SA_DESCRIPTOR = u"ohos.security.cm.service";
/* The SA-side requestId is a 32-char hex of 16 CSPRNG bytes; the cap leaves defensive headroom */
constexpr uint32_t UKEY_REPORT_REQUEST_ID_MAX_LEN = 64;
constexpr uint32_t UKEY_REPORT_PARAM_CNT = 2;
/* On-demand cold-start race: the SA may report this binder error for the
 * first request; wait and retry once */
constexpr int32_t IPC_ERR_SA_STARTING = 29201;
constexpr int32_t UKEY_REPORT_RETRY_WAIT_MS = 500;

/* Wire format identical to the CmFreshParamSet(isCopy=true) output in
 * cm_param.c: [CmParamSet header][CmParam x2][requestId bytes], blob data
 * right after the params; blob.data is an absolute-address placeholder
 * (overwritten by the SA-side FreshParamSet, the value is not read) */
constexpr uint32_t UKEY_REPORT_PARAM_SET_BUFFER_SIZE = sizeof(struct CmParamSet) +
    UKEY_REPORT_PARAM_CNT * sizeof(struct CmParam) + UKEY_REPORT_REQUEST_ID_MAX_LEN;

sptr<IRemoteObject> GetCertManagerSa()
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        CM_LOG_E("get system ability manager failed");
        return nullptr;
    }
    sptr<IRemoteObject> object = saManager->CheckSystemAbility(CM_SA_ID);
    if (object != nullptr) {
        return object;
    }
    return saManager->LoadSystemAbility(CM_SA_ID, LOAD_SA_TIMEOUT_SECONDS);
}

int32_t BuildUkeyReportParamSet(const std::string &requestId, int32_t resultCode,
    uint8_t *buffer, uint32_t bufferSize, uint32_t &paramSetSize)
{
    uint32_t requestIdLen = static_cast<uint32_t>(requestId.size());
    if (requestIdLen == 0 || requestIdLen > UKEY_REPORT_REQUEST_ID_MAX_LEN) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    uint32_t blobOffset = sizeof(struct CmParamSet) + UKEY_REPORT_PARAM_CNT * sizeof(struct CmParam);
    paramSetSize = blobOffset + requestIdLen;
    if (paramSetSize > bufferSize) {
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (memset_s(buffer, bufferSize, 0, paramSetSize) != EOK) {
        CM_LOG_E("clear report param buffer failed");
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    auto *paramSet = reinterpret_cast<struct CmParamSet *>(buffer);
    paramSet->paramSetSize = paramSetSize;
    paramSet->paramsCnt = UKEY_REPORT_PARAM_CNT;
    struct CmParam *params = reinterpret_cast<struct CmParam *>(buffer + sizeof(struct CmParamSet));
    params[0].tag = CM_TAG_PARAM0_BUFFER;
    params[0].blob.size = requestIdLen;
    params[0].blob.data = buffer + blobOffset;
    params[1].tag = CM_TAG_PARAM1_UINT32;
    params[1].uint32Param = static_cast<uint32_t>(resultCode);
    if (memcpy_s(buffer + blobOffset, bufferSize - blobOffset, requestId.c_str(), requestIdLen) != EOK) {
        return CMR_ERROR_MEM_OPERATION_COPY;
    }
    return CM_SUCCESS;
}

int32_t SendUkeyReportOnce(const uint8_t *paramSet, uint32_t paramSetSize, int32_t &replyCode)
{
    sptr<IRemoteObject> sa = GetCertManagerSa();
    if (sa == nullptr) {
        sa = GetCertManagerSa();
    }
    if (sa == nullptr) {
        CM_LOG_E("certificate manager sa is null");
        return CMR_ERROR_NULL_POINTER;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option = MessageOption::TF_SYNC;
    data.WriteInterfaceToken(CM_SA_DESCRIPTOR);
    data.WriteUint32(paramSetSize);
    if (!data.WriteBuffer(paramSet, static_cast<size_t>(paramSetSize))) {
        CM_LOG_E("write report param set failed");
        return CMR_ERROR_IPC_WRITE_FAIL;
    }
    int32_t err = sa->SendRequest(static_cast<uint32_t>(CM_MSG_REPORT_UKEY_AUTH_RESULT),
        data, reply, option);
    if (err != 0) {
        return err;
    }
    replyCode = reply.ReadInt32();
    return CM_SUCCESS;
}
} // namespace

int32_t ReportUkeyAuthResultViaIpc(const std::string &requestId, int32_t resultCode)
{
    alignas(alignof(struct CmParamSet)) uint8_t buffer[UKEY_REPORT_PARAM_SET_BUFFER_SIZE] = {0};
    uint32_t paramSetSize = 0;
    int32_t ret = BuildUkeyReportParamSet(requestId, resultCode, buffer, sizeof(buffer), paramSetSize);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("build ukey report param set failed, ret = %d", ret);
        return ret;
    }

    int32_t replyCode = CM_FAILURE;
    ret = SendUkeyReportOnce(reinterpret_cast<const uint8_t *>(&buffer), paramSetSize, replyCode);
    if (ret == IPC_ERR_SA_STARTING) {
        CM_LOG_W("sa may be starting, retry once");
        std::this_thread::sleep_for(std::chrono::milliseconds(UKEY_REPORT_RETRY_WAIT_MS));
        ret = SendUkeyReportOnce(reinterpret_cast<const uint8_t *>(&buffer), paramSetSize, replyCode);
    }
    if (ret != CM_SUCCESS) {
        CM_LOG_E("report ukey auth result request failed, ret = %d", ret);
        return ret;
    }
    return replyCode;
}
} // namespace AbilityRuntime
} // namespace OHOS
