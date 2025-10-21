/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "cm_napi_dialog_common.h"

#include <unordered_map>
#include "securec.h"

#include "cm_log.h"
#include "cm_type.h"
#include "iservice_registry.h"
#include "bundle_mgr_proxy.h"
#include "system_ability_definition.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"

using namespace OHOS::Security::AccessToken;

#define BYTE_SHIFT_16           0x10
#define BYTE_SHIFT_8            0x08
#define BYTE_SHIFT_6            0x06
#define BASE64_URL_TABLE_SIZE   0x3F
#define BASE64_GROUP_NUM        3
#define BYTE_INDEX_ZONE         0
#define BYTE_INDEX_ONE          1
#define BYTE_INDEX_TWO          2
#define BYTE_INDEX_THREE        3
#define BASE64_PADDING          "="
#define BYTE_END_ONE            1
#define BYTE_END_TWO            2

static const char g_base64Table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
namespace CMNapi {
namespace {
constexpr int CM_MAX_DATA_LEN = 0x6400000; // The maximum length is 100M

static const std::string DIALOG_NO_PERMISSION_MSG = "the caller has no permission";
static const std::string DIALOG_INVALID_PARAMS_MSG = "the input parameters is invalid";
static const std::string DIALOG_GENERIC_MSG = "There is an internal error. Possible causes: "
    "1.IPC communication failed. 2.Memory operation error.";
static const std::string DIALOG_OPERATION_CANCELS_MSG = "the user cancels the installation operation";
static const std::string DIALOG_INSTALL_FAILED_MSG = "the user install certificate failed"
    " in the certificate manager dialog";
static const std::string DIALOG_NOT_SUPPORTED_MSG = "the API is not supported on this device";

static const std::string DIALOG_OPERATION_FAILED_MSG = "the user operation failed "
    "in the certification manager dialog: ";
static const std::string PARSE_CERT_FAILED_MSG = "parse the certificate failed.";
static const std::string ADVANCED_SECURITY_MSG = "the device enters advanced security mode.";
static const std::string INCORRECT_FORMAT_MSG = "the certificate is in an invalid format.";
static const std::string MAX_QUANTITY_REACHED_MSG = "the number of certificates or credentials "
    "reaches the maxinum allowed.";
static const std::string SA_INTERNAL_ERROR_MSG = "sa internal error.";
static const std::string NOT_EXIST_MSG = "the certificate dose not exist.";
static const std::string NOT_ENTERPRISE_DEVICE_MSG = "The operation does not comply with the device security policy,"
    "such as the device does not allow users to manage the ca certificate of the global user.";
static const std::string CAPABILITY_NOT_SUPPORTED_MSG = "the capability not supported.";

static const std::unordered_map<int32_t, int32_t> DIALOG_CODE_TO_JS_CODE_MAP = {
    // no permission
    { CMR_DIALOG_ERROR_PERMISSION_DENIED, HAS_NO_PERMISSION },
    // internal error
    { CMR_DIALOG_ERROR_INTERNAL, DIALOG_ERROR_GENERIC },
    // the user cancels the installation operation
    { CMR_DIALOG_ERROR_OPERATION_CANCELS, DIALOG_ERROR_OPERATION_CANCELED },
    // the user install certificate failed in the certificate manager dialog
    { CMR_DIALOG_ERROR_INSTALL_FAILED, DIALOG_ERROR_INSTALL_FAILED },
    // the API is not supported on this device
    { CMR_DIALOG_ERROR_NOT_SUPPORTED, DIALOG_ERROR_NOT_SUPPORTED },
    // The input parameter is invalid
    { CMR_DIALOG_ERROR_PARAM_INVALID, PARAM_ERROR },
    // The device is not supported
    { CMR_DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED, DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED},

    { CMR_DIALOG_ERROR_PARSE_CERT_FAILED, DIALOG_ERROR_INSTALL_FAILED },
    { CMR_DIALOG_ERROR_ADVANCED_SECURITY, DIALOG_ERROR_INSTALL_FAILED },
    { CMR_DIALOG_ERROR_INCORRECT_FORMAT, DIALOG_ERROR_INSTALL_FAILED },
    { CMR_DIALOG_ERROR_MAX_QUANTITY_REACHED, DIALOG_ERROR_INSTALL_FAILED },
    { CMR_DIALOG_ERROR_SA_INTERNAL_ERROR, DIALOG_ERROR_INSTALL_FAILED },
    { CMR_DIALOG_ERROR_NOT_EXIST, DIALOG_ERROR_INSTALL_FAILED },
    { CMR_DIALOG_ERROR_NOT_ENTERPRISE_DEVICE, DIALOG_ERROR_NOT_COMPLY_SECURITY_POLICY },
};

static const std::unordered_map<int32_t, std::string> DIALOG_CODE_TO_MSG_MAP = {
    { CMR_DIALOG_ERROR_PERMISSION_DENIED, DIALOG_NO_PERMISSION_MSG },
    { CMR_DIALOG_ERROR_INTERNAL, DIALOG_GENERIC_MSG },
    { CMR_DIALOG_ERROR_OPERATION_CANCELS, DIALOG_OPERATION_CANCELS_MSG },
    { CMR_DIALOG_ERROR_INSTALL_FAILED, DIALOG_INSTALL_FAILED_MSG },
    { CMR_DIALOG_ERROR_NOT_SUPPORTED, DIALOG_NOT_SUPPORTED_MSG },
    { CMR_DIALOG_ERROR_NOT_ENTERPRISE_DEVICE, NOT_ENTERPRISE_DEVICE_MSG },
    { CMR_DIALOG_ERROR_PARAM_INVALID, DIALOG_INVALID_PARAMS_MSG },
    { CMR_DIALOG_ERROR_CAPABILITY_NOT_SUPPORTED, CAPABILITY_NOT_SUPPORTED_MSG},

    { CMR_DIALOG_ERROR_PARSE_CERT_FAILED, DIALOG_OPERATION_FAILED_MSG + PARSE_CERT_FAILED_MSG },
    { CMR_DIALOG_ERROR_ADVANCED_SECURITY, DIALOG_OPERATION_FAILED_MSG + ADVANCED_SECURITY_MSG },
    { CMR_DIALOG_ERROR_INCORRECT_FORMAT, DIALOG_OPERATION_FAILED_MSG + INCORRECT_FORMAT_MSG },
    { CMR_DIALOG_ERROR_MAX_QUANTITY_REACHED, DIALOG_OPERATION_FAILED_MSG + MAX_QUANTITY_REACHED_MSG },
    { CMR_DIALOG_ERROR_SA_INTERNAL_ERROR, DIALOG_OPERATION_FAILED_MSG + SA_INTERNAL_ERROR_MSG },
    { CMR_DIALOG_ERROR_NOT_EXIST, DIALOG_OPERATION_FAILED_MSG + NOT_EXIST_MSG },
};
}  // namespace

static bool CheckBasicPermission(void)
{
    AccessTokenID tokenId = OHOS::IPCSkeleton::GetCallingTokenID();

    int result = AccessTokenKit::VerifyAccessToken(tokenId, "ohos.permission.ACCESS_CERT_MANAGER");
    if (result == PERMISSION_GRANTED) {
        return true;
    }

    return false;
}

void StartUIExtensionAbility(std::shared_ptr<CmUIExtensionRequestContext> asyncContext,
    OHOS::AAFwk::Want want, std::shared_ptr<CmUIExtensionCallback> uiExtCallback)
{
    /*
     * Before starting the UIExtension, the permission is verified for interception.
     * The verification will be performed again in the process of starting the com.ohos.certmanager application.
     */
    if (!CheckBasicPermission()) {
        CM_LOG_E("not has basic permission");
        ThrowError(asyncContext->env, HAS_NO_PERMISSION, DIALOG_NO_PERMISSION_MSG);
        return;
    }

    CM_LOG_D("begin StartUIExtensionAbility");
    auto abilityContext = asyncContext->context;
    if (abilityContext == nullptr) {
        CM_LOG_E("abilityContext is null");
        ThrowError(asyncContext->env, PARAM_ERROR, "abilityContext is null");
        return;
    }
    auto uiContent = abilityContext->GetUIContent();
    if (uiContent == nullptr) {
        CM_LOG_E("uiContent is null");
        ThrowError(asyncContext->env, PARAM_ERROR, "uiContent is null");
        return;
    }

    OHOS::Ace::ModalUIExtensionCallbacks extensionCallbacks = {
        [uiExtCallback](int32_t releaseCode) { uiExtCallback->OnRelease(releaseCode); },
        [uiExtCallback](int32_t resultCode, const OHOS::AAFwk::Want& result) {
            uiExtCallback->OnResult(resultCode, result); },
        [uiExtCallback](const OHOS::AAFwk::WantParams& request) { uiExtCallback->OnReceive(request); },
        [uiExtCallback](int32_t errorCode, const std::string& name, const std::string& message) {
            uiExtCallback->OnError(errorCode, name, message); },
        [uiExtCallback](const std::shared_ptr<OHOS::Ace::ModalUIExtensionProxy>& uiProxy) {
            uiExtCallback->OnRemoteReady(uiProxy); },
        [uiExtCallback]() { uiExtCallback->OnDestroy(); }
    };

    OHOS::Ace::ModalUIExtensionConfig uiExtConfig;
    uiExtConfig.isProhibitBack = false;
    int32_t sessionId = uiContent->CreateModalUIExtension(want, extensionCallbacks, uiExtConfig);
    CM_LOG_I("end CreateModalUIExtension");
    if (sessionId == 0) {
        CM_LOG_E("CreateModalUIExtension failed");
        ThrowError(asyncContext->env, PARAM_ERROR, "CreateModalUIExtension failed");
    }
    uiExtCallback->SetSessionId(sessionId);
    return;
}

static std::string EncodeBase64(const uint8_t *indata, const uint32_t length)
{
    std::string encodeStr("");
    if (indata == nullptr) {
        CM_LOG_E("input param is invalid");
        return encodeStr;
    }
    int i = 0;
    while (i < (int)length) {
        unsigned int octeta = i < (int)length ? *(indata + (i++)) : 0;
        unsigned int octetb = i < (int)length ? *(indata + (i++)) : 0;
        unsigned int octetc = i < (int)length ? *(indata + (i++)) : 0;

        unsigned int triple = (octeta << BYTE_SHIFT_16) + (octetb << BYTE_SHIFT_8) + octetc;

        encodeStr += g_base64Table[(triple >> BYTE_INDEX_THREE * BYTE_SHIFT_6) & BASE64_URL_TABLE_SIZE];
        encodeStr += g_base64Table[(triple >> BYTE_INDEX_TWO   * BYTE_SHIFT_6) & BASE64_URL_TABLE_SIZE];
        encodeStr += g_base64Table[(triple >> BYTE_INDEX_ONE   * BYTE_SHIFT_6) & BASE64_URL_TABLE_SIZE];
        encodeStr += g_base64Table[(triple >> BYTE_INDEX_ZONE  * BYTE_SHIFT_6) & BASE64_URL_TABLE_SIZE];
    }

    switch (BASE64_GROUP_NUM - (i % BASE64_GROUP_NUM)) {
        case BYTE_END_TWO:
            encodeStr.replace(encodeStr.length() - BYTE_END_TWO, 1, BASE64_PADDING);
            encodeStr.replace(encodeStr.length() - BYTE_END_ONE, 1, BASE64_PADDING);
            break;
        case BYTE_END_ONE:
            encodeStr.replace(encodeStr.length() - BYTE_END_ONE, 1, BASE64_PADDING);
            break;
        default:
            break;
    }
    return encodeStr;
}

bool ParseCmUIAbilityContextReq(
    napi_env env, const napi_value& obj, std::shared_ptr<OHOS::AbilityRuntime::AbilityContext>& abilityContext)
{
    bool stageMode = false;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, obj, stageMode);
    if (status != napi_ok || !stageMode) {
        CM_LOG_E("not stage mode");
        return false;
    }

    auto context = OHOS::AbilityRuntime::GetStageModeContext(env, obj);
    if (context == nullptr) {
        CM_LOG_E("get context failed");
        return false;
    }

    abilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(context);
    if (abilityContext == nullptr) {
        CM_LOG_E("get abilityContext failed");
        return false;
    }
    CM_LOG_I("end ParseUIAbilityContextReq");
    return true;
}

napi_value ParseUint32(napi_env env, napi_value object, uint32_t &store)
{
    napi_valuetype type;
    napi_typeof(env, object, &type);
    if (type != napi_number) {
        CM_LOG_E("param type is not number");
        return nullptr;
    }
    uint32_t temp = 0;
    if (napi_get_value_uint32(env, object, &temp) != napi_ok) {
        CM_LOG_E("failed to get uint value");
        return nullptr;
    }
    store = temp;
    return GetInt32(env, 0);
}

napi_value ParseBoolean(napi_env env, napi_value object, bool &status)
{
    napi_valuetype type;
    napi_typeof(env, object, &type);
    if (type != napi_boolean) {
        CM_LOG_E("param type is not bool");
        return nullptr;
    }
    bool temp = false;
    if (napi_get_value_bool(env, object, &temp) != napi_ok) {
        CM_LOG_E("failed to get bool value");
        return nullptr;
    }
    status = temp;
    return GetInt32(env, 0);
}

napi_value ParseString(napi_env env, napi_value obj, CmBlob *&blob)
{
    napi_valuetype type = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, obj, &type));
    if (type != napi_string) {
        CM_LOG_E("the type of param is not string");
        return nullptr;
    }
    size_t length = 0;
    napi_status status = napi_get_value_string_utf8(env, obj, nullptr, 0, &length);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        CM_LOG_E("could not get string length");
        return nullptr;
    }

    if ((length == 0) || (length > CM_MAX_DATA_LEN)) {
        CM_LOG_E("input string length is 0 or too large, length: %d", length);
        return nullptr;
    }

    char *data = static_cast<char *>(CmMalloc(length + 1));
    if (data == nullptr) {
        napi_throw_error(env, nullptr, "could not alloc memory");
        CM_LOG_E("could not alloc memory");
        return nullptr;
    }
    (void)memset_s(data, length + 1, 0, length + 1);

    size_t res = 0;
    status = napi_get_value_string_utf8(env, obj, data, length + 1, &res);
    if (status != napi_ok) {
        CmFree(data);
        GET_AND_THROW_LAST_ERROR((env));
        CM_LOG_E("could not get string");
        return nullptr;
    }

    blob = static_cast<CmBlob *>(CmMalloc(sizeof(CmBlob)));
    if (blob == nullptr) {
        CmFree(data);
        napi_throw_error(env, nullptr, "could not alloc memory");
        CM_LOG_E("could not alloc memory");
        return nullptr;
    }
    blob->data = reinterpret_cast<uint8_t *>(data);
    blob->size = static_cast<uint32_t>((length + 1) & UINT32_MAX);

    return GetInt32(env, 0);
}

napi_value GetUint8ArrayToBase64Str(napi_env env, napi_value object, std::string &certArray)
{
    napi_typedarray_type arrayType;
    napi_value arrayBuffer = nullptr;
    size_t length = 0;
    size_t offset = 0;
    void *certData = nullptr;

    napi_status status = napi_get_typedarray_info(
        env, object, &arrayType, &length, static_cast<void **>(&certData), &arrayBuffer, &offset);
    if (arrayType != napi_uint8_array) {
        return nullptr;
    }
    if (status != napi_ok) {
        CM_LOG_E("the type of param is not uint8_array");
        return nullptr;
    }
    if (length > CM_MAX_DATA_LEN) {
        CM_LOG_E("certData is too large, length = %x", length);
        return nullptr;
    }
    uint8_t *data = nullptr;
    if (length == 0) {
        CM_LOG_D("The memory length created is only 1 Byte");
        // The memory length created is only 1 Byte
        data = static_cast<uint8_t *>(CmMalloc(1));
    } else {
        data = static_cast<uint8_t *>(CmMalloc(length));
    }
    if (data == nullptr) {
        CM_LOG_E("Malloc failed");
        return nullptr;
    }
    (void)memset_s(data, length, 0, length);
    if (memcpy_s(data, length, certData, length) != EOK) {
        CmFree(data);
        CM_LOG_E("memcpy_s fail, length = %x", length);
        return nullptr;
    }
    std::string encode = EncodeBase64(data, length);
    certArray = encode;
    CmFree(data);
    return GetInt32(env, 0);
}

napi_value GetCertTypeArray(napi_env env, napi_value object, std::vector<int32_t> &certTypes)
{
    bool isArray = false;
    napi_status status = napi_is_array(env, object, &isArray);
    if ((status != napi_ok) || (!isArray)) {
        CM_LOG_E("object is not array");
        return nullptr;
    }
    uint32_t length = 0;
    status = napi_get_array_length(env, object, &length);
    if (status != napi_ok || length == 0) {
        CM_LOG_E("failed to get length");
        return nullptr;
    }

    for (uint32_t i = 0; i < length; ++i) {
        napi_value element = nullptr;
        if (napi_get_element(env, object, i, &element) != napi_ok) {
            CM_LOG_E("failed to get %u-th element", i);
            return nullptr;
        }
        uint32_t certType = 0;
        if (ParseUint32(env, element, certType)== nullptr) {
            return nullptr;
        }
        
        if (certType < CA_CERT || certType > CREDENTIAL_UKEY) {
            CM_LOG_E("certtype is invalid");
            return nullptr;
        }
        certTypes.push_back(static_cast<int32_t>(certType));
    }
    return GetInt32(env, 0);
}

static const char *GetJsErrorMsg(int32_t errCode)
{
    auto iter = DIALOG_CODE_TO_MSG_MAP.find(errCode);
    if (iter != DIALOG_CODE_TO_MSG_MAP.end()) {
        return (iter->second).c_str();
    }
    return DIALOG_GENERIC_MSG.c_str();
}

int32_t TranformErrorCode(int32_t errorCode)
{
    auto iter = DIALOG_CODE_TO_JS_CODE_MAP.find(errorCode);
    if (iter != DIALOG_CODE_TO_JS_CODE_MAP.end()) {
        return iter->second;
    }
    return DIALOG_ERROR_GENERIC;
}

napi_value GenerateBusinessError(napi_env env, int32_t errorCode)
{
    const char *errorMessage = GetJsErrorMsg(errorCode);
    if (errorMessage == nullptr) {
        return nullptr;
    }

    napi_value code = nullptr;
    int32_t outputCode = TranformErrorCode(errorCode);
    NAPI_CALL(env, napi_create_int32(env, outputCode, &code));
    napi_value message = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, errorMessage, NAPI_AUTO_LENGTH, &message));

    napi_value businessErrorMsg = nullptr;
    NAPI_CALL(env, napi_create_error(env, nullptr, message, &businessErrorMsg));
    NAPI_CALL(env, napi_set_named_property(env, businessErrorMsg, BUSINESS_ERROR_PROPERTY_CODE.c_str(), code));
    return businessErrorMsg;
}

void ThrowError(napi_env env, int32_t errorCode, const std::string errMsg)
{
    napi_value paramsError = nullptr;
    napi_value outCode = nullptr;
    napi_value message = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, errorCode, &outCode));
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &message));
    NAPI_CALL_RETURN_VOID(env, napi_create_error(env, nullptr, message, &paramsError));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, paramsError,
        BUSINESS_ERROR_PROPERTY_CODE.c_str(), outCode));
    NAPI_CALL_RETURN_VOID(env, napi_throw(env, paramsError));
}

void GeneratePromise(napi_env env, napi_deferred deferred, int32_t resultCode,
    napi_value *result, int32_t length)
{
    if (length < RESULT_NUMBER) {
        return;
    }
    if (resultCode == CM_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, deferred, result[1]));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, deferred, result[0]));
    }
}

static OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> GetBundleMgrProxy()
{
    auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        CM_LOG_E("fail to get system ability mgr.");
        return nullptr;
    }

    auto remoteObject = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        CM_LOG_E("fail to get bundle manager proxy.");
        return nullptr;
    }
    return OHOS::iface_cast<OHOS::AppExecFwk::IBundleMgr>(remoteObject);
}

static int32_t GetCallerBundleInfo(OHOS::AppExecFwk::BundleInfo &bundleInfo)
{
    OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> bundleMgrProxy = GetBundleMgrProxy();
    if (bundleMgrProxy == nullptr) {
        CM_LOG_E("Failed to get bundle manager proxy.");
        return CM_FAILURE;
    }

    int32_t flags = static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT) |
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION) |
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(OHOS::AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY);
    int32_t resCode = bundleMgrProxy->GetBundleInfoForSelf(flags, bundleInfo);
    if (resCode != CM_SUCCESS) {
        CM_LOG_E("Failed to get bundleInfo, resCode is %d", resCode);
        return CM_FAILURE;
    }
    return CM_SUCCESS;
}

int32_t GetCallerLabelName(std::shared_ptr<CmUIExtensionRequestContext> asyncContext)
{
    if (asyncContext == nullptr || asyncContext->context == nullptr) {
        CM_LOG_E("invalid param");
        return CM_FAILURE;
    }
    OHOS::AppExecFwk::BundleInfo bundleInfo;
    if (GetCallerBundleInfo(bundleInfo) != CM_SUCCESS) {
        CM_LOG_E("Failed to get caller bundleInfo");
        return CM_FAILURE;
    }

    if (asyncContext->context->GetResourceManager() == nullptr) {
        CM_LOG_E("context get resourcemanager faild");
        return CMR_ERROR_NULL_POINTER;
    }

    int32_t resCode = asyncContext->context->GetResourceManager()->GetStringById(bundleInfo.applicationInfo.labelId,
        asyncContext->labelName);
    if (resCode != CM_SUCCESS) {
        CM_LOG_E("getStringById is faild, resCode is %d", resCode);
        return CM_FAILURE;
    }
    return CM_SUCCESS;
}
}  // namespace CertManagerNapi
