/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "cm_napi_get_cert_store_path.h"

#include <unistd.h>

#include "cm_log.h"
#include "cm_napi_common.h"
#include "cm_type.h"

#include "bundle_mgr_proxy.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace CMNapi {
namespace {
constexpr int CM_NAPI_GET_CERT_STORE_PATH_ARGS = 1;
}

static sptr<BundleMgrProxy> GetBundleMgrProxy()
{
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        CM_LOG_E("Failed to get system ability mgr.");
        return nullptr;
    }

    auto remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        CM_LOG_E("Failed to get bundle manager proxy.");
        return nullptr;
    }
    return iface_cast<BundleMgrProxy>(remoteObject);
}

static int32_t GetUserCaStorePath(const enum CmCertScope certScope, string &path)
{
    path += CA_STORE_PATH_USER_SANDBOX_BASE;
    if (certScope == CM_GLOBAL_USER) {
        path += "0";
        return CM_SUCCESS;
    }

    int32_t userId = 0;
    sptr<BundleMgrProxy> bundleMgrProxy = GetBundleMgrProxy();
    if (bundleMgrProxy == nullptr) {
        CM_LOG_E("Failed to get bundle manager proxy.");
        return CM_FAILURE;
    }

    BundleInfo bundleInfo;
    int32_t flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    int32_t ret = bundleMgrProxy->GetBundleInfoForSelf(flags, bundleInfo);
    if (ret != 0) {
        CM_LOG_E("Failed to get bundle info for self");
        return CM_FAILURE;
    }

    ret = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(bundleInfo.applicationInfo.uid, userId);
    if (ret != 0) {
        CM_LOG_E("Failed to get userid from uid[%d]", bundleInfo.applicationInfo.uid);
        return CM_FAILURE;
    }

    path += to_string(userId);
    return CM_SUCCESS;
}

static bool IsDirExist(const char *fileName)
{
    if (fileName == nullptr) {
        return false;
    }
    if (access(fileName, F_OK) == 0) {
        return true;
    }
    return false;
}

static int32_t GetSysCaStorePath(napi_env env, const enum CmCertAlg certAlg, string &path)
{
    if (certAlg == CM_ALG_INTERNATIONAL) {
        path = CA_STORE_PATH_SYSTEM;
        return CM_SUCCESS;
    }
    if (!IsDirExist(SYSTEM_CA_STORE_GM)) {
        CM_LOG_E("system gm ca store path not exist");
        ThrowError(env, STORE_PATH_NOT_SUPPORTED, "the device does not support specified certificate store path");
        return STORE_PATH_NOT_SUPPORTED;
    } else {
        path = CA_STORE_PATH_SYSTEM_SM;
    }
    return CM_SUCCESS;
}

static napi_value GetCertStorePath(napi_env env, const enum CmCertType certType, const enum CmCertScope certScope,
    const enum CmCertAlg certAlg)
{
    string path = "";
    if (certType == CM_CA_CERT_SYSTEM) {
        int32_t ret = GetSysCaStorePath(env, certAlg, path);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get system ca path, ret = %d", ret);
            return nullptr;
        }
    } else {
        int32_t ret = GetUserCaStorePath(certScope, path);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get user ca path.");
            ThrowError(env, INNER_FAILURE, GENERIC_MSG);
            return nullptr;
        }
    }

    napi_value result = nullptr;
    napi_status status = napi_create_string_utf8(env, path.c_str(), path.length(), &result);
    if (status != napi_ok) {
        CM_LOG_E("Failed to creat string out.");
        ThrowError(env, INNER_FAILURE, GENERIC_MSG);
        return nullptr;
    }
    return result;
}

static int32_t GetCertScope(napi_env env, napi_value arg, uint32_t &scope)
{
    bool hasScope = false;
    napi_status status = napi_has_named_property(env, arg, CM_CERT_SCOPE_STR.c_str(), &hasScope);
    if (status != napi_ok || !hasScope) {
        CM_LOG_D("property certScope not exist");
        return CM_SUCCESS; /* certScope is optional parameter, can be unset */
    }

    napi_value obj = nullptr;
    status = napi_get_named_property(env, arg, CM_CERT_SCOPE_STR.c_str(), &obj);
    if (status != napi_ok) {
        CM_LOG_E("Failed to get property certScope");
        return CM_FAILURE;
    }

    napi_valuetype valueType;
    status = napi_typeof(env, obj, &valueType);
    if (status != napi_ok) {
        CM_LOG_E("Failed to get property type");
        return CM_FAILURE;
    }

    if (valueType == napi_undefined) {
        CM_LOG_D("property certScope is undefined");
        return CM_SUCCESS; /* certScope is optional parameter, can be undefined */
    }

    napi_value result = ParseUint32(env, obj, scope);
    if (result == nullptr) {
        CM_LOG_E("Failed to get scope value");
        return CM_FAILURE;
    }

    if (!IsValidCertScope(scope)) { /* the scope needs to be checked regardless of the certType type */
        CM_LOG_E("certScope[%u] is invalid", scope);
        return CM_FAILURE;
    }

    return CM_SUCCESS;
}

static int32_t GetAndCheckCertType(napi_env env, napi_value arg, uint32_t &type)
{
    napi_value certType = nullptr;
    napi_status status = napi_get_named_property(env, arg, CM_CERT_TYPE_STR.c_str(), &certType);
    if (status != napi_ok) {
        CM_LOG_E("Failed to get certType");
        return CM_FAILURE;
    }

    napi_value result = ParseUint32(env, certType, type);
    if (result == nullptr) {
        CM_LOG_E("Failed to get certType value");
        return CM_FAILURE;
    }

    if (!IsValidCertType(type)) {
        CM_LOG_E("certType[%u] is invalid", type);
        return CM_FAILURE;
    }
    return CM_SUCCESS;
}

static int32_t GetAndCheckCertScope(napi_env env, napi_value arg, const enum CmCertType type, uint32_t &scope)
{
    int32_t ret = GetCertScope(env, arg, scope);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get certScope");
        return CM_FAILURE;
    }

    if ((type == CM_CA_CERT_USER) && (scope == INIT_INVALID_VALUE)) {
        CM_LOG_E("get user ca cert store path, but scope is not set");
        return CM_FAILURE;
    }
    return CM_SUCCESS;
}

static int32_t GetAndCheckCertAlg(napi_env env, napi_value arg, uint32_t &algorithm)
{
    bool hasAlg = false;
    napi_status status = napi_has_named_property(env, arg, CM_CERT_ALG_STR.c_str(), &hasAlg);
    if (status != napi_ok || !hasAlg) {
        CM_LOG_D("property certAlg not exist");
        algorithm = CM_ALG_INTERNATIONAL;
        return SUCCESS;
    }

    napi_value certAlg = nullptr;
    status = napi_get_named_property(env, arg, CM_CERT_ALG_STR.c_str(), &certAlg);
    if (status != napi_ok) {
        CM_LOG_E("Failed to get certAlg");
        return CM_FAILURE;
    }

    napi_value result = ParseUint32(env, certAlg, algorithm);
    if (result == nullptr) {
        CM_LOG_E("Failed to get certAlg value");
        return CM_FAILURE;
    }

    if (!IsValidCertAlg(algorithm)) {
        CM_LOG_E("certAlg[%u] is invalid", algorithm);
        return CM_FAILURE;
    }
    return CM_SUCCESS;
}

napi_value CMNapiGetCertStorePath(napi_env env, napi_callback_info info)
{
    CM_LOG_I("get cert store path enter");
    // get params
    size_t argc = CM_NAPI_GET_CERT_STORE_PATH_ARGS;
    napi_value argv[CM_NAPI_GET_CERT_STORE_PATH_ARGS] = { nullptr };
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok) {
        ThrowError(env, PARAM_ERROR, "Failed to get params");
        return nullptr;
    }

    // check param count should be 1.
    if (argc != CM_NAPI_GET_CERT_STORE_PATH_ARGS) {
        ThrowError(env, PARAM_ERROR, "param count invalid, should be 1.");
        CM_LOG_E("args count[%zu] invalid, should be 1.", argc);
        return nullptr;
    }

    uint32_t type;
    int32_t ret = GetAndCheckCertType(env, argv[0], type);
    if (ret != CM_SUCCESS) {
        ThrowError(env, PARAM_ERROR, "Failed to get param certType");
        return nullptr;
    }

    uint32_t scope = INIT_INVALID_VALUE;
    ret = GetAndCheckCertScope(env, argv[0], static_cast<CmCertType>(type), scope);
    if (ret != CM_SUCCESS) {
        ThrowError(env, PARAM_ERROR, "Failed to get param certScope");
        return nullptr;
    }

    uint32_t algorithm;
    ret = GetAndCheckCertAlg(env, argv[0], algorithm);
    if (ret != CM_SUCCESS) {
        ThrowError(env, PARAM_ERROR, "Failed to get param certAlg");
        return nullptr;
    }

    napi_value res = GetCertStorePath(env, static_cast<CmCertType>(type), static_cast<CmCertScope>(scope),
        static_cast<CmCertAlg>(algorithm));
    CM_LOG_I("get cert store path end");
    return res;
}
}  // namespace CertManagerNapi
