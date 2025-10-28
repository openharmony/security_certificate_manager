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

#include "cert_manager_permission_check.h"

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "bundlemgr/bundle_mgr_proxy.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"

#include "cm_log.h"

using namespace OHOS::Security::AccessToken;
using namespace OHOS;
using namespace AppExecFwk;

static bool HasPermission(const std::string &permissionName)
{
    AccessTokenID tokenId = OHOS::IPCSkeleton::GetCallingTokenID();

    int result = AccessTokenKit::VerifyAccessToken(tokenId, permissionName);
    if (result == PERMISSION_GRANTED) {
        return true;
    }

    return false;
}

bool CmHasPrivilegedPermission(void)
{
    return HasPermission("ohos.permission.ACCESS_CERT_MANAGER_INTERNAL");
}

bool CmHasCommonPermission(void)
{
    return HasPermission("ohos.permission.ACCESS_CERT_MANAGER");
}

bool CmHasEnterpriseUserTrustedPermission(void)
{
    return HasPermission("ohos.permission.ACCESS_ENTERPRISE_USER_TRUSTED_CERT");
}

bool CmHasUserTrustedPermission(void)
{
    return HasPermission("ohos.permission.ACCESS_USER_TRUSTED_CERT");
}

bool CmHasSystemAppPermission(void)
{
    return HasPermission("ohos.permission.ACCESS_SYSTEM_APP_CERT");
}

bool CmIsSystemApp(void)
{
    AccessTokenID tokenId = OHOS::IPCSkeleton::GetCallingTokenID();
    auto tokenType = AccessTokenKit::GetTokenType(tokenId);
    if (tokenType == TOKEN_HAP) { /* only care about hap type */
        uint64_t fullTokenId = OHOS::IPCSkeleton::GetCallingFullTokenID();
        return TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
    }
    return true;
}

bool CmIsSystemAppByStoreType(const uint32_t store)
{
    /* care about public and system credential */
    if (store == CM_CREDENTIAL_STORE || store == CM_SYS_CREDENTIAL_STORE) {
        return CmIsSystemApp();
    }
    return true;
}

bool CmPermissionCheck(const uint32_t store)
{
    switch (store) {
        case CM_CREDENTIAL_STORE:
            return CmHasPrivilegedPermission() && CmHasCommonPermission();
        case CM_PRI_CREDENTIAL_STORE:
            return CmHasCommonPermission();
        case CM_SYS_CREDENTIAL_STORE:
            return CmHasCommonPermission() && CmHasSystemAppPermission();
        default:
            return false;
    }
}

static sptr<IBundleMgr> GetBundleMgr()
{
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        CM_LOG_E("systemAbilityManager is nullptr, please check.");
        return nullptr;
    }
    auto bundleMgrRemoteObj = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleMgrRemoteObj == nullptr) {
        CM_LOG_E("bundleMgrRemoteObj is nullptr, please check.");
        return nullptr;
    }
    sptr<IBundleMgr> bundleMgr = iface_cast<IBundleMgr>(bundleMgrRemoteObj);
    if (bundleMgr == nullptr) {
        CM_LOG_E("iface_cast bundleMgr is nullptr, let's try new proxy way.");
        sptr<IBundleMgr> bundleMgrProxy = new BundleMgrProxy(bundleMgrRemoteObj);
        if (bundleMgrProxy == nullptr) {
            CM_LOG_E("bundleMgrProxy is nullptr, please check.");
            return nullptr;
        }
        bundleMgr = bundleMgrProxy;
    }
    return bundleMgr;
}

// Temporarily process, install all user credentials under the certificate manager uid
bool CmGetCertManagerAppUid(int32_t *uid, int32_t userId)
{
    char bundleName[] = "com.ohos.certmanager";
    auto bundleMgrPtr = GetBundleMgr();
    if (bundleMgrPtr == nullptr) {
        CM_LOG_E("bundleMgrPtr is nullptr");
        return false;
    }

    int32_t tmpUid = bundleMgrPtr->GetUidByBundleName(bundleName, userId);
    if (tmpUid < 0) {
        CM_LOG_E("cert manager uid is invalid, uid: %d", tmpUid);
        return false;
    }

    *uid = tmpUid;
    return true;
}
 