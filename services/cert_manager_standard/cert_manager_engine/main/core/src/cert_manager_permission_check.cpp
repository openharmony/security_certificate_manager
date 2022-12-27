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

#include "cm_log.h"

using namespace OHOS::Security::AccessToken;

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

bool CmIsSystemApp(void)
{
    return true;
}

bool CmIsSystemAppByStoreType(const uint32_t store)
{
    if (store == CM_CREDENTIAL_STORE) { /* only care about public credential */
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
        default:
            return false;
    }
}
