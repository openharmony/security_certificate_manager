/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cm_rdb_open_callback.h"

#include "rdb_errno.h"

#include "cm_log.h"

namespace OHOS {
namespace Security {
namespace CertManager {
CmRdbOpenCallback::CmRdbOpenCallback(const RdbConfig &rdbConfig) : rdbConfig_(rdbConfig) {}

int32_t CmRdbOpenCallback::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    CM_LOG_D("CmRdbOpenCallback OnCreate");
    return NativeRdb::E_OK;
}

int32_t CmRdbOpenCallback::OnUpgrade(NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    CM_LOG_D("CmRdbOpenCallback OnUpgrade : database upgrade. currentVersion = %{public}d, newVersion = %{public}d",
        currentVersion, targetVersion);
    /* Upgrade the database: Add the AUTH_STORAGE_LEVEL column with a default value of 1 (EL1).  */
    if (currentVersion == RDB_VERSION_FIRST && targetVersion == RDB_VERSION_CURRENT) {
        rdbStore.ExecuteSql("ALTER TABLE " + CERT_PROPERTY_TABLE_NAME + " ADD COLUMN " +
            COLUMN_AUTH_STORAGE_LEVEL + " INTEGER DEFAULT 1;");
    }
    return NativeRdb::E_OK;
}

int32_t CmRdbOpenCallback::OnDowngrade(NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    CM_LOG_D("CmRdbOpenCallback OnDowngrade");
    return NativeRdb::E_OK;
}

int32_t CmRdbOpenCallback::OnOpen(NativeRdb::RdbStore &rdbStore)
{
    CM_LOG_D("CmRdbOpenCallback OnOpen");
    return NativeRdb::E_OK;
}
} // namespace CertManager
} // namespace Security
} // namespace OHOS