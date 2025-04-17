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

#include "cm_rdb_data_manager.h"

#include "cm_log.h"
#include "cm_rdb_open_callback.h"
#include "cm_scope_guard.h"

namespace OHOS {
namespace Security {
namespace CertManager {
const int32_t CLOSE_RDB_TIME = 20; // delay 20s stop rdbStore
CmRdbDataManager::CmRdbDataManager(const RdbConfig &rdbConfig) : rdbConfig_(rdbConfig) {}

CmRdbDataManager::~CmRdbDataManager()
{
    std::lock_guard<std::mutex> lock(rdbMutex_);
    rdbStore_ = nullptr;
}

bool CmRdbDataManager::InsertData(const NativeRdb::ValuesBucket &valuesBucket)
{
    CM_LOG_D("enter CmRdbDataManager InsertData");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        CM_LOG_E("rdbStore is nullptr");
        return false;
    }

    int64_t rowId = -1;
    auto ret = rdbStore->InsertWithConflictResolution(rowId, rdbConfig_.tableName, valuesBucket,
        NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    return ret == NativeRdb::E_OK;
}

bool CmRdbDataManager::UpdateData(const std::string &primKey, const std::string &keyColumn,
    const NativeRdb::ValuesBucket &valuesBucket)
{
    CM_LOG_D("enter CmRdbDataManager UpdateData");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        CM_LOG_E("rdbStore is nullptr");
        return false;
    }

    NativeRdb::AbsRdbPredicates updatePredicates(rdbConfig_.tableName);
    updatePredicates.EqualTo(keyColumn, primKey);
    int32_t rowId = -1;
    auto ret = rdbStore->Update(rowId, valuesBucket, updatePredicates);
    return ret == NativeRdb::E_OK;
}

bool CmRdbDataManager::DeleteData(const std::string &primKey, const std::string &keyColumn)
{
    CM_LOG_D("enter CmRdbDataManager DeleteData");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        CM_LOG_E("rdbStore is nullptr");
        return false;
    }

    NativeRdb::AbsRdbPredicates deletePredicates(rdbConfig_.tableName);
    deletePredicates.EqualTo(keyColumn, primKey);
    int32_t rowId = -1;
    auto ret = rdbStore->Delete(rowId, deletePredicates);
    return ret == NativeRdb::E_OK;
}

std::shared_ptr<NativeRdb::AbsSharedResultSet> CmRdbDataManager::QueryData(const std::string &primKey,
    const std::string &keyColumn)
{
    CM_LOG_D("enter CmRdbDataManager QueryData");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        CM_LOG_E("rdbStore is nullptr");
        return nullptr;
    }

    NativeRdb::AbsRdbPredicates queryPredicates(rdbConfig_.tableName);
    queryPredicates.EqualTo(keyColumn, primKey);
    std::shared_ptr<NativeRdb::AbsSharedResultSet> absSharedResultSet =
        rdbStore->Query(queryPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        CM_LOG_E("absSharedResultSet is nullptr");
        return nullptr;
    }
    if (!absSharedResultSet->HasBlock()) {
        CM_LOG_E("absSharedResultSet query failed");
        absSharedResultSet->Close();
        return nullptr;
    }
    return absSharedResultSet;
}

bool CmRdbDataManager::CreateTable()
{
    CM_LOG_D("enter CmRdbDataManager CreateTable");
    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        CM_LOG_E("rdbStore is nullptr");
        return false;
    }

    if (rdbConfig_.createTableSql.empty()) {
        CM_LOG_E("createTableSql is nullptr");
        return false;
    }

    int ret = rdbStore->ExecuteSql(rdbConfig_.createTableSql);
    if (ret != NativeRdb::E_OK) {
        CM_LOG_E("Failed to create table, ret: %{public}d", ret);
        return false;
    }
    return true;
}

void CmRdbDataManager::DelayCloseRdbStore()
{
    CM_LOG_D("enter CmRdbDataManager DelayCloseRdbStore");
    std::weak_ptr<CmRdbDataManager> weakPtr = shared_from_this();
    auto closeTask = [weakPtr]() {
        CM_LOG_D("DelayCloseRdbStore thread begin");
        std::this_thread::sleep_for(std::chrono::seconds(CLOSE_RDB_TIME));
        auto sharedPtr = weakPtr.lock();
        if (sharedPtr == nullptr) {
            return;
        }
        std::lock_guard<std::mutex> lock(sharedPtr->rdbMutex_);
        sharedPtr->rdbStore_ = nullptr;
        CM_LOG_D("DelayCloseRdbStore thread end");
    };
    std::thread closeRdbStoreThread(closeTask);
    closeRdbStoreThread.detach();
}

void CmRdbDataManager::CmRdbDataManager::ClearCache()
{
    NativeRdb::RdbHelper::ClearCache();
}

std::shared_ptr<NativeRdb::RdbStore> CmRdbDataManager::GetRdbStore()
{
    CM_LOG_D("enter CmRdbDataManager GetRdbStore");
    std::lock_guard<std::mutex> lock(rdbMutex_);
    if (rdbStore_ != nullptr) {
        return rdbStore_;
    }

    int32_t errCode = NativeRdb::E_OK;
    NativeRdb::RdbStoreConfig rdbStoreConfig(rdbConfig_.dbPath + rdbConfig_.dbName);
    rdbStoreConfig.SetSecurityLevel(NativeRdb::SecurityLevel::S1);
    CmRdbOpenCallback cmRdbOpenCallback(rdbConfig_);
    rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(rdbStoreConfig, rdbConfig_.version, cmRdbOpenCallback, errCode);
    if (rdbStore_ == nullptr) {
        CM_LOG_E("Failed to init cert manager rdbStore");
    }
    DelayCloseRdbStore();
    return rdbStore_;
}
} // namespace CertManager
} // namespace Security
} // namespace OHOS