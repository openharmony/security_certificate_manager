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

#include "cm_cert_property_rdb.h"

#include "securec.h"

#include "cm_log.h"
#include "cm_rdb_config.h"
#include "cm_rdb_data_manager.h"
#include "cm_scope_guard.h"

using namespace OHOS;
using namespace OHOS::Security::CertManager;

const std::string CERT_MANAGER_RDB_NAME = "/cert_manager.db";
const std::string CERT_PROPERTY_TABLE_NAME = "cert_property";
const std::string COLUMN_URI = "URI";
const std::string COLUMN_ALIAS = "ALIAS";
const std::string COLUMN_SUBJECT_NAME = "SUBJECT_NAME";
const std::string COLUMN_CERT_TYPE = "CERT_TYPE";
const std::string COLUMN_CERT_STORE = "CERT_STORE";
const std::string COLUMN_USERID = "USERID";
const std::string COLUMN_UID = "UID";

static std::shared_ptr<CmRdbDataManager> cmRdbDataManager = nullptr;

int32_t CreateCertPropertyRdb(void)
{
    CM_LOG_D("enter CreateCertPropertyRdb");
    RdbConfig rdbConfig;
    rdbConfig.dbName = CERT_MANAGER_RDB_NAME;
    rdbConfig.tableName = CERT_PROPERTY_TABLE_NAME;
    rdbConfig.createTableSql = std::string("CREATE TABLE IF NOT EXISTS " + CERT_PROPERTY_TABLE_NAME +
        "(URI TEXT PRIMARY KEY, ALIAS TEXT NOT NULL, SUBJECT_NAME TEXT NOT NULL, CERT_TYPE TEXT NOT NULL, " +
        "CERT_STORE INTEGER NOT NULL, USERID INTEGER NOT NULL, UID INTEGER NOT NULL)");
    cmRdbDataManager = std::make_shared<CmRdbDataManager>(rdbConfig);
    bool ret = cmRdbDataManager->CreateTable();
    if (!ret) {
        CM_LOG_E("Failed to create cert_property table");
        return CMR_ERROR_CREATE_RDB_TABLE_FAIL;
    }
    return CM_SUCCESS;
}

int32_t InsertCertProperty(const struct CertProperty *certProperty)
{
    CM_LOG_D("enter InsertCertProperty");
    if (certProperty == nullptr) {
        CM_LOG_E("certProperty is nullptr");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (cmRdbDataManager == nullptr) {
        CM_LOG_E("cmRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }

    NativeRdb::ValuesBucket insertBucket;
    insertBucket.PutString(COLUMN_URI, std::string(certProperty->uri));
    insertBucket.PutString(COLUMN_ALIAS, std::string(certProperty->alias));
    insertBucket.PutString(COLUMN_SUBJECT_NAME, std::string(certProperty->subjectName));
    insertBucket.PutString(COLUMN_CERT_TYPE, std::string(certProperty->certType));
    insertBucket.PutInt(COLUMN_CERT_STORE, certProperty->certStore);
    insertBucket.PutInt(COLUMN_USERID, certProperty->userId);
    insertBucket.PutInt(COLUMN_UID, certProperty->uid);
    bool ret = cmRdbDataManager->InsertData(insertBucket);
    if (!ret) {
        CM_LOG_E("Failed to insert cert:%s property data", certProperty->uri);
        return CMR_ERROR_INSERT_RDB_DATA_FAIL;
    }
    return CM_SUCCESS;
}

int32_t DeleteCertProperty(const char *uri)
{
    CM_LOG_D("enter DeleteCertProperty");
    if (uri == nullptr) {
        CM_LOG_E("uri is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (cmRdbDataManager == nullptr) {
        CM_LOG_E("cmRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }

    bool ret = cmRdbDataManager->DeleteData(std::string(uri), COLUMN_URI);
    if (!ret) {
        CM_LOG_E("Failed to delete cert:%s property data", uri);
        return CMR_ERROR_DELETE_RDB_DATA_FAIL;
    }
    return CM_SUCCESS;
}

int32_t UpdateCertProperty(const struct CertProperty *certProperty)
{
    CM_LOG_D("enter UpdateCertProperty");
    if (certProperty == nullptr) {
        CM_LOG_E("certProperty is nullptr");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (cmRdbDataManager == nullptr) {
        CM_LOG_E("cmRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }

    NativeRdb::ValuesBucket updateBucket;
    updateBucket.PutString(COLUMN_URI, std::string(certProperty->uri));
    updateBucket.PutString(COLUMN_ALIAS, std::string(certProperty->alias));
    updateBucket.PutString(COLUMN_SUBJECT_NAME, std::string(certProperty->subjectName));
    updateBucket.PutString(COLUMN_CERT_TYPE, std::string(certProperty->certType));
    updateBucket.PutInt(COLUMN_CERT_STORE, certProperty->certStore);
    updateBucket.PutInt(COLUMN_USERID, certProperty->userId);
    updateBucket.PutInt(COLUMN_UID, certProperty->uid);
    bool ret = cmRdbDataManager->UpdateData(std::string(certProperty->uri), COLUMN_URI, updateBucket);
    if (!ret) {
            CM_LOG_E("Failed to update cert:%s property data", certProperty->uri);
        return CMR_ERROR_DELETE_RDB_DATA_FAIL;
    }
    return CM_SUCCESS;
}

static int32_t GetStringValue(const std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet,
    const std::string &columnName, char *outBuf, uint32_t outBufLen)
{
    int columnIndex = 0;
    auto ret = resultSet->GetColumnIndex(columnName, columnIndex);
    if (ret != NativeRdb::E_OK) {
        CM_LOG_E("Failed to get column index, column: %{public}s", columnName.c_str());
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    std::string value;
    ret = resultSet->GetString(columnIndex, value);
    if (ret != NativeRdb::E_OK) {
        CM_LOG_E("Failed to get column value, column: %{public}s", columnName.c_str());
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    if (memcpy_s(outBuf, outBufLen, value.c_str(), value.size() + 1) != EOK) {
        CM_LOG_E("memcpy_s fail");
        return CMR_ERROR_INVALID_OPERATION;
    }
    return CM_SUCCESS;
}

static int32_t GetIntValue(const std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet,
    const std::string &columnName, int32_t &value)
{
    int columnIndex = 0;
    auto ret = resultSet->GetColumnIndex(columnName, columnIndex);
    if (ret != NativeRdb::E_OK) {
        CM_LOG_E("Failed to get column index, column: %{public}s", columnName.c_str());
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    ret = resultSet->GetInt(columnIndex, value);
    if (ret != NativeRdb::E_OK) {
        CM_LOG_E("Failed to get column value, column: %{public}s", columnName.c_str());
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    return CM_SUCCESS;
}

static int32_t GetCertProperty(const std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet,
    struct CertProperty *certProperty)
{
    int32_t ret = GetStringValue(resultSet, COLUMN_URI, certProperty->uri, MAX_LEN_URI);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get uri");
        return ret;
    }

    ret = GetStringValue(resultSet, COLUMN_ALIAS, certProperty->alias, MAX_LEN_CERT_ALIAS);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get alias");
        return ret;
    }

    ret = GetStringValue(resultSet, COLUMN_SUBJECT_NAME, certProperty->subjectName, MAX_LEN_SUBJECT_NAME);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get subjectName");
        return ret;
    }

    ret = GetStringValue(resultSet, COLUMN_CERT_TYPE, certProperty->certType, MAX_LEN_CERT_TYPE);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get certType");
        return ret;
    }

    ret = GetIntValue(resultSet, COLUMN_CERT_STORE, certProperty->certStore);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get certStore");
        return ret;
    }

    ret = GetIntValue(resultSet, COLUMN_USERID, certProperty->userId);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get userId");
        return ret;
    }

    ret = GetIntValue(resultSet, COLUMN_UID, certProperty->uid);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get uid");
        return ret;
    }
    return ret;
}

int32_t QueryCertProperty(const char *uri, struct CertProperty *certProperty)
{
    CM_LOG_D("enter QueryCertProperty");
    if (uri == nullptr || certProperty == nullptr) {
        CM_LOG_E("input param is invalid");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (cmRdbDataManager == nullptr) {
        CM_LOG_E("cmRdbDataManager is nullptr");
        return CMR_ERROR_NULL_POINTER;
    }

    auto absSharedResultSet = cmRdbDataManager->QueryData(std::string(uri), COLUMN_URI);
    if (absSharedResultSet == nullptr) {
        CM_LOG_E("Failed to query cert: %s property data", uri);
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    CmScoprGuard stateGuard([&] { absSharedResultSet->Close(); });
    int rowCount = 0;
    int ret = absSharedResultSet->GetRowCount(rowCount);
    if (ret != NativeRdb::E_OK) {
        CM_LOG_E("Failed to get row count, ret: %d", ret);
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    if (rowCount <= 0) {
        CM_LOG_D("Finish to query, cert: %s does not exist in the database", uri);
        return CM_SUCCESS;
    }

    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        CM_LOG_E("Failed to go to firstRow, ret: %d", ret);
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }

    int32_t result = GetCertProperty(absSharedResultSet, certProperty);
    if (result != CM_SUCCESS) {
        CM_LOG_E("Failed to get cert property data");
        return CMR_ERROR_QUERY_RDB_DATA_FAIL;
    }
    return CM_SUCCESS;
}