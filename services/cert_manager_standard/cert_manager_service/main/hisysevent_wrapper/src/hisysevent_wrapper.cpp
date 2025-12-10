/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "hisysevent_wrapper.h"

#include "cm_log.h"

#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "hisysevent.h"
#include "ipc_skeleton.h"

using namespace OHOS;
using namespace OHOS::HiviewDFX;
using namespace OHOS::Security::AccessToken;

static constexpr char CM_DOMAIN[] = "CERT_MANAGER";
static constexpr char CM_EVENT_NAME[] = "CERT_FAULT";
static constexpr char CM_TAG_FUNCTION[] = "FUNCTION";
static constexpr char CM_TAG_USER_ID[] = "USER_ID";
static constexpr char CM_TAG_UID[] = "UID";
static constexpr char CM_TAG_CERT_NAME[] = "CERT_NAME";
static constexpr char CM_TAG_ERROR_CODE[] = "ERROR_CODE";
static constexpr char CM_TAG_ERROR_MESSAGE[] = "ERROR_MESSAGE";
static constexpr char CM_TAG_CALLER[] = "CALLER";

static const std::string CALLER_UID_NAME = "ipc_calling_uid: ";

static const std::string CM_UNKNOWN_MSG = "there is an unknown error.";
static const std::string CMR_ERROR_NOT_PERMITTED_MSG = "the operation is not permitted.";
static const std::string CMR_ERROR_NOT_SUPPORTED_MSG = "the operation is not supported.";
static const std::string CMR_ERROR_STORAGE_MSG = "the storage data is invalid";
static const std::string CMR_ERROR_NOT_FOUND_MSG = "the item is not found";
static const std::string CMR_ERROR_NULL_POINTER_MSG = "the argument has null pointer";
static const std::string CMR_ERROR_INVALID_ARGUMENT_MSG = "the argument is invalid";
static const std::string CMR_ERROR_MAKE_DIR_FAIL_MSG = "failed to make dir";
static const std::string CMR_ERROR_INVALID_OPERATION_MSG = "the operation is invalid";
static const std::string CMR_ERROR_OPEN_FILE_FAIL_MSG = "failed to open file";
static const std::string CMR_ERROR_READ_FILE_ERROR_MSG = "failed to read file";
static const std::string CMR_ERROR_WRITE_FILE_FAIL_MSG = "failed to write file";
static const std::string CMR_ERROR_REMOVE_FILE_FAIL_MSG = "failed to remove file";
static const std::string CMR_ERROR_CLOSE_FILE_FAIL_MSG = "failed to close file";
static const std::string CMR_ERROR_MALLOC_FAIL_MSG = "failed to malloc memory";
static const std::string CMR_ERROR_NOT_EXIST_MSG = "the item is not exist";
static const std::string CMR_ERROR_ALREADY_EXISTS_MSG = "the item is already exist";
static const std::string CMR_ERROR_INSUFFICIENT_DATA_MSG = "the data is invalid";
static const std::string CMR_ERROR_BUFFER_TOO_SMALL_MSG = "the out buffer is too small";
static const std::string CMR_ERROR_INVALID_CERT_FORMAT_MSG = "the cert format is invalid";
static const std::string CMR_ERROR_PARAM_NOT_EXIST_MSG = "the param is not exist";
static const std::string CMR_ERROR_SESSION_REACHED_LIMIT_MSG = "reach the max session count";
static const std::string CMR_ERROR_PERMISSION_DENIED_MSG = "the caller has no permission";
static const std::string CMR_ERROR_AUTH_CHECK_FAILED_MSG = "auth check failed";
static const std::string CMR_ERROR_KEY_OPERATION_FAILED_MSG = "the key operation failed";
static const std::string CMR_ERROR_NOT_SYSTEMP_APP_MSG = "the caller is not system app";
static const std::string CMR_ERROR_MAX_CERT_COUNT_REACHED_MSG = "reach the max cert count";
static const std::string CMR_ERROR_ALIAS_LENGTH_REACHED_LIMIT_MSG = "reach the max alias length";
static const std::string CMR_ERROR_GET_ADVSECMODE_PARAM_FAIL_MSG = "failed to get advsecmode param";
static const std::string CMR_ERROR_DEVICE_ENTER_ADVSECMODE_MSG = "the device is in advsecmode";
static const std::string CMR_ERROR_CREATE_RDB_TABLE_FAIL_MSG = "failed to create rdb table";
static const std::string CMR_ERROR_INSERT_RDB_DATA_FAIL_MSG = "failed to insert data into rdb table";
static const std::string CMR_ERROR_UPDATE_RDB_DATA_FAIL_MSG = "failed to update data into rdb table";
static const std::string CMR_ERROR_DELETE_RDB_DATA_FAIL_MSG = "failed to delete data from rdb table";
static const std::string CMR_ERROR_QUERY_RDB_DATA_FAIL_MSG = "failed to query data from rdb table";
static const std::string CMR_ERROR_PASSWORD_IS_ERR_MSG = "the password is incorrect";

static const std::string CMR_ERROR_OPENSSL_FAIL_MSG = "failed to call openssl API";
static const std::string CMR_ERROR_MAX_GRANT_COUNT_REACHED_MSG = "reach the max grant uid count";
static const std::string CMR_ERROR_SA_START_STATUS_INIT_FAILED_MSG = "failed to init status when sa start";
static const std::string CMR_ERROR_SA_START_HUKS_INIT_FAILED_MSG = "failed to init huks when sa start";
static const std::string CMR_ERROR_SA_START_PUBLISH_FAILED_MSG = "failed to publish sa when sa start";
static const std::string CMR_ERROR_IPC_PARAM_SIZE_INVALID_MSG = "the ipc param size is invalid";
static const std::string CMR_ERROR_GET_LOCAL_TIME_FAILED_MSG = "failed to get local time";
static const std::string CMR_ERROR_MEM_OPERATION_COPY_MSG = "failed to copy data, maybe invalid buffer length";
static const std::string CMR_ERROR_MEM_OPERATION_PRINT_MSG = "failed to sprintf data, maybe invalid buffer length";
static const std::string CMR_ERROR_FILE_OPEN_DIR_MSG = "failed to open dir";
static const std::string CMR_ERROR_FILE_STAT_MSG = "failed to stat file";
static const std::string CMR_ERROR_CERT_COUNT_MISMATCH_MSG = "the file count is not same";
static const std::string CMR_ERROR_GET_CERT_STATUS_MSG = "failed to get cert status";
static const std::string CMR_ERROR_GET_CERT_SUBJECT_ITEM_MSG = "failed to get cert subject item";

/* invalid argument msg */
static const std::string CMR_ERROR_INVALID_PARAMSET_ARG_MSG = "the paramset argument is invalid";
static const std::string CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE_MSG = "the store type argument is invalid";
static const std::string CMR_ERROR_INVALID_ARGUMENT_SCOPE_MSG = "the scope argument is invalid";
static const std::string CMR_ERROR_INVALID_ARGUMENT_USER_ID_MSG = "the user id argument is invalid";
static const std::string CMR_ERROR_INVALID_ARGUMENT_UID_MSG = "the uid argument is invalid";
static const std::string CMR_ERROR_INVALID_ARGUMENT_URI_MSG = "the uri argument is invalid";
static const std::string CMR_ERROR_INVALID_ARGUMENT_STATUS_MSG = "the status argument is invalid";
static const std::string CMR_ERROR_INVALID_ARGUMENT_APP_CERT_MSG = "the app cert data is invalid";
static const std::string CMR_ERROR_INVALID_ARGUMENT_APP_PWD_MSG = "the app pwd data is invalid";
static const std::string CMR_ERROR_INVALID_ARGUMENT_ALIAS_MSG = "the alias argument is invalid";
static const std::string CMR_ERROR_INVALID_ARGUMENT_SIGN_SPEC_MSG = "the sign verify spec argument is invalid";
static const std::string CMR_ERROR_INVALID_ARGUMENT_HANDLE_MSG = "the handle argument is invalid";
static const std::string CMR_ERROR_INVALID_ARGUMENT_CRED_PREVKEY_MSG = "the cred private key is invalid";

/* key operation failed msg */
static const std::string CMR_ERROR_KEY_IMPORT_PARAM_FAILED_MSG = "failed to construct import key param";
static const std::string CMR_ERROR_KEY_IMPORT_FAILED_MSG = "failed to import key to huks";
static const std::string CMR_ERROR_KEY_DELETE_PARAM_FAILED_MSG = "failed to construct delete key param";
static const std::string CMR_ERROR_KEY_DELETE_FAILED_MSG = "failed to delete key from huks";
static const std::string CMR_ERROR_KEY_MAC_PARAM_FAILED_MSG = "failed to construct mac param";
static const std::string CMR_ERROR_KEY_MAC_INIT_FAILED_MSG = "failed to calc mac when call huks init";
static const std::string CMR_ERROR_KEY_MAC_FINISH_FAILED_MSG = "failed to calc mac when call huks finish";
static const std::string CMR_ERROR_KEY_GENERATE_PARAM_FAILED_MSG = "failed to construct generate key param";
static const std::string CMR_ERROR_KEY_GENERATE_FAILED_MSG = "failed to generate key from huks";
static const std::string CMR_ERROR_KEY_INIT_PARAM_FAILED_MSG = "failed to construct init key param";
static const std::string CMR_ERROR_KEY_INIT_FAILED_MSG = "failed to init from huks";
static const std::string CMR_ERROR_KEY_PROCESS_PARAM_FAILED_MSG = "failed to construct update or finish or abort param";
static const std::string CMR_ERROR_KEY_UPDATE_FAILED_MSG = "failed to do update operation from huks";
static const std::string CMR_ERROR_KEY_FINISH_FAILED_MSG = "failed to do finish operation from huks";
static const std::string CMR_ERROR_KEY_ABORT_FAILED_MSG = "failed to do abort operation from huks";
static const std::string CMR_ERROR_KEY_CHECK_EXIST_PARAM_FAILED_MSG = "failed to construct check key exist param";
static const std::string CMR_ERROR_KEY_CHECK_EXIST_FAILED_MSG = "failed to check key exist from huks";

/* auth check failed msg */
static const std::string CMR_ERROR_AUTH_FAILED_MAC_FAILED_MSG = "failed to calc the mac value";
static const std::string CMR_ERROR_AUTH_FAILED_MAC_MISMATCH_MSG = "the auth result is not same with mac value";

/* ukey failed msg */
static const std::string ACCESS_UKEY_SERVICE_FAILED_MSG = "the access USB key service failed";
static const std::string CAPABILITY_NOT_SUPPORTED_MSG = "capability not support";
static const std::string HUKS_ABNORMAL_MSG = "huks encountered an exception";

static const std::unordered_map<int32_t, std::string> ERROR_CODE_TO_MSG_MAP = {
    { CM_FAILURE, CM_UNKNOWN_MSG },
    { CMR_ERROR_NOT_PERMITTED, CMR_ERROR_NOT_PERMITTED_MSG },
    { CMR_ERROR_NOT_SUPPORTED, CMR_ERROR_NOT_SUPPORTED_MSG },
    { CMR_ERROR_STORAGE, CMR_ERROR_STORAGE_MSG },
    { CMR_ERROR_NOT_FOUND, CMR_ERROR_NOT_FOUND_MSG },
    { CMR_ERROR_NULL_POINTER, CMR_ERROR_NULL_POINTER_MSG },
    { CMR_ERROR_INVALID_ARGUMENT, CMR_ERROR_INVALID_ARGUMENT_MSG },
    { CMR_ERROR_MAKE_DIR_FAIL, CMR_ERROR_MAKE_DIR_FAIL_MSG },
    { CMR_ERROR_INVALID_OPERATION, CMR_ERROR_INVALID_OPERATION_MSG },
    { CMR_ERROR_OPEN_FILE_FAIL, CMR_ERROR_OPEN_FILE_FAIL_MSG },
    { CMR_ERROR_READ_FILE_ERROR, CMR_ERROR_READ_FILE_ERROR_MSG },
    { CMR_ERROR_WRITE_FILE_FAIL, CMR_ERROR_WRITE_FILE_FAIL_MSG },
    { CMR_ERROR_REMOVE_FILE_FAIL, CMR_ERROR_REMOVE_FILE_FAIL_MSG },
    { CMR_ERROR_CLOSE_FILE_FAIL, CMR_ERROR_CLOSE_FILE_FAIL_MSG },
    { CMR_ERROR_MALLOC_FAIL, CMR_ERROR_MALLOC_FAIL_MSG },
    { CMR_ERROR_NOT_EXIST, CMR_ERROR_NOT_EXIST_MSG },
    { CMR_ERROR_ALREADY_EXISTS, CMR_ERROR_ALREADY_EXISTS_MSG },
    { CMR_ERROR_INSUFFICIENT_DATA, CMR_ERROR_INSUFFICIENT_DATA_MSG },
    { CMR_ERROR_BUFFER_TOO_SMALL, CMR_ERROR_BUFFER_TOO_SMALL_MSG },
    { CMR_ERROR_INVALID_CERT_FORMAT, CMR_ERROR_INVALID_CERT_FORMAT_MSG },
    { CMR_ERROR_PARAM_NOT_EXIST, CMR_ERROR_PARAM_NOT_EXIST_MSG },
    { CMR_ERROR_SESSION_REACHED_LIMIT, CMR_ERROR_SESSION_REACHED_LIMIT_MSG },
    { CMR_ERROR_PERMISSION_DENIED, CMR_ERROR_PERMISSION_DENIED_MSG },
    { CMR_ERROR_AUTH_CHECK_FAILED, CMR_ERROR_AUTH_CHECK_FAILED_MSG },
    { CMR_ERROR_KEY_OPERATION_FAILED, CMR_ERROR_KEY_OPERATION_FAILED_MSG },
    { CMR_ERROR_NOT_SYSTEMP_APP, CMR_ERROR_NOT_SYSTEMP_APP_MSG },
    { CMR_ERROR_MAX_CERT_COUNT_REACHED, CMR_ERROR_MAX_CERT_COUNT_REACHED_MSG },
    { CMR_ERROR_ALIAS_LENGTH_REACHED_LIMIT, CMR_ERROR_ALIAS_LENGTH_REACHED_LIMIT_MSG },
    { CMR_ERROR_GET_ADVSECMODE_PARAM_FAIL, CMR_ERROR_GET_ADVSECMODE_PARAM_FAIL_MSG },
    { CMR_ERROR_DEVICE_ENTER_ADVSECMODE, CMR_ERROR_DEVICE_ENTER_ADVSECMODE_MSG },
    { CMR_ERROR_CREATE_RDB_TABLE_FAIL, CMR_ERROR_CREATE_RDB_TABLE_FAIL_MSG },
    { CMR_ERROR_INSERT_RDB_DATA_FAIL, CMR_ERROR_INSERT_RDB_DATA_FAIL_MSG },
    { CMR_ERROR_UPDATE_RDB_DATA_FAIL, CMR_ERROR_UPDATE_RDB_DATA_FAIL_MSG },
    { CMR_ERROR_DELETE_RDB_DATA_FAIL, CMR_ERROR_DELETE_RDB_DATA_FAIL_MSG },
    { CMR_ERROR_QUERY_RDB_DATA_FAIL, CMR_ERROR_QUERY_RDB_DATA_FAIL_MSG },
    { CMR_ERROR_PASSWORD_IS_ERR, CMR_ERROR_PASSWORD_IS_ERR_MSG },

    { CMR_ERROR_OPENSSL_FAIL, CMR_ERROR_OPENSSL_FAIL_MSG },
    { CMR_ERROR_MAX_GRANT_COUNT_REACHED, CMR_ERROR_MAX_GRANT_COUNT_REACHED_MSG },
    { CMR_ERROR_SA_START_STATUS_INIT_FAILED, CMR_ERROR_SA_START_STATUS_INIT_FAILED_MSG },
    { CMR_ERROR_SA_START_HUKS_INIT_FAILED, CMR_ERROR_SA_START_HUKS_INIT_FAILED_MSG },
    { CMR_ERROR_SA_START_PUBLISH_FAILED, CMR_ERROR_SA_START_PUBLISH_FAILED_MSG },
    { CMR_ERROR_IPC_PARAM_SIZE_INVALID, CMR_ERROR_IPC_PARAM_SIZE_INVALID_MSG },
    { CMR_ERROR_GET_LOCAL_TIME_FAILED, CMR_ERROR_GET_LOCAL_TIME_FAILED_MSG },
    { CMR_ERROR_MEM_OPERATION_COPY, CMR_ERROR_MEM_OPERATION_COPY_MSG },
    { CMR_ERROR_MEM_OPERATION_PRINT, CMR_ERROR_MEM_OPERATION_PRINT_MSG },
    { CMR_ERROR_FILE_OPEN_DIR, CMR_ERROR_FILE_OPEN_DIR_MSG },
    { CMR_ERROR_FILE_STAT, CMR_ERROR_FILE_STAT_MSG },
    { CMR_ERROR_CERT_COUNT_MISMATCH, CMR_ERROR_CERT_COUNT_MISMATCH_MSG },
    { CMR_ERROR_GET_CERT_STATUS, CMR_ERROR_GET_CERT_STATUS_MSG },
    { CMR_ERROR_GET_CERT_SUBJECT_ITEM, CMR_ERROR_GET_CERT_SUBJECT_ITEM_MSG },

    /* invalid argument */
    { CMR_ERROR_INVALID_PARAMSET_ARG, CMR_ERROR_INVALID_PARAMSET_ARG_MSG },
    { CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE, CMR_ERROR_INVALID_ARGUMENT_STORE_TYPE_MSG },
    { CMR_ERROR_INVALID_ARGUMENT_SCOPE, CMR_ERROR_INVALID_ARGUMENT_SCOPE_MSG },
    { CMR_ERROR_INVALID_ARGUMENT_USER_ID, CMR_ERROR_INVALID_ARGUMENT_USER_ID_MSG },
    { CMR_ERROR_INVALID_ARGUMENT_UID, CMR_ERROR_INVALID_ARGUMENT_UID_MSG },
    { CMR_ERROR_INVALID_ARGUMENT_URI, CMR_ERROR_INVALID_ARGUMENT_URI_MSG },
    { CMR_ERROR_INVALID_ARGUMENT_STATUS, CMR_ERROR_INVALID_ARGUMENT_STATUS_MSG },
    { CMR_ERROR_INVALID_ARGUMENT_APP_CERT, CMR_ERROR_INVALID_ARGUMENT_APP_CERT_MSG },
    { CMR_ERROR_INVALID_ARGUMENT_APP_PWD, CMR_ERROR_INVALID_ARGUMENT_APP_PWD_MSG },
    { CMR_ERROR_INVALID_ARGUMENT_ALIAS, CMR_ERROR_INVALID_ARGUMENT_ALIAS_MSG },
    { CMR_ERROR_INVALID_ARGUMENT_SIGN_SPEC, CMR_ERROR_INVALID_ARGUMENT_SIGN_SPEC_MSG },
    { CMR_ERROR_INVALID_ARGUMENT_HANDLE, CMR_ERROR_INVALID_ARGUMENT_HANDLE_MSG },
    { CMR_ERROR_INVALID_ARGUMENT_CRED_PREVKEY, CMR_ERROR_INVALID_ARGUMENT_CRED_PREVKEY_MSG },

    /* key operation failed */
    { CMR_ERROR_KEY_IMPORT_PARAM_FAILED, CMR_ERROR_KEY_IMPORT_PARAM_FAILED_MSG },
    { CMR_ERROR_KEY_IMPORT_FAILED, CMR_ERROR_KEY_IMPORT_FAILED_MSG },
    { CMR_ERROR_KEY_DELETE_PARAM_FAILED, CMR_ERROR_KEY_DELETE_PARAM_FAILED_MSG },
    { CMR_ERROR_KEY_DELETE_FAILED, CMR_ERROR_KEY_DELETE_FAILED_MSG },
    { CMR_ERROR_KEY_MAC_PARAM_FAILED, CMR_ERROR_KEY_MAC_PARAM_FAILED_MSG },
    { CMR_ERROR_KEY_MAC_INIT_FAILED, CMR_ERROR_KEY_MAC_INIT_FAILED_MSG },
    { CMR_ERROR_KEY_MAC_FINISH_FAILED, CMR_ERROR_KEY_MAC_FINISH_FAILED_MSG },
    { CMR_ERROR_KEY_GENERATE_PARAM_FAILED, CMR_ERROR_KEY_GENERATE_PARAM_FAILED_MSG },
    { CMR_ERROR_KEY_GENERATE_FAILED, CMR_ERROR_KEY_GENERATE_FAILED_MSG },
    { CMR_ERROR_KEY_INIT_PARAM_FAILED, CMR_ERROR_KEY_INIT_PARAM_FAILED_MSG },
    { CMR_ERROR_KEY_INIT_FAILED, CMR_ERROR_KEY_INIT_FAILED_MSG },
    { CMR_ERROR_KEY_PROCESS_PARAM_FAILED, CMR_ERROR_KEY_PROCESS_PARAM_FAILED_MSG },
    { CMR_ERROR_KEY_UPDATE_FAILED, CMR_ERROR_KEY_UPDATE_FAILED_MSG },
    { CMR_ERROR_KEY_FINISH_FAILED, CMR_ERROR_KEY_FINISH_FAILED_MSG },
    { CMR_ERROR_KEY_ABORT_FAILED, CMR_ERROR_KEY_ABORT_FAILED_MSG },
    { CMR_ERROR_KEY_CHECK_EXIST_PARAM_FAILED, CMR_ERROR_KEY_CHECK_EXIST_PARAM_FAILED_MSG },
    { CMR_ERROR_KEY_CHECK_EXIST_FAILED, CMR_ERROR_KEY_CHECK_EXIST_FAILED_MSG },

    /* auth check failed */
    { CMR_ERROR_AUTH_FAILED_MAC_FAILED, CMR_ERROR_AUTH_FAILED_MAC_FAILED_MSG },
    { CMR_ERROR_AUTH_FAILED_MAC_MISMATCH, CMR_ERROR_AUTH_FAILED_MAC_MISMATCH_MSG },

    /* ukey failed */
    { CMR_ERROR_UKEY_GENERAL_ERROR, ACCESS_UKEY_SERVICE_FAILED_MSG },
    { CMR_ERROR_UKEY_DEVICE_SUPPORT, CAPABILITY_NOT_SUPPORTED_MSG },
    { CMR_ERROR_HUKS_GENERAL_ERROR, HUKS_ABNORMAL_MSG },
};

static const char *GetErrorMsg(int32_t errCode)
{
    auto iter = ERROR_CODE_TO_MSG_MAP.find(errCode);
    if (iter != ERROR_CODE_TO_MSG_MAP.end()) {
        return (iter->second).c_str();
    }
    return CM_UNKNOWN_MSG.c_str();
}

static void GetCallerName(std::string &callerName)
{
    auto callingTokenId = IPCSkeleton::GetCallingTokenID();
    if (AccessTokenKit::GetTokenType(callingTokenId) != ATokenTypeEnum::TOKEN_HAP) {
        int32_t uid = IPCSkeleton::GetCallingUid();
        callerName += CALLER_UID_NAME;
        callerName += std::to_string(uid);
        return;
    }

    HapTokenInfo hapTokenInfo;
    int32_t ret = AccessTokenKit::GetHapTokenInfo(callingTokenId, hapTokenInfo);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("Failed to get hap info from access token kit.");
        callerName += "NULL"; /* when faile to get hap info, callName is empty string */
        return;
    }
    callerName += hapTokenInfo.bundleName;
    return;
}

int WriteEvent(const char *functionName, const struct EventValues *eventValues)
{
    std::string callerName = "";
    GetCallerName(callerName);
    int32_t ret = HiSysEventWrite(CM_DOMAIN, CM_EVENT_NAME, HiSysEvent::EventType::FAULT,
        CM_TAG_CERT_NAME, eventValues->certName,
        CM_TAG_UID, eventValues->uid,
        CM_TAG_FUNCTION, functionName,
        CM_TAG_ERROR_CODE, eventValues->errorCode,
        CM_TAG_USER_ID, eventValues->userId,
        CM_TAG_ERROR_MESSAGE, GetErrorMsg(eventValues->errorCode),
        CM_TAG_CALLER, callerName.c_str());
    if (ret != CM_SUCCESS) {
        CM_LOG_E("WriteEvent failed, ret = %d", ret);
        return ret;
    }
    return ret;
}