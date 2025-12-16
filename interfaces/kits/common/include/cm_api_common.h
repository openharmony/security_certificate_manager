/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef CM_API_COMMON_H
#define CM_API_COMMON_H

#include <string>
#include "cm_type.h"

namespace OHOS::Security::CertManager {
enum ErrorCode {
    SUCCESS = 0,
    HAS_NO_PERMISSION = 201,
    NOT_SYSTEM_APP = 202,
    PARAM_ERROR = 401,
    CAPABILITY_NOT_SUPPORTED = 801,
    INNER_FAILURE = 17500001,
    NOT_FOUND = 17500002,
    INVALID_CERT_FORMAT = 17500003,
    MAX_CERT_COUNT_REACHED = 17500004,
    NO_AUTHORIZATION = 17500005,
    ALIAS_LENGTH_REACHED_LIMIT = 17500006,
    DEVICE_ENTER_ADVSECMODE = 17500007,
    PASSWORD_IS_ERROR = 17500008,
    STORE_PATH_NOT_SUPPORTED = 17500009,
    ACCESS_UKEY_SERVICE_FAILED = 17500010,
    PARAMETER_VALIDATION_FAILED = 17500011,
};

constexpr int CM_MAX_DATA_LEN = 0x6400000; // The maximum length is 100M

static const std::string NO_PERMISSION_MSG = "the caller has no permission";
static const std::string NOT_SYSTEM_APP_MSG = "the caller is not a system application";
static const std::string INVALID_PARAMS_MSG = "the input parameters is invalid";
static const std::string GENERIC_MSG = "there is an internal error";
static const std::string NO_FOUND_MSG = "the certificate do not exist";
static const std::string INCORRECT_FORMAT_MSG = "the input cert data is invalid";
static const std::string MAX_CERT_COUNT_REACHED_MSG = "the count of certificates or credentials reach the max";
static const std::string NO_AUTHORIZATION_MSG = "the application is not authorized by user";
static const std::string ALIAS_LENGTH_REACHED_LIMIT_MSG = "the input alias length reaches the max";
static const std::string DEVICE_ENTER_ADVSECMODE_MSG = "the device enters advanced security mode";
static const std::string PASSWORD_IS_ERROR_MSG = "the input password is error";
static const std::string STORE_PATH_NOT_SUPPORTED_MSG = "the device does not support specified certificate store path";
static const std::string ACCESS_UKEY_SERVICE_FAILED_MSG = "the access USB key service failed";
static const std::string CAPABILITY_NOT_SUPPORTED_MSG = "capability not support";
static const std::string HUKS_ABNORMAL_MSG = "huks encountered an exception";

static const std::unordered_map<int32_t, int32_t> NATIVE_CODE_TO_JS_CODE_MAP = {
    // invalid params
    { CMR_ERROR_INVALID_ARGUMENT, PARAM_ERROR },

    // no permission
    { CMR_ERROR_PERMISSION_DENIED, HAS_NO_PERMISSION },
    { CMR_ERROR_NOT_SYSTEMP_APP, NOT_SYSTEM_APP },

    { CMR_ERROR_INVALID_CERT_FORMAT, INVALID_CERT_FORMAT },
    { CMR_ERROR_INSUFFICIENT_DATA, INVALID_CERT_FORMAT },
    { CMR_ERROR_NOT_FOUND, NOT_FOUND },
    { CMR_ERROR_NOT_EXIST, NOT_FOUND },
    { CMR_ERROR_MAX_CERT_COUNT_REACHED, MAX_CERT_COUNT_REACHED },
    { CMR_ERROR_AUTH_CHECK_FAILED, NO_AUTHORIZATION },
    { CMR_ERROR_ALIAS_LENGTH_REACHED_LIMIT, ALIAS_LENGTH_REACHED_LIMIT },
    { CMR_ERROR_DEVICE_ENTER_ADVSECMODE, DEVICE_ENTER_ADVSECMODE },
    { CMR_ERROR_PASSWORD_IS_ERR, PASSWORD_IS_ERROR },
    { CMR_ERROR_STORE_PATH_NOT_SUPPORTED, STORE_PATH_NOT_SUPPORTED },
    
    // ukey
    { CMR_ERROR_UKEY_GENERAL_ERROR, ACCESS_UKEY_SERVICE_FAILED },
    { CMR_ERROR_UKEY_DEVICE_SUPPORT, CAPABILITY_NOT_SUPPORTED },
    { CMR_ERROR_HUKS_GENERAL_ERROR, INNER_FAILURE },
};

static const std::unordered_map<int32_t, std::string> NATIVE_CODE_TO_MSG_MAP = {
    { CMR_ERROR_PERMISSION_DENIED, NO_PERMISSION_MSG },
    { CMR_ERROR_NOT_SYSTEMP_APP, NOT_SYSTEM_APP_MSG },
    { CMR_ERROR_INVALID_ARGUMENT, INVALID_PARAMS_MSG },
    { CMR_ERROR_NOT_FOUND, NO_FOUND_MSG },
    { CMR_ERROR_NOT_EXIST, NO_FOUND_MSG },
    { CMR_ERROR_INVALID_CERT_FORMAT, INCORRECT_FORMAT_MSG },
    { CMR_ERROR_INSUFFICIENT_DATA, INCORRECT_FORMAT_MSG },
    { CMR_ERROR_MAX_CERT_COUNT_REACHED, MAX_CERT_COUNT_REACHED_MSG },
    { CMR_ERROR_AUTH_CHECK_FAILED, NO_AUTHORIZATION_MSG },
    { CMR_ERROR_ALIAS_LENGTH_REACHED_LIMIT, ALIAS_LENGTH_REACHED_LIMIT_MSG },
    { CMR_ERROR_DEVICE_ENTER_ADVSECMODE, DEVICE_ENTER_ADVSECMODE_MSG },
    { CMR_ERROR_PASSWORD_IS_ERR, PASSWORD_IS_ERROR_MSG },
    { CMR_ERROR_STORE_PATH_NOT_SUPPORTED, STORE_PATH_NOT_SUPPORTED_MSG },
    { CMR_ERROR_UKEY_GENERAL_ERROR, ACCESS_UKEY_SERVICE_FAILED_MSG },
    { CMR_ERROR_UKEY_DEVICE_SUPPORT, CAPABILITY_NOT_SUPPORTED_MSG },
    { CMR_ERROR_HUKS_GENERAL_ERROR, HUKS_ABNORMAL_MSG },
};

enum CmCertAlg {
    CM_ALG_INTERNATIONAL = 1,
    CM_ALG_SM = 2,
};

enum CmJSKeyDigest {
    CM_JS_DIGEST_NONE = 0,
    CM_JS_DIGEST_MD5 = 1,
    CM_JS_DIGEST_SHA1 = 2,
    CM_JS_DIGEST_SHA224 = 3,
    CM_JS_DIGEST_SHA256 = 4,
    CM_JS_DIGEST_SHA384 = 5,
    CM_JS_DIGEST_SHA512 = 6,
    CM_JS_DIGEST_SM3 = 7,
};

enum CmJSKeyPadding {
    CM_JS_PADDING_NONE = 0,
    CM_JS_PADDING_PSS = 1,
    CM_JS_PADDING_PKCS1_V1_5 = 2,
};

struct CmJSKeyPaddingCmKeyPaddingMap {
    CmJSKeyPadding key;
    CmKeyPadding retPadding;
};

const struct CmJSKeyPaddingCmKeyPaddingMap PADDING_MAP[] = {
    { CM_JS_PADDING_NONE, CM_PADDING_NONE },
    { CM_JS_PADDING_PSS, CM_PADDING_PSS },
    { CM_JS_PADDING_PKCS1_V1_5, CM_PADDING_PKCS1_V1_5 },
};

struct CmJSKeyDigestCmKeyDigestMap {
    CmJSKeyDigest key;
    CmKeyDigest retDigest;
};

const struct CmJSKeyDigestCmKeyDigestMap DIGEST_MAP[] = {
    { CM_JS_DIGEST_NONE, CM_DIGEST_NONE },
    { CM_JS_DIGEST_MD5, CM_DIGEST_MD5 },
    { CM_JS_DIGEST_SHA1, CM_DIGEST_SHA1 },
    { CM_JS_DIGEST_SHA224, CM_DIGEST_SHA224 },
    { CM_JS_DIGEST_SHA256, CM_DIGEST_SHA256 },
    { CM_JS_DIGEST_SHA384, CM_DIGEST_SHA384 },
    { CM_JS_DIGEST_SHA512, CM_DIGEST_SHA512 },
    { CM_JS_DIGEST_SM3, CM_DIGEST_SM3 },
};
}
#endif
