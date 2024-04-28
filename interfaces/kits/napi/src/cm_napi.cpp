/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "cm_napi_common.h"

#include "cm_napi_get_system_cert_list.h"
#include "cm_napi_get_system_cert_info.h"
#include "cm_napi_set_cert_status.h"
#include "cm_napi_install_app_cert.h"
#include "cm_napi_uninstall_app_cert.h"
#include "cm_napi_uninstall_all_app_cert.h"
#include "cm_napi_get_app_cert_list.h"
#include "cm_napi_get_app_cert_info.h"
#include "cm_napi_grant.h"
#include "cm_napi_sign_verify.h"
#include "cm_napi_user_trusted_cert.h"

namespace CMNapi {
    inline void AddInt32Property(napi_env env, napi_value object, const char *name, int32_t value)
    {
        napi_value property = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, value, &property));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name, property));
    }

    static void AddCMErrorCodePart(napi_env env, napi_value errorCode)
    {
        AddInt32Property(env, errorCode, "CM_ERROR_NO_PERMISSION", HAS_NO_PERMISSION);
        AddInt32Property(env, errorCode, "CM_ERROR_NOT_SYSTEM_APP", NOT_SYSTEM_APP);
        AddInt32Property(env, errorCode, "CM_ERROR_INVALID_PARAMS", PARAM_ERROR);
        AddInt32Property(env, errorCode, "CM_ERROR_GENERIC", INNER_FAILURE);
        AddInt32Property(env, errorCode, "CM_ERROR_NO_FOUND", NOT_FOUND);
        AddInt32Property(env, errorCode, "CM_ERROR_INCORRECT_FORMAT", INVALID_CERT_FORMAT);
        AddInt32Property(env, errorCode, "CM_ERROR_MAX_CERT_COUNT_REACHED", MAX_CERT_COUNT_REACHED);
        AddInt32Property(env, errorCode, "CM_ERROR_NO_AUTHORIZATION", NO_AUTHORIZATION);
        AddInt32Property(env, errorCode, "CM_ERROR_ALIAS_LENGTH_REACHED_LIMIT", ALIAS_LENGTH_REACHED_LIMIT);
        AddInt32Property(env, errorCode, "CM_ERROR_DEVICE_ENTER_ADVSECMODE", DEVICE_ENTER_ADVSECMODE);
    }

    static napi_value CreateCMErrorCode(napi_env env)
    {
        napi_value errorCode = nullptr;
        NAPI_CALL(env, napi_create_object(env, &errorCode));

        AddCMErrorCodePart(env, errorCode);

        return errorCode;
    }

    static napi_value CreateCMKeyPurpose(napi_env env)
    {
        napi_value keyPurpose = nullptr;
        NAPI_CALL(env, napi_create_object(env, &keyPurpose));

        AddInt32Property(env, keyPurpose, "CM_KEY_PURPOSE_SIGN", CM_KEY_PURPOSE_SIGN);
        AddInt32Property(env, keyPurpose, "CM_KEY_PURPOSE_VERIFY", CM_KEY_PURPOSE_VERIFY);

        return keyPurpose;
    }

    static napi_value CreateCMKeyDigest(napi_env env)
    {
        napi_value keyDigest = nullptr;
        NAPI_CALL(env, napi_create_object(env, &keyDigest));

        AddInt32Property(env, keyDigest, "CM_DIGEST_NONE", CM_JS_DIGEST_NONE);
        AddInt32Property(env, keyDigest, "CM_DIGEST_MD5", CM_JS_DIGEST_MD5);
        AddInt32Property(env, keyDigest, "CM_DIGEST_SHA1", CM_JS_DIGEST_SHA1);
        AddInt32Property(env, keyDigest, "CM_DIGEST_SHA224", CM_JS_DIGEST_SHA224);
        AddInt32Property(env, keyDigest, "CM_DIGEST_SHA256", CM_JS_DIGEST_SHA256);
        AddInt32Property(env, keyDigest, "CM_DIGEST_SHA384", CM_JS_DIGEST_SHA384);
        AddInt32Property(env, keyDigest, "CM_DIGEST_SHA512", CM_JS_DIGEST_SHA512);
        return keyDigest;
    }

    static napi_value CreateCMKeyPadding(napi_env env)
    {
        napi_value keyPadding = nullptr;
        NAPI_CALL(env, napi_create_object(env, &keyPadding));

        AddInt32Property(env, keyPadding, "CM_PADDING_NONE", CM_JS_PADDING_NONE);
        AddInt32Property(env, keyPadding, "CM_PADDING_PSS", CM_JS_PADDING_PSS);
        AddInt32Property(env, keyPadding, "CM_PADDING_PKCS1_V1_5", CM_JS_PADDING_PKCS1_V1_5);
        return keyPadding;
    }
}  // namespace CertManagerNapi

using namespace CMNapi;

extern "C" {
    static napi_value CMNapiRegister(napi_env env, napi_value exports)
    {
        napi_property_descriptor desc[] = {
            DECLARE_NAPI_PROPERTY("CMErrorCode", CreateCMErrorCode(env)),
            DECLARE_NAPI_PROPERTY("CmKeyPurpose", CreateCMKeyPurpose(env)),
            DECLARE_NAPI_PROPERTY("CmKeyDigest", CreateCMKeyDigest(env)),
            DECLARE_NAPI_PROPERTY("CmKeyPadding", CreateCMKeyPadding(env)),

            DECLARE_NAPI_FUNCTION("getSystemTrustedCertificateList", CMNapiGetSystemCertList),
            DECLARE_NAPI_FUNCTION("getSystemTrustedCertificate", CMNapiGetSystemCertInfo),
            DECLARE_NAPI_FUNCTION("setCertificateStatus", CMNapiSetCertStatus),
            DECLARE_NAPI_FUNCTION("installAppCertificate", CMNapiInstallPublicCert),
            DECLARE_NAPI_FUNCTION("installPublicCertificate", CMNapiInstallPublicCert),
            DECLARE_NAPI_FUNCTION("uninstallAllAppCertificate", CMNapiUninstallAllAppCert),
            DECLARE_NAPI_FUNCTION("uninstallAppCertificate", CMNapiUninstallPublicCert),
            DECLARE_NAPI_FUNCTION("getAppCertificateList", CMNapiGetAllPublicCertList),
            DECLARE_NAPI_FUNCTION("getAppCertificate", CMNapiGetPublicCertInfo),
            DECLARE_NAPI_FUNCTION("uninstallPublicCertificate", CMNapiUninstallPublicCert),
            DECLARE_NAPI_FUNCTION("getAllPublicCertificates", CMNapiGetAllPublicCertList),
            DECLARE_NAPI_FUNCTION("getPublicCertificate", CMNapiGetPublicCertInfo),

            DECLARE_NAPI_FUNCTION("installUserTrustedCertificate", CMNapiInstallUserTrustedCert),
            DECLARE_NAPI_FUNCTION("uninstallAllUserTrustedCertificate", CMNapiUninstallAllUserTrustedCert),
            DECLARE_NAPI_FUNCTION("uninstallUserTrustedCertificate", CMNapiUninstallUserTrustedCert),
            DECLARE_NAPI_FUNCTION("getUserTrustedCertificateList", CMNapiGetAllUserTrustedCertList),
            DECLARE_NAPI_FUNCTION("getAllUserTrustedCertificates", CMNapiGetAllUserTrustedCertList),
            DECLARE_NAPI_FUNCTION("getUserTrustedCertificate", CMNapiGetUserTrustedCertInfo),
            DECLARE_NAPI_FUNCTION("installPrivateCertificate", CMNapiInstallPrivateAppCert),
            DECLARE_NAPI_FUNCTION("uninstallPrivateCertificate", CMNapiUninstallPrivateAppCert),
            DECLARE_NAPI_FUNCTION("getPrivateCertificateList", CMNapiGetPrivateAppCertList),
            DECLARE_NAPI_FUNCTION("getAllAppPrivateCertificates", CMNapiGetPrivateAppCertList),
            DECLARE_NAPI_FUNCTION("getPrivateCertificate", CMNapiGetPrivateAppCertInfo),
            DECLARE_NAPI_FUNCTION("grantAppCertificate", CMNapiGrantPublicCertificate),
            DECLARE_NAPI_FUNCTION("grantPublicCertificate", CMNapiGrantPublicCertificate),
            DECLARE_NAPI_FUNCTION("isAuthorizedApp", CMNapiIsAuthorizedApp),
            DECLARE_NAPI_FUNCTION("getAuthorizedAppList", CMNapiGetAuthorizedAppList),
            DECLARE_NAPI_FUNCTION("removeGrantedAppCertificate", CMNapiRemoveGrantedPublic),
            DECLARE_NAPI_FUNCTION("removeGrantedPublicCertificate", CMNapiRemoveGrantedPublic),
            DECLARE_NAPI_FUNCTION("init", CMNapiInit),
            DECLARE_NAPI_FUNCTION("update", CMNapiUpdate),
            DECLARE_NAPI_FUNCTION("finish", CMNapiFinish),
            DECLARE_NAPI_FUNCTION("abort", CMNapiAbort),

            DECLARE_NAPI_FUNCTION("installSystemAppCertificate", CMNapiInstallSystemAppCert),
            DECLARE_NAPI_FUNCTION("uninstallSystemAppCertificate", CMNapiUninstallSystemAppCert),
            DECLARE_NAPI_FUNCTION("getAllSystemAppCertificates", CMNapiGetSystemAppCertList),
            DECLARE_NAPI_FUNCTION("getSystemAppCertificate", CMNapiGetSystemAppCertInfo),
        };
        NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
        return exports;
    }

    static napi_module g_module = {
        .nm_version = 1,
        .nm_flags = 0,
        .nm_filename = nullptr,
        .nm_register_func = CMNapiRegister,
        .nm_modname = "security.certmanager",
        .nm_priv =  nullptr,
        .reserved = { nullptr },
    };

    __attribute__((constructor)) void CertManagerRegister(void)
    {
        napi_module_register(&g_module);
    }
}
