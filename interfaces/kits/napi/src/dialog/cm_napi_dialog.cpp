/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cm_napi_dialog_common.h"

#include "cm_napi_open_detail_dialog.h"
#include "cm_napi_open_dialog.h"
#include "cm_napi_open_install_dialog.h"
#include "cm_napi_open_uninstall_dialog.h"
#include "cm_napi_open_authorize_dialog.h"
#include "cm_napi_open_ukey_auth_dialog.h"

namespace CMNapi {
inline void AddInt32Property(napi_env env, napi_value object, const char *name, int32_t value)
{
    napi_value property = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, value, &property));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, object, name, property));
}

static napi_value CreateCmErrorCode(napi_env env)
{
    napi_value dialogErrorCode = nullptr;
    NAPI_CALL(env, napi_create_object(env, &dialogErrorCode));

    AddInt32Property(env, dialogErrorCode, "ERROR_GENERIC", DIALOG_ERROR_GENERIC);
    AddInt32Property(env, dialogErrorCode, "ERROR_OPERATION_CANCELED", DIALOG_ERROR_OPERATION_CANCELED);
    AddInt32Property(env, dialogErrorCode, "ERROR_OPERATION_FAILED", DIALOG_ERROR_INSTALL_FAILED);
    AddInt32Property(env, dialogErrorCode, "ERROR_DEVICE_NOT_SUPPORTED", DIALOG_ERROR_NOT_SUPPORTED);
    AddInt32Property(env, dialogErrorCode, "ERROR_NOT_COMPLY_SECURITY_POLICY",
        DIALOG_ERROR_NOT_COMPLY_SECURITY_POLICY);
    AddInt32Property(env, dialogErrorCode, "ERROR_PARAMETER_VALIDATION_FAILED",
        DIALOG_ERROR_PARAMETER_VALIDATION_FAILED);
    AddInt32Property(env, dialogErrorCode, "ERROR_NO_AVAILABLE_CERTIFICATE",
        DIALOG_ERROR_NO_AVAILABLE_CERTIFICATE);

    return dialogErrorCode;
}

static napi_value CreateCmDialogPageType(napi_env env)
{
    napi_value dialogPageType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &dialogPageType));

    AddInt32Property(env, dialogPageType, "PAGE_MAIN", PAGE_MAIN);
    AddInt32Property(env, dialogPageType, "PAGE_CA_CERTIFICATE", PAGE_CA_CERTIFICATE);
    AddInt32Property(env, dialogPageType, "PAGE_CREDENTIAL", PAGE_CREDENTIAL);
    AddInt32Property(env, dialogPageType, "PAGE_INSTALL_CERTIFICATE", PAGE_INSTALL_CERTIFICATE);

    return dialogPageType;
}

static napi_value CreateCmCertificateType(napi_env env)
{
    napi_value certificateType = nullptr;
    NAPI_CALL(env, napi_create_object(env, &certificateType));

    AddInt32Property(env, certificateType, "CA_CERT", CA_CERT);
    AddInt32Property(env, certificateType, "CREDENTIAL_USER", CREDENTIAL_USER);
    AddInt32Property(env, certificateType, "CREDENTIAL_APP", CREDENTIAL_APP);
    AddInt32Property(env, certificateType, "CREDENTIAL_UKEY", CREDENTIAL_UKEY);

    return certificateType;
}

static napi_value CreateCmCertificateScope(napi_env env)
{
    napi_value certificateScope = nullptr;
    NAPI_CALL(env, napi_create_object(env, &certificateScope));

    AddInt32Property(env, certificateScope, "NOT_SPECIFIED", NOT_SPECIFIED);
    AddInt32Property(env, certificateScope, "CURRENT_USER", CURRENT_USER);
    AddInt32Property(env, certificateScope, "GLOBAL_USER", GLOBAL_USER);

    return certificateScope;
}

}  // namespace CertManagerNapi

using namespace CMNapi;

extern "C" {
static napi_value CMDialogNapiRegister(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("CertificateDialogErrorCode", CreateCmErrorCode(env)),
        DECLARE_NAPI_PROPERTY("CertificateDialogPageType", CreateCmDialogPageType(env)),
        DECLARE_NAPI_PROPERTY("CertificateType", CreateCmCertificateType(env)),
        DECLARE_NAPI_PROPERTY("CertificateScope", CreateCmCertificateScope(env)),

        /* dialog */
        DECLARE_NAPI_FUNCTION("openCertificateManagerDialog", CMNapiOpenCertManagerDialog),
        DECLARE_NAPI_FUNCTION("openInstallCertificateDialog", CMNapiOpenInstallCertDialog),
        DECLARE_NAPI_FUNCTION("openUninstallCertificateDialog", CMNapiOpenUninstallCertDialog),
        DECLARE_NAPI_FUNCTION("openCertificateDetailDialog", CMNapiOpenDetailDialog),
        DECLARE_NAPI_FUNCTION("openAuthorizeDialog", CMNapiOpenAuthorizeDialog),
        DECLARE_NAPI_FUNCTION("openUkeyAuthDialog", CMNapiOpenUkeyAuthorizeDialog),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    return exports;
}

static napi_module g_module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = CMDialogNapiRegister,
    .nm_modname = "security.certManagerDialog",
    .nm_priv =  nullptr,
    .reserved = { nullptr },
};

__attribute__((constructor)) void CMDialogNapiRegister(void)
{
    napi_module_register(&g_module);
}
}
