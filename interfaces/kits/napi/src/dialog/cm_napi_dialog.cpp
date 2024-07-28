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

#include "cm_napi_common.h"

#include "cm_napi_open_dialog.h"

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
}  // namespace CertManagerNapi

using namespace CMNapi;

extern "C" {
static napi_value CMDialogNapiRegister(napi_env env, napi_value exports)
{
    napi_property_descriptor desc[] = {
        DECLARE_NAPI_PROPERTY("CertificateDialogErrorCode", CreateCmErrorCode(env)),
        DECLARE_NAPI_PROPERTY("CertificateDialogPageType", CreateCmDialogPageType(env)),

        /* dialog */
        DECLARE_NAPI_FUNCTION("openCertificateManagerDialog", CMNapiOpenCertManagerDialog),
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
