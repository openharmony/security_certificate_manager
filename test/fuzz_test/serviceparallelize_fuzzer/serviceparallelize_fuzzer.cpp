/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "cert_manager_service.h"

#include <unordered_map>
#include <fuzzer/FuzzedDataProvider.h>
#include <cstring>

#include "cm_fuzz_test_common.h"
#include "cm_test_common.h"


using namespace CmFuzzTest;
namespace OHOS {

enum FuncEnum {
    FUNCTION_CM_SERVICE_INSTALL_APP_CERT = 0,
    FUNCTION_CM_SERVICE_GET_APP_CERT,
    FUNCTION_CM_SERVICE_GRANT_APP_CERTIFICATE,
    FUNCTION_CM_SERVICE_GET_AUTHORIZED_APP_LIST,
    FUNCTION_CM_SERVICE_IS_AUTHORIZED_APP,
    FUNCTION_CM_SERVICE_REMOVE_GRANTED_APP,
    FUNCTION_CM_SERVICE_INIT,
    FUNCTION_CM_SERVICE_UPDATE,
    FUNCTION_CM_SERVICE_FINISH,
    FUNCTION_CM_SERVICE_ABORT,
    FUNCTION_CM_SERVICE_GET_CERT_LIST,
    FUNCTION_CM_SERVICE_GET_CERT_INFO,
    FUNCTION_CM_INSTALL_USER_CERT,
    FUNCTION_CM_INSTALL_MULTI_USER_CERT,
    FUNCTION_CM_UNINSTALL_USER_CERT,
    FUNCTION_CM_UNINSTALL_ALL_USER_CERT,
    FUNCTION_CM_SET_STATUS_BACKUP_CERT,
    FUNCTION_CM_SERVICE_CHECK_APP_PERMISSION,
};

static void ConstructCmBlob(FuzzedDataProvider &fdp, CmBlob &cmBlob)
{
    std::string randomString = fdp.ConsumeRandomLengthString();
    uint8_t* newData = new uint8_t[randomString.length()];
    memcpy_s(newData, randomString.length(), randomString.c_str(), randomString.length());
    cmBlob = {
        randomString.length(),
        newData
    };
}

static void ConstructCmContext(FuzzedDataProvider &fdp, CmContext &context)
{
    uint32_t userId = fdp.ConsumeIntegral<uint32_t>();
    uint32_t uid = fdp.ConsumeIntegral<uint32_t>();
    context.userId = userId;
    context.uid = uid;
}

static void ConstructCmAppCertParam(CmBlob appCert, CmBlob appCertPwd,
    CmBlob certAlias, CmAppCertParam &cmAppCertParam)
{
    cmAppCertParam.appCert = &appCert;
    cmAppCertParam.appCertPwd = &appCertPwd;
    cmAppCertParam.certAlias = &certAlias;
}

static void GetCode(FuzzedDataProvider &fdp, FuncEnum &code)
{
    static const FuncEnum fuzzcode[] = {
        FUNCTION_CM_SERVICE_INSTALL_APP_CERT,
        FUNCTION_CM_SERVICE_GET_APP_CERT,
        FUNCTION_CM_SERVICE_GRANT_APP_CERTIFICATE,
        FUNCTION_CM_SERVICE_GET_AUTHORIZED_APP_LIST,
        FUNCTION_CM_SERVICE_IS_AUTHORIZED_APP,
        FUNCTION_CM_SERVICE_REMOVE_GRANTED_APP,
        FUNCTION_CM_SERVICE_INIT,
        FUNCTION_CM_SERVICE_UPDATE,
        FUNCTION_CM_SERVICE_FINISH,
        FUNCTION_CM_SERVICE_ABORT,
        FUNCTION_CM_SERVICE_GET_CERT_LIST,
        FUNCTION_CM_SERVICE_GET_CERT_INFO,
        FUNCTION_CM_INSTALL_USER_CERT,
        FUNCTION_CM_INSTALL_MULTI_USER_CERT,
        FUNCTION_CM_UNINSTALL_USER_CERT,
        FUNCTION_CM_UNINSTALL_ALL_USER_CERT,
        FUNCTION_CM_SET_STATUS_BACKUP_CERT,
        FUNCTION_CM_SERVICE_CHECK_APP_PERMISSION,
    };

    code = fdp.PickValueInArray(fuzzcode);
}

static void FuzzCmServicInstallAppCert(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    struct CmBlob appCert;
    ConstructCmBlob(fdp, appCert);
    struct CmBlob appCertPwd;
    ConstructCmBlob(fdp, appCertPwd);
    struct CmBlob certAlias;
    ConstructCmBlob(fdp, certAlias);
    struct CmAppCertParam cmAppCertParam;
    ConstructCmAppCertParam(appCert, appCert, certAlias, cmAppCertParam);
    cmAppCertParam.userId = fdp.ConsumeIntegral<uint32_t>();
    cmAppCertParam.store = fdp.ConsumeIntegral<uint32_t>();
    struct CmBlob keyUri;
    ConstructCmBlob(fdp, keyUri);
    CmServicInstallAppCert(&context, &cmAppCertParam, &keyUri);
    delete[] appCert.data;
    delete[] appCertPwd.data;
    delete[] certAlias.data;
    delete[] keyUri.data;
}

static void FuzzCmServiceGetAppCert(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    uint32_t store = fdp.ConsumeIntegral<uint32_t>();
    struct CmBlob keyUri;
    ConstructCmBlob(fdp, keyUri);
    keyUri.data[keyUri.size - 1] = '\0';
    struct CmBlob certBlob;
    ConstructCmBlob(fdp, certBlob);
    CmServiceGetAppCert(&context, store, &keyUri, &certBlob);
    delete[] keyUri.data;
    delete[] certBlob.data;
}

static void FuzzCmServiceGrantAppCertificate(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    uint32_t appUid = fdp.ConsumeIntegral<uint32_t>();
    struct CmBlob keyUri;
    ConstructCmBlob(fdp, keyUri);
    struct CmBlob authUri;
    ConstructCmBlob(fdp, authUri);
    CmServiceGrantAppCertificate(&context, &keyUri, appUid, &authUri);
    delete[] keyUri.data;
    delete[] authUri.data;
}

static void FuzzCmServiceGetAuthorizedAppList(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    struct CmBlob keyUri;
    ConstructCmBlob(fdp, keyUri);
    struct CmAppUidList appUidList;
    appUidList.appUidCount = fdp.ConsumeIntegral<uint32_t>();
    uint32_t appUid = fdp.ConsumeIntegral<uint32_t>();
    appUidList.appUid = &appUid;
    CmServiceGetAuthorizedAppList(&context, &keyUri, &appUidList);
    delete[] keyUri.data;
}

static void FuzzCmServiceIsAuthorizedApp(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    struct CmBlob authUri;
    ConstructCmBlob(fdp, authUri);
    CmServiceIsAuthorizedApp(&context, &authUri);
    delete[] authUri.data;
}

static void FuzzCmServiceRemoveGrantedApp(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    struct CmBlob keyUri;
    ConstructCmBlob(fdp, keyUri);
    uint32_t appUid = fdp.ConsumeIntegral<uint32_t>();
    CmServiceRemoveGrantedApp(&context, &keyUri, appUid);
    delete[] keyUri.data;
}

static void FuzzCmServiceInit(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    struct CmBlob authUri;
    ConstructCmBlob(fdp, authUri);
    struct CmBlob handle;
    ConstructCmBlob(fdp, handle);
    struct CmSignatureSpec spec;
    CmServiceInit(&context, &authUri, &spec, &handle);
    delete[] authUri.data;
    delete[] handle.data;
}

static void FuzzCmServiceUpdate(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    struct CmBlob handle;
    ConstructCmBlob(fdp, handle);
    struct CmBlob inData;
    ConstructCmBlob(fdp, inData);
    CmServiceUpdate(&context, &handle, &inData);
    delete[] handle.data;
    delete[] inData.data;
}

static void FuzzCmServiceFinish(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    struct CmBlob handle;
    ConstructCmBlob(fdp, handle);
    struct CmBlob inData;
    ConstructCmBlob(fdp, inData);
    struct CmBlob outData;
    ConstructCmBlob(fdp, outData);
    CmServiceFinish(&context, &handle, &inData, &outData);
    delete[] handle.data;
    delete[] inData.data;
    delete[] outData.data;
}

static void FuzzCmServiceAbort(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    struct CmBlob handle;
    ConstructCmBlob(fdp, handle);
    CmServiceAbort(&context, &handle);
    delete[] handle.data;
}

static void FuzzCmServiceGetCertList(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    struct UserCAProperty prop;
    uint32_t store = fdp.ConsumeIntegral<uint32_t>();
    std::string random = fdp.ConsumeRandomLengthString();
    struct CmMutableBlob cmBlob = { strlen(random.c_str()) + 1, (uint8_t *)random.c_str() };
    struct CmMutableBlob blobArray[] = {cmBlob};
    struct CmMutableBlob certFileList = {
        .size = sizeof(blobArray) / sizeof(struct CmMutableBlob),
        .data = (uint8_t*)blobArray
    };
    CmServiceGetCertList(&context, &prop, store, &certFileList);
}

static void FuzzCmServiceGetCertInfo(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    struct CmBlob certUri;
    ConstructCmBlob(fdp, certUri);
    uint32_t store = fdp.ConsumeIntegral<uint32_t>();
    struct CmBlob certificateData;
    ConstructCmBlob(fdp, certificateData);
    uint32_t status = fdp.ConsumeIntegral<uint32_t>();
    CmServiceGetCertInfo(&context, &certUri, store, &certificateData, &status);
    delete[] certUri.data;
    delete[] certificateData.data;
}

static void FuzzCmInstallUserCert(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    struct CmBlob userCert;
    ConstructCmBlob(fdp, userCert);
    uint32_t status = fdp.ConsumeIntegral<uint32_t>();
    struct CmBlob certAlias;
    ConstructCmBlob(fdp, certAlias);
    struct CmBlob certUri;
    ConstructCmBlob(fdp, certUri);
    CmInstallUserCert(&context, &userCert, &certAlias, status, &certUri);
    delete[] userCert.data;
    delete[] certAlias.data;
    delete[] certUri.data;
}

static void FuzzCmInstallMultiUserCert(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    struct CmBlob userCert;
    ConstructCmBlob(fdp, userCert);
    uint32_t status = fdp.ConsumeIntegral<uint32_t>();
    struct CmBlob certAlias;
    ConstructCmBlob(fdp, certAlias);
    struct CmBlob certUri;
    ConstructCmBlob(fdp, certUri);
    CmInstallMultiUserCert(&context, &userCert, &certAlias, status, &certUri);
    delete[] userCert.data;
    delete[] certAlias.data;
    delete[] certUri.data;
}

static void FuzzCmUninstallUserCert(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    struct CmBlob certUri;
    ConstructCmBlob(fdp, certUri);
    CmUninstallUserCert(&context, &certUri);
    delete[] certUri.data;
}

static void FuzzCmUninstallAllUserCert(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    CmUninstallAllUserCert(&context);
}

static void FuzzCmSetStatusBackupCert(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    struct CmBlob certUri;
    ConstructCmBlob(fdp, certUri);
    uint32_t store = fdp.ConsumeIntegral<uint32_t>();
    uint32_t status = fdp.ConsumeIntegral<uint32_t>();
    CmSetStatusBackupCert(&context, &certUri, store, status);
    delete[] certUri.data;
}

static void FuzzCmServiceCheckAppPermission(FuzzedDataProvider &fdp)
{
    CmContext context = { 0, 0 };
    ConstructCmContext(fdp, context);
    struct CmBlob keyUri;
    ConstructCmBlob(fdp, keyUri);
    uint32_t hasPermission = fdp.ConsumeIntegral<uint32_t>();
    struct CmBlob huksAlias;
    ConstructCmBlob(fdp, huksAlias);
    CmServiceCheckAppPermission(&context, &keyUri, &hasPermission, &huksAlias);
    delete[] keyUri.data;
    delete[] huksAlias.data;
}

bool FuzzIService(FuzzedDataProvider &fdp)
{
    FuncEnum code;
    GetCode(fdp, code);
    using IpcFuzzFunc = void(*)(FuzzedDataProvider&);
    const std::unordered_map<FuncEnum, IpcFuzzFunc> ipcFuzzFuncs = {
        { FUNCTION_CM_SERVICE_INSTALL_APP_CERT, FuzzCmServicInstallAppCert },
        { FUNCTION_CM_SERVICE_GET_APP_CERT, FuzzCmServiceGetAppCert },
        { FUNCTION_CM_SERVICE_GRANT_APP_CERTIFICATE, FuzzCmServiceGrantAppCertificate },
        { FUNCTION_CM_SERVICE_GET_AUTHORIZED_APP_LIST, FuzzCmServiceGetAuthorizedAppList },
        { FUNCTION_CM_SERVICE_IS_AUTHORIZED_APP, FuzzCmServiceIsAuthorizedApp },
        { FUNCTION_CM_SERVICE_REMOVE_GRANTED_APP, FuzzCmServiceRemoveGrantedApp },
        { FUNCTION_CM_SERVICE_INIT, FuzzCmServiceInit },
        { FUNCTION_CM_SERVICE_UPDATE, FuzzCmServiceUpdate },
        { FUNCTION_CM_SERVICE_FINISH, FuzzCmServiceFinish },
        { FUNCTION_CM_SERVICE_ABORT, FuzzCmServiceAbort },
        { FUNCTION_CM_SERVICE_GET_CERT_LIST, FuzzCmServiceGetCertList },
        { FUNCTION_CM_SERVICE_GET_CERT_INFO, FuzzCmServiceGetCertInfo },
        { FUNCTION_CM_INSTALL_USER_CERT, FuzzCmInstallUserCert },
        { FUNCTION_CM_INSTALL_MULTI_USER_CERT, FuzzCmInstallMultiUserCert },
        { FUNCTION_CM_UNINSTALL_USER_CERT, FuzzCmUninstallUserCert },
        { FUNCTION_CM_UNINSTALL_ALL_USER_CERT, FuzzCmUninstallAllUserCert },
        { FUNCTION_CM_SET_STATUS_BACKUP_CERT, FuzzCmSetStatusBackupCert },
        { FUNCTION_CM_SERVICE_CHECK_APP_PERMISSION, FuzzCmServiceCheckAppPermission }
    };

    auto it = ipcFuzzFuncs.find(code);
    if (it != ipcFuzzFuncs.end()) {
        it->second(fdp);
    }
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider fdp(data, size);
    OHOS::FuzzIService(fdp);
    return 0;
}