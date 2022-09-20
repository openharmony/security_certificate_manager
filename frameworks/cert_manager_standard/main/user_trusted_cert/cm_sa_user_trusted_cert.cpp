/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "cm_sa.h"

enum CmMessage {
    CM_MSG_INSTALL_USER_CERTIFICATE,
	CM_MSG_UNINSTALL_USER_CERTIFICATE,
	CM_MSG_UNINSTALL_ALL_USER_CERTIFICATE,
};

static struct CmIpcPoint g_cmIpcHandler[] = {
    { CM_MSG_INSTALL_USER_CERTIFICATE, CmIpcServiceInstallUserCert },
    { CM_MSG_UNINSTALL_USER_CERTIFICATE, CmIpcServiceUninstallUserCert },
    { CM_MSG_UNINSTALL_ALL_USER_CERTIFICATE, CmIpcServiceUninstallAllUserCert },
    { CM_MSG_GET_CERTIFICATE_LIST, CmIpcServiceGetCertificateList01 },
    { CM_MSG_GET_CERTIFICATE_INFO, CmIpcServiceGetCertificateInfo01 },
    { CM_MSG_SET_CERTIFICATE_STATUS, CmIpcServiceSetCertStatus01 },
};

