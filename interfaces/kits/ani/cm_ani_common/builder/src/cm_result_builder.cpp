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

#include "cm_result_builder.h"
#include "ani.h"
#include "cm_ani_utils.h"
#include "cm_type.h"
#include "cm_log.h"
#include <string>

namespace OHOS::Security::CertManager::Ani {
CMResultBuilder::CMResultBuilder(ani_env *env)
{
    this->env = env;
}

CMResultBuilder *CMResultBuilder::setUri(CmBlob *uri)
{
    this->uri = uri;
    return this;
}

int32_t CMResultBuilder::buildUri()
{
    if (uri == nullptr) {
        CM_LOG_D("cmResult uri is nullptr");
        return CM_SUCCESS;
    }
    ani_string uriString = AniUtils::GenerateString(env, *uri);
    if (uriString == nullptr) {
        CM_LOG_E("cmResult generate uri failed");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    ani_status status = env->Object_SetPropertyByName_Ref(cmResult, "uri", uriString);
    if (status != ANI_OK) {
        CM_LOG_E("cmResult set property uri failed. ret = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

CMResultBuilder *CMResultBuilder::setCredentialList(CredentialList *credentialList)
{
    this->credentialList = credentialList;
    return this;
}

int32_t CMResultBuilder::buildCredentialList()
{
    if (credentialList == nullptr) {
        CM_LOG_D("cmResult credentialList is nullptr");
        return CM_SUCCESS;
    }
    uint32_t credCount = credentialList->credentialCount;
    CredentialAbstract *credentialAbstract = credentialList->credentialAbstract;
    if (credCount == 0 || credentialAbstract == nullptr) {
        return CM_SUCCESS;
    }

    ani_array aniCredArray;
    int32_t ret = AniUtils::GenerateCredArray(env, credentialAbstract, credCount, aniCredArray);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("generate cred array failed.");
        return ret;
    }
    ani_status status = env->Object_SetPropertyByName_Ref(cmResult, "credentialList", aniCredArray);
    if (status != ANI_OK) {
        CM_LOG_E("cmResult set property credentialList failed. ret = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

CMResultBuilder *CMResultBuilder::setCredential(Credential *credential)
{
    this->credential = credential;
    return this;
}

int32_t CMResultBuilder::credentialSetStringProperty(ani_object credentialObj)
{
    CmBlob typeBlob = { strlen(credential->type), (uint8_t *)credential->type };
    CmBlob aliasBlob = { strlen(credential->alias), (uint8_t *)credential->alias };
    CmBlob keyUriBlob = { strlen(credential->keyUri), (uint8_t *)credential->keyUri };
    ani_string typeString = AniUtils::GenerateString(env, typeBlob);
    ani_string aliasString = AniUtils::GenerateString(env, aliasBlob);
    ani_string keyUriString = AniUtils::GenerateString(env, keyUriBlob);
    if (typeString == nullptr || aliasString == nullptr || keyUriString == nullptr) {
        CM_LOG_E("credential generate string failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (env->Object_SetPropertyByName_Ref(credentialObj, "type", typeString) != ANI_OK) {
        CM_LOG_E("set credential property type failed");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (env->Object_SetPropertyByName_Ref(credentialObj, "alias", aliasString) != ANI_OK) {
        CM_LOG_E("set credential property alias failed");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (env->Object_SetPropertyByName_Ref(credentialObj, "keyUri", keyUriString) != ANI_OK) {
        CM_LOG_E("set credential property keyUri failed");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t CMResultBuilder::buildCredential()
{
    if (credential == nullptr) {
        CM_LOG_D("cmResult credential is nullptr");
        return CM_SUCCESS;
    }
    ani_object credentialObj;
    int32_t ret = AniUtils::GenerateCredentialObj(env, credentialObj);
    if (ret != CM_SUCCESS) {
        CM_LOG_I("generate credentialObj failed. ret = %d", ret);
        return ret;
    }
    ret = credentialSetStringProperty(credentialObj);
    if (ret != CM_SUCCESS) {
        CM_LOG_I("credentialObj set string property failed. ret = %d", ret);
        return ret;
    }
    ani_object credData;
    ret = AniUtils::GenerateUint8Array(env, &credential->credData, credData);
    if (ret != CM_SUCCESS) {
        CM_LOG_I("generate credData object failed. ret = %d", ret);
        return ret;
    }
    if (env->Object_SetPropertyByName_Int(credentialObj, "certNum",
        static_cast<ani_int>(credential->certNum)) != ANI_OK) {
        CM_LOG_E("set credential property certNum failed");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (env->Object_SetPropertyByName_Int(credentialObj, "keyNum",
        static_cast<ani_int>(credential->keyNum)) != ANI_OK) {
        CM_LOG_E("set credential property keyNum failed");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    if (env->Object_SetPropertyByName_Ref(credentialObj, "credentialData", credData) != ANI_OK) {
        CM_LOG_E("set credential property credData failed");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    ani_status status = env->Object_SetPropertyByName_Ref(cmResult, "credential", credentialObj);
    if (status != ANI_OK) {
        CM_LOG_E("cmResult set property credential failed. ret = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

CMResultBuilder *CMResultBuilder::setOutData(CmBlob *outData)
{
    this->outData = outData;
    return this;
}

int32_t CMResultBuilder::buildOutData()
{
    if (this->outData == nullptr) {
        CM_LOG_D("cmResult outData is nullptr");
        return CM_SUCCESS;
    }
    ani_object aniOutData;
    int32_t ret = AniUtils::GenerateUint8Array(env, this->outData, aniOutData);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("generate outData failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    ani_status status = env->Object_SetPropertyByName_Ref(this->cmResult, "outData", aniOutData);
    if (status != ANI_OK) {
        CM_LOG_E("cmResult set property outData failed. ret = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

CMResultBuilder *CMResultBuilder::setCertList(CertList *certList)
{
    this->certList = certList;
    return this;
}

int32_t CMResultBuilder::buildCertList()
{
    if (certList == nullptr) {
        CM_LOG_D("cmResult certList is nullptr");
        return CM_SUCCESS;
    }
    uint32_t certCount = certList->certsCount;
    CertAbstract *certAbstract = certList->certAbstract;
    if (certCount == 0 || certAbstract == nullptr) {
        return CM_SUCCESS;
    }

    ani_array aniCertArray;
    int32_t ret = AniUtils::GenerateCertArray(env, certAbstract, certCount, aniCertArray);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("generate cert array failed.");
        return ret;
    }
    ani_status status = env->Object_SetPropertyByName_Ref(cmResult, "certList", aniCertArray);
    if (status != ANI_OK) {
        CM_LOG_E("cmResult set property certList failed. ret = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

CMResultBuilder *CMResultBuilder::setCertInfo(CertInfo *certInfo)
{
    this->certInfo = certInfo;
    return this;
}

int32_t CMResultBuilder::buildCertInfo()
{
    if (this->certInfo == nullptr) {
        CM_LOG_D("cmResult certInfo is nullptr");
        return CM_SUCCESS;
    }
    ani_object certInfoObj;
    int32_t ret = AniUtils::GenerateCertInfo(this->env, certInfoObj);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("generate certInfo failed.");
        return ret;
    }
    std::map<std::string, std::string> propertyMap;
    propertyMap["uri"] = std::string(this->certInfo->uri);
    propertyMap["certAlias"] = std::string(this->certInfo->certAlias);
    propertyMap["issuerName"] = std::string(this->certInfo->issuerName);
    propertyMap["subjectName"] = std::string(this->certInfo->subjectName);
    propertyMap["serial"] = std::string(this->certInfo->serial);
    propertyMap["notBefore"] = std::string(this->certInfo->notBefore);
    propertyMap["notAfter"] = std::string(this->certInfo->notAfter);
    propertyMap["fingerprintSha256"] = std::string(this->certInfo->fingerprintSha256);
    ret = AniUtils::SetObjStringProperty(env, certInfoObj, propertyMap);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("set certInfo property failed.");
        return ret;
    }
    ani_status status = env->Object_SetPropertyByName_Boolean(certInfoObj, "state",
        static_cast<ani_boolean>(this->certInfo->status));
    if (status != ANI_OK) {
        CM_LOG_E("certInfo set state failed. ret = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    ani_object certInfoData;
    ret = AniUtils::GenerateUint8Array(env, &this->certInfo->certInfo, certInfoData);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("generate certInfo data failed.");
        return ret;
    }
    status = env->Object_SetPropertyByName_Ref(certInfoObj, "cert", certInfoData);
    if (status != ANI_OK) {
        CM_LOG_E("certInfo set propterty cert failed.");
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    status = env->Object_SetPropertyByName_Ref(cmResult, "certInfo", certInfoObj);
    if (status != ANI_OK) {
        CM_LOG_E("cmResult set property certInfo failed. ret = %d", static_cast<int32_t>(status));
        return CMR_ERROR_INVALID_ARGUMENT;
    }
    return CM_SUCCESS;
}

int32_t CMResultBuilder::build()
{
    int32_t ret = AniUtils::GenerateCmResult(env, cmResult);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("cmResult build failed");
        return ret;
    }
    ret = buildUri();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("cmResult build uri failed.");
        return ret;
    }
    ret = buildCredentialList();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("cmResult build credList failed.");
        return ret;
    }
    ret = buildCredential();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("cmResult build credential failed.");
        return ret;
    }
    ret = buildOutData();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("cmResult build outData failed.");
        return ret;
    }
    ret = buildCertList();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("cmResult build certList failed.");
        return ret;
    }
    ret = buildCertInfo();
    if (ret != CM_SUCCESS) {
        CM_LOG_E("cmResult build certInfo failed.");
        return ret;
    }
    return CM_SUCCESS;
}
} // OHOS::Security::CertManager::Ani