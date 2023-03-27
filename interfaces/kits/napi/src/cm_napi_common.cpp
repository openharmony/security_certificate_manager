/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "cm_napi_common.h"

#include "securec.h"

#include "cm_log.h"
#include "cm_type.h"

namespace CMNapi {
namespace {
constexpr int CM_MAX_DATA_LEN = 0x6400000; // The maximum length is 100M
constexpr int RESULT_ARG_NUMBER = 2;
}  // namespace

static napi_value GetCmContextAttribute(napi_env env, napi_value object, const char *type, int maxSize,
    char *&srcData)
{
    napi_value typeValue = nullptr;
    napi_status  status = napi_get_named_property(env, object, type, &typeValue);
    if (status != napi_ok || typeValue == nullptr) {
        GET_AND_THROW_LAST_ERROR((env));
        CM_LOG_E("could not get property %s", type);
        return nullptr;
    }

    size_t length = 0;
    status = napi_get_value_string_utf8(env, typeValue, nullptr, 0, &length);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        CM_LOG_E("could not get string length");
        return nullptr;
    }

    if (static_cast<int>(length) > maxSize) {
        CM_LOG_E("input param length too large");
        return nullptr;
    }

    srcData = static_cast<char *>(CmMalloc(length + 1));
    if (srcData == nullptr) {
        napi_throw_error(env, nullptr, "could not alloc memory");
        CM_LOG_E("could not alloc memory");
        return nullptr;
    }
    (void)memset_s(srcData, length + 1, 0, length + 1);

    size_t result = 0;
    status = napi_get_value_string_utf8(env, typeValue, srcData, length + 1, &result);
    if (status != napi_ok) {
        CmFree(srcData);
        srcData = nullptr;
        GET_AND_THROW_LAST_ERROR((env));
        CM_LOG_E("could not get string");
        return nullptr;
    }

    return GetInt32(env, 0);
}

napi_value ParseCmContext(napi_env env, napi_value object, CmContext *&cmContext)
{
    char *userIdData = nullptr;
    char *uidData = nullptr;
    char *packageNameData = nullptr;

    int32_t ret = CM_SUCCESS;
    do {
        napi_value userIdStatus = GetCmContextAttribute(env, object,
            CM_CONTEXT_PROPERTY_USERID.c_str(), CM_MAX_DATA_LEN, userIdData);
        napi_value uidStatus = GetCmContextAttribute(env, object,
            CM_CONTEXT_PROPERTY_UID.c_str(), CM_MAX_DATA_LEN, uidData);
        napi_value packageNameStatus = GetCmContextAttribute(env, object,
            CM_CONTEXT_PROPERTY_PACKAGENAME.c_str(), CM_MAX_DATA_LEN, packageNameData);
        if (userIdStatus == nullptr || uidStatus == nullptr || packageNameStatus == nullptr) {
            CM_LOG_E("get userid or uid or packName failed");
            ret = CMR_ERROR;
            break;
        }

        cmContext = static_cast<CmContext *>(CmMalloc(sizeof(CmContext)));
        if (cmContext == nullptr) {
            CM_LOG_E("could not alloc memory");
            ret = CMR_ERROR_MALLOC_FAIL;
            break;
        }

        cmContext->userId = static_cast<uint32_t>(atoi(userIdData));
        cmContext->uid = static_cast<uint32_t>(atoi(uidData));
        if (strcpy_s(cmContext->packageName, sizeof(cmContext->packageName), packageNameData) != EOK) {
            CM_LOG_E("copy package name failed");
            ret = CMR_ERROR_INVALID_OPERATION;
            break;
        }
    } while (0);
    CM_FREE_PTR(userIdData);
    CM_FREE_PTR(uidData);
    CM_FREE_PTR(packageNameData);
    if (ret != CM_SUCCESS) {
        return nullptr;
    }
    return GetInt32(env, 0);
}

napi_value ParseUint32(napi_env env, napi_value object, uint32_t &store)
{
    napi_valuetype valueType;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_number) {
        CM_LOG_E("param type is not number");
        return nullptr;
    }
    uint32_t temp = 0;
    napi_get_value_uint32(env, object, &temp);
    store = temp;
    return GetInt32(env, 0);
}

napi_value ParseBoolean(napi_env env, napi_value object, bool &status)
{
    napi_valuetype valueType;
    napi_typeof(env, object, &valueType);
    if (valueType != napi_boolean) {
        CM_LOG_E("param type is not bool");
        return nullptr;
    }
    bool temp = false;
    napi_get_value_bool(env, object, &temp);
    status = temp;
    return GetInt32(env, 0);
}

napi_value ParseString(napi_env env, napi_value object, CmBlob *&certUri)
{
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, object, &valueType));
    if (valueType != napi_string) {
        CM_LOG_E("the type of param is not string");
        return nullptr;
    }
    size_t length = 0;
    napi_status status = napi_get_value_string_utf8(env, object, nullptr, 0, &length);
    if (status != napi_ok) {
        GET_AND_THROW_LAST_ERROR((env));
        CM_LOG_E("could not get string length");
        return nullptr;
    }

    if (length > CM_MAX_DATA_LEN) {
        CM_LOG_E("input key alias length too large");
        return nullptr;
    }

    char *data = static_cast<char *>(CmMalloc(length + 1));
    if (data == nullptr) {
        napi_throw_error(env, nullptr, "could not alloc memory");
        CM_LOG_E("could not alloc memory");
        return nullptr;
    }
    (void)memset_s(data, length + 1, 0, length + 1);

    size_t result = 0;
    status = napi_get_value_string_utf8(env, object, data, length + 1, &result);
    if (status != napi_ok) {
        CmFree(data);
        GET_AND_THROW_LAST_ERROR((env));
        CM_LOG_E("could not get string");
        return nullptr;
    }

    certUri = static_cast<CmBlob *>(CmMalloc(sizeof(CmBlob)));
    if (certUri == nullptr) {
        CmFree(data);
        napi_throw_error(env, nullptr, "could not alloc memory");
        CM_LOG_E("could not alloc memory");
        return nullptr;
    }
    certUri->data = reinterpret_cast<uint8_t *>(data);
    certUri->size = static_cast<uint32_t>((length + 1) & UINT32_MAX);

    return GetInt32(env, 0);
}

napi_value GetUint8Array(napi_env env, napi_value object, CmBlob &arrayBlob)
{
    napi_typedarray_type arrayType;
    napi_value arrayBuffer = nullptr;
    size_t length = 0;
    size_t offset = 0;
    void *rawData = nullptr;
    NAPI_CALL(
        env, napi_get_typedarray_info(env, object, &arrayType, &length,
        static_cast<void **>(&rawData), &arrayBuffer, &offset));
    NAPI_ASSERT(env, arrayType == napi_uint8_array, "Param is not uint8 array");

    if (length > CM_MAX_DATA_LEN) {
        CM_LOG_E("Data is too large, length = %x", length);
        return nullptr;
    }
    if (length == 0) {
        CM_LOG_I("The memory length created is only 1 Byte");
        // The memory length created is only 1 Byte
        arrayBlob.data = static_cast<uint8_t *>(CmMalloc(1));
    } else {
        arrayBlob.data = static_cast<uint8_t *>(CmMalloc(length));
    }
    if (arrayBlob.data == nullptr) {
        CM_LOG_E("Malloc failed");
        return nullptr;
    }
    (void)memset_s(arrayBlob.data, length, 0, length);
    if (memcpy_s(arrayBlob.data, length, rawData, length) != EOK) {
        return nullptr;
    }
    arrayBlob.size = static_cast<uint32_t>(length);

    return GetInt32(env, 0);
}

napi_ref GetCallback(napi_env env, napi_value object)
{
    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, object, &valueType);
    if (status != napi_ok) {
        CM_LOG_E("could not get object type");
        return nullptr;
    }

    if (valueType != napi_function) {
        CM_LOG_E("invalid type");
        return nullptr;
    }

    napi_ref ref = nullptr;
    status = napi_create_reference(env, object, 1, &ref);
    if (status != napi_ok) {
        CM_LOG_E("could not create reference");
        return nullptr;
    }
    return ref;
}

static napi_value GenerateAarrayBuffer(napi_env env, uint8_t *data, uint32_t size)
{
    uint8_t *buffer = static_cast<uint8_t *>(CmMalloc(size));
    if (buffer == nullptr) {
        return nullptr;
    }
    (void)memcpy_s(buffer, size, data, size);

    napi_value outBuffer = nullptr;
    napi_status status = napi_create_external_arraybuffer(
        env, buffer, size, [](napi_env env, void *data, void *hint) { CmFree(data); }, nullptr, &outBuffer);
    if (status == napi_ok) {
        // free by finalize callback
        buffer = nullptr;
    } else {
        CmFree(buffer);
        GET_AND_THROW_LAST_ERROR((env));
    }

    return outBuffer;
}

napi_value GenerateCertAbstractArray(napi_env env, const struct CertAbstract *certAbstract, const uint32_t certCount)
{
    if (certCount == 0 || certAbstract == nullptr) {
        return nullptr;
    }
    napi_value array = nullptr;
    NAPI_CALL(env, napi_create_array(env, &array));
    for (uint32_t i = 0; i < certCount; i++) {
        napi_value uri = nullptr;
        napi_value certAlias = nullptr;
        napi_value subjectName = nullptr;
        napi_value status = nullptr;

        napi_create_string_latin1(env, static_cast<const char *>(certAbstract[i].uri), NAPI_AUTO_LENGTH, &uri);
        napi_create_string_latin1(env, static_cast<const char *>(certAbstract[i].certAlias),
            NAPI_AUTO_LENGTH, &certAlias);
        napi_create_string_latin1(env, static_cast<const char *>(certAbstract[i].subjectName),
            NAPI_AUTO_LENGTH, &subjectName);
        napi_get_boolean(env, certAbstract[i].status, &status);

        napi_value element = nullptr;
        napi_create_object(env, &element);
        napi_set_named_property (env, element, CM_CERT_PROPERTY_URI.c_str(), uri);
        napi_set_named_property (env, element, CM_CERT_PROPERTY_CERTALIAS.c_str(), certAlias);
        napi_set_named_property (env, element, CM_CERT_PROPERTY_STATUS.c_str(), status);
        napi_set_named_property (env, element, CM_CERT_PROPERTY_SUBJECTNAME.c_str(), subjectName);

        napi_set_element(env, array, i, element);
    }
    return array;
}

napi_value GenerateCredentialAbstractArray(napi_env env,
    const struct CredentialAbstract *credentialAbstract, const uint32_t credentialCount)
{
    if (credentialCount == 0 || credentialAbstract == nullptr) {
        return nullptr;
    }
    napi_value array = nullptr;
    NAPI_CALL(env, napi_create_array(env, &array));
    for (uint32_t i = 0; i < credentialCount; i++) {
        napi_value type = nullptr;
        napi_value alias = nullptr;
        napi_value keyUri = nullptr;
        napi_create_string_latin1(env, static_cast<const char *>(credentialAbstract[i].type),
            NAPI_AUTO_LENGTH, &type);
        napi_create_string_latin1(env, static_cast<const char *>(credentialAbstract[i].alias),
            NAPI_AUTO_LENGTH, &alias);
        napi_create_string_latin1(env, static_cast<const char *>(credentialAbstract[i].keyUri),
            NAPI_AUTO_LENGTH, &keyUri);

        napi_value element = nullptr;
        napi_create_object(env, &element);
        napi_set_named_property (env, element, CM_CERT_PROPERTY_TYPE.c_str(), type);
        napi_set_named_property (env, element, CM_CERT_PROPERTY_CREDENTIAL_ALIAS.c_str(), alias);
        napi_set_named_property (env, element, CM_CERT_PROPERTY_KEY_URI.c_str(), keyUri);

        napi_set_element(env, array, i, element);
    }
    return array;
}

napi_value GenerateCertInfo(napi_env env, const struct CertInfo *certInfo)
{
    if (certInfo == nullptr) {
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));

    struct CertInfoValue cInfVal = { nullptr };
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(certInfo->uri),
        NAPI_AUTO_LENGTH, &cInfVal.uri));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(certInfo->certAlias),
        NAPI_AUTO_LENGTH, &cInfVal.certAlias));
    NAPI_CALL(env, napi_get_boolean(env, certInfo->status, &cInfVal.status));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(certInfo->issuerName),
        NAPI_AUTO_LENGTH, &cInfVal.issuerName));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(certInfo->subjectName),
        NAPI_AUTO_LENGTH, &cInfVal.subjectName));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(certInfo->serial),
        NAPI_AUTO_LENGTH, &cInfVal.serial));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(certInfo->notBefore),
        NAPI_AUTO_LENGTH, &cInfVal.notBefore));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(certInfo->notAfter),
        NAPI_AUTO_LENGTH, &cInfVal.notAfter));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(certInfo->fingerprintSha256),
        NAPI_AUTO_LENGTH, &cInfVal.fingerprintSha256));

    napi_value certBuffer = GenerateAarrayBuffer(env, certInfo->certInfo.data, certInfo->certInfo.size);
    if (certBuffer != nullptr) {
        NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, certInfo->certInfo.size,
            certBuffer, 0, &cInfVal.certInfoBlob));
    }

    napi_value elem = nullptr;
    NAPI_CALL(env, napi_create_object(env, &elem));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_URI.c_str(), cInfVal.uri));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_CERTALIAS.c_str(), cInfVal.certAlias));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_STATUS.c_str(), cInfVal.status));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_ISSUERNAME.c_str(), cInfVal.issuerName));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_SUBJECTNAME.c_str(), cInfVal.subjectName));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_SERIAL.c_str(), cInfVal.serial));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_BEFORE.c_str(), cInfVal.notBefore));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_AFTER.c_str(), cInfVal.notAfter));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_FINGERSHA256.c_str(),
        cInfVal.fingerprintSha256));
    NAPI_CALL(env, napi_set_named_property(env, elem, CM_CERT_PROPERTY_CERT_DATA.c_str(), cInfVal.certInfoBlob));

    return elem;
}

int32_t TranformErrorCode(int32_t errorCode)
{
    if (errorCode == CMR_ERROR_INVALID_CERT_FORMAT || errorCode == CMR_ERROR_INSUFFICIENT_DATA) {
        return INVALID_CERT_FORMAT;
    }
    if (errorCode == CMR_ERROR_NOT_FOUND || errorCode == CMR_ERROR_NOT_EXIST) {
        return NOT_FOUND;
    }
    if (errorCode == CMR_ERROR_NOT_PERMITTED) {
        return NO_PERMISSION;
    }
    if (errorCode == CMR_ERROR_NOT_SYSTEMP_APP) {
        return NOT_SYSTEM_APP;
    }
    return INNER_FAILURE;
}

napi_value GenerateBusinessError(napi_env env, int32_t errorCode, const char *errorMsg)
{
    napi_value businessError = nullptr;
    NAPI_CALL(env, napi_create_object(env, &businessError));

    napi_value code = nullptr;
    int32_t outCode = TranformErrorCode(errorCode);
    NAPI_CALL(env, napi_create_int32(env, outCode, &code));
    NAPI_CALL(env, napi_set_named_property(env, businessError, BUSINESS_ERROR_PROPERTY_CODE.c_str(), code));
    napi_value message = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, errorMsg, NAPI_AUTO_LENGTH, &message));
    NAPI_CALL(env, napi_set_named_property(env, businessError, BUSINESS_ERROR_PROPERTY_MESSAGE.c_str(), message));
    return businessError;
}

void ThrowParamsError(napi_env env, int32_t errorCode, std::string errMsg)
{
    napi_value paramsError = nullptr;
    napi_value code = nullptr;
    napi_value message = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, errorCode, &code));
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &message));
    NAPI_CALL_RETURN_VOID(env, napi_create_error(env, nullptr, message, &paramsError));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, paramsError, BUSINESS_ERROR_PROPERTY_CODE.c_str(), code));
    NAPI_CALL_RETURN_VOID(env, napi_throw(env, paramsError));
}

napi_value GenerateAppCertInfo(napi_env env, const struct Credential *credential)
{
    if (credential == nullptr) {
        return nullptr;
    }
    napi_value result = nullptr;
    NAPI_CALL(env, napi_create_object(env, &result));
    napi_value type = nullptr;
    napi_value alias = nullptr;
    napi_value keyUri = nullptr;
    napi_value certNum = nullptr;
    napi_value keyNum = nullptr;
    napi_value credData = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(credential->type),
        NAPI_AUTO_LENGTH, &type));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(credential->alias),
        NAPI_AUTO_LENGTH, &alias));
    NAPI_CALL(env, napi_create_string_latin1(env, static_cast<const char *>(credential->keyUri),
        NAPI_AUTO_LENGTH, &keyUri));

    NAPI_CALL(env, napi_create_int32(env, credential->certNum, &certNum));
    NAPI_CALL(env, napi_create_int32(env, credential->keyNum, &keyNum));

    napi_value crendentialBuffer = GenerateAarrayBuffer(env, credential->credData.data, credential->credData.size);
    if (crendentialBuffer != nullptr) {
        NAPI_CALL(env, napi_create_typedarray(env, napi_uint8_array, credential->credData.size,
            crendentialBuffer, 0, &credData));
    }

    napi_value element = nullptr;
    NAPI_CALL(env, napi_create_object(env, &element));
    NAPI_CALL(env, napi_set_named_property(env, element, CM_CERT_PROPERTY_TYPE.c_str(), type));
    NAPI_CALL(env, napi_set_named_property(env, element, CM_CERT_PROPERTY_CREDENTIAL_ALIAS.c_str(), alias));
    NAPI_CALL(env, napi_set_named_property(env, element, CM_CERT_PROPERTY_KEY_URI.c_str(), keyUri));
    NAPI_CALL(env, napi_set_named_property(env, element, CM_CERT_PROPERTY_CERT_NUM.c_str(), certNum));
    NAPI_CALL(env, napi_set_named_property(env, element, CM_CERT_PROPERTY_KEY_NUM.c_str(), keyNum));

    NAPI_CALL(env, napi_set_named_property(env, element, CM_CERT_PROPERTY_CREDENTIAL_DATA.c_str(), credData));

    return element;
}

void GeneratePromise(napi_env env, napi_deferred deferred, int32_t resultCode,
    napi_value *result, int32_t arrLength)
{
    if (arrLength < RESULT_NUMBER) {
        return;
    }
    if (resultCode == CM_SUCCESS) {
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, deferred, result[1]));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, deferred, result[0]));
    }
}

void GenerateCallback(napi_env env, napi_ref callback, napi_value *result, int32_t arrLength)
{
    napi_value func = nullptr;
    napi_value returnVal = nullptr;
    if (arrLength < RESULT_NUMBER) {
        return;
    }
    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, callback, &func));
    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, func, RESULT_ARG_NUMBER, result, &returnVal));
}

void GenerateNapiPromise(napi_env env, napi_ref callback, napi_deferred *deferred, napi_value *promise)
{
    if (callback == nullptr) {
        NAPI_CALL_RETURN_VOID(env, napi_create_promise(env, deferred, promise));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, promise));
    }
}

void DeleteNapiContext(napi_env env, napi_async_work &asyncWork, napi_ref &callback)
{
    if (asyncWork != nullptr) {
        napi_delete_async_work(env, asyncWork);
        asyncWork = nullptr;
    }

    if (callback != nullptr) {
        napi_delete_reference(env, callback);
        callback = nullptr;
    }
}

void FreeCmContext(CmContext *&context)
{
    if (context == nullptr) {
        return;
    }

    context->userId = 0;
    context->uid = 0;

    CmFree(context);
    context = nullptr;
}

void FreeCertList(CertList *&certList)
{
    if (certList == nullptr || certList->certAbstract == nullptr) {
        return;
    }

    FreeCertAbstract(certList->certAbstract);
    certList->certAbstract = nullptr;

    CmFree(certList);
    certList = nullptr;
}

void FreeCredentialList(CredentialList *&credentialList)
{
    if (credentialList == nullptr || credentialList->credentialAbstract == nullptr) {
        return;
    }

    FreeCredentialAbstract(credentialList->credentialAbstract);
    credentialList->credentialAbstract = nullptr;

    CmFree(credentialList);
    credentialList = nullptr;
}

void FreeCertInfo(CertInfo *&certInfo)
{
    if (certInfo == nullptr) {
        return;
    }

    certInfo->status = false;

    if (certInfo->certInfo.data != nullptr) {
        CmFree(certInfo->certInfo.data);
    }

    CmFree(certInfo);
    certInfo = nullptr;
}

void FreeCredential(Credential *&credential)
{
    if (credential == nullptr) {
        return;
    }

    if (credential->credData.data != nullptr) {
        CmFree(credential->credData.data);
    }

    CmFree(credential);
    credential = nullptr;
}
}  // namespace CertManagerNapi
