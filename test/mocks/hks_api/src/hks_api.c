/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")
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

#include "hks_api.h"

int32_t HksExportProviderCertificates(const struct HksBlob *providerName,
                                      const struct HksParamSet *paramSetIn, struct HksExtCertInfoSet *certSet)
{
    (void)providerName;
    (void)paramSetIn;
    (void)certSet;
    return 0;
}

int32_t HksExportCertificate(const struct HksBlob *resourceId,
    const struct HksParamSet *paramSetIn, struct HksExtCertInfoSet *certSet)
{
    (void)resourceId;
    (void)paramSetIn;
    (void)certSet;
    return 0;
}

// 句柄管理
int32_t HksOpenRemoteHandle(const struct HksBlob *resourceId,
    const struct HksParamSet *paramSetIn)
{
    (void)resourceId;
    (void)paramSetIn;
    return 0;
}

int32_t HksGetRemoteHandle(const struct HksBlob *resourceId,
    const struct HksParamSet *paramSetIn)
{
    (void)resourceId;
    (void)paramSetIn;
    return 0;
}

int32_t HksCloseRemoteHandle(const struct HksBlob *resourceId,
    const struct HksParamSet *paramSetIn)
{
    (void)resourceId;
    (void)paramSetIn;
    return 0;
}

// PIN码认证
int32_t HksAuthUkeyPin(const struct HksBlob *resourceId, const struct HksParamSet *paramSetIn,
    uint32_t *retryCount)
{
    (void)resourceId;
    (void)paramSetIn;
    (void)retryCount;
    return 0;
}

int32_t HksGetUkeyPinAuthState(const struct HksBlob *name, const struct HksParamSet *paramSetIn,
    int32_t *status)
{
    (void)name;
    (void)paramSetIn;
    (void)status;
    return 0;
}

int32_t HksClearUkeyPinAuthState(const struct HksBlob *resourceId)
{
    (void)resourceId;
    return 0;
}

// 签名验签
int32_t HksUkeySign(const struct HksBlob *resourceId, const struct HksParamSet *paramSetIn,
    const struct HksBlob *srcData, struct HksBlob *signatureOut)
{
    (void)resourceId;
    (void)paramSetIn;
    (void)srcData;
    (void)signatureOut;
    return 0;
}

int32_t HksUkeyVerify(const struct HksBlob *resourceId, const struct HksParamSet *paramSetIn,
    const struct HksBlob *srcData, struct HksBlob *signatureOut)
{
    (void)resourceId;
    (void)paramSetIn;
    (void)srcData;
    (void)signatureOut;
    return 0;
}

int32_t HksGetRemoteProperty(const struct HksBlob *resourceId, const struct HksBlob *propertyId,
    const struct HksParamSet *paramSetIn, struct HksParamSet **propertySetOut)
{
    (void)resourceId;
    (void)propertyId;
    (void)paramSetIn;
    (void)propertySetOut;
    return 0;
}

int32_t HksGetSdkVersion(struct HksBlob *sdkVersion)
{
    (void)sdkVersion;
    return 0;
}

int32_t HksInitialize(void)
{
    return 0;
}

int32_t HksRefreshKeyInfo(void)
{
    return 0;
}

int32_t HksGenerateKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, struct HksParamSet *paramSetOut)
{
    (void)keyAlias;
    (void)paramSetIn;
    (void)paramSetOut;
    return 0;
}

int32_t HksImportKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *key)
{
    (void)keyAlias;
    (void)paramSet;
    (void)key;
    return 0;
}

int32_t HksImportWrappedKey(const struct HksBlob *keyAlias, const struct HksBlob *wrappingKeyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData)
{
    (void)keyAlias;
    (void)wrappingKeyAlias;
    (void)paramSet;
    (void)wrappedKeyData;
    return 0;
}

int32_t HksExportPublicKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *key)
{
    (void)keyAlias;
    (void)paramSet;
    (void)key;
    return 0;
}

int32_t HksDeleteKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet)
{
    (void)keyAlias;
    (void)paramSet;
    return 0;
}

int32_t HksKeyExist(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet)
{
    (void)keyAlias;
    (void)paramSet;
    return 0;
}

int32_t HksGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *random)
{
    (void)paramSet;
    (void)random;
    return 0;
}

int32_t HksSign(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature)
{
    (void)key;
    (void)paramSet;
    (void)srcData;
    (void)signature;
    return 0;
}

int32_t HksVerify(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, const struct HksBlob *signature)
{
    (void)key;
    (void)paramSet;
    (void)srcData;
    (void)signature;
    return 0;
}

int32_t HksEncrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText)
{
    (void)key;
    (void)paramSet;
    (void)plainText;
    (void)cipherText;
    return 0;
}

int32_t HksDecrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText)
{
    (void)key;
    (void)paramSet;
    (void)cipherText;
    (void)plainText;
    return 0;
}

int32_t HksAgreeKey(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey)
{
    (void)paramSet;
    (void)privateKey;
    (void)peerPublicKey;
    (void)agreedKey;
    return 0;
}

int32_t HksDeriveKey(const struct HksParamSet *paramSet, const struct HksBlob *mainKey,
    struct HksBlob *derivedKey)
{
    (void)paramSet;
    (void)mainKey;
    (void)derivedKey;
    return 0;
}

int32_t HksMac(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *mac)
{
    (void)key;
    (void)paramSet;
    (void)srcData;
    (void)mac;
    return 0;
}

int32_t HksHash(const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *hash)
{
    (void)paramSet;
    (void)srcData;
    (void)hash;
    return 0;
}

int32_t HksGetKeyInfoList(const struct HksParamSet *paramSet,
    struct HksKeyInfo *keyInfoList, uint32_t *listCount)
{
    (void)paramSet;
    (void)keyInfoList;
    (void)listCount;
    return 0;
}

int32_t HksAttestKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksCertChain *certChain)
{
    (void)keyAlias;
    (void)paramSet;
    (void)certChain;
    return 0;
}

int32_t HksAnonAttestKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksCertChain *certChain)
{
    (void)keyAlias;
    (void)paramSet;
    (void)certChain;
    return 0;
}

int32_t HksGetCertificateChain(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksCertChain *certChain)
{
    (void)keyAlias;
    (void)paramSet;
    (void)certChain;
    return 0;
}

int32_t HksWrapKey(const struct HksBlob *keyAlias, const struct HksBlob *targetKeyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *wrappedData)
{
    (void)keyAlias;
    (void)targetKeyAlias;
    (void)paramSet;
    (void)wrappedData;
    return 0;
}

int32_t HksUnwrapKey(const struct HksBlob *keyAlias, const struct HksBlob *targetKeyAlias,
    const struct HksBlob *wrappedData, const struct HksParamSet *paramSet)
{
    (void)keyAlias;
    (void)targetKeyAlias;
    (void)wrappedData;
    (void)paramSet;
    return 0;
}

int32_t HksBnExpMod(struct HksBlob *x, const struct HksBlob *a,
    const struct HksBlob *e, const struct HksBlob *n)
{
    (void)x;
    (void)a;
    (void)e;
    (void)n;
    return 0;
}

int32_t HcmIsDeviceKeyExist(const struct HksParamSet *paramSet)
{
    (void)paramSet;
    return 0;
}

int32_t HksValidateCertChain(const struct HksCertChain *certChain, struct HksParamSet *paramSetOut)
{
    (void)certChain;
    (void)paramSetOut;
    return 0;
}

int32_t HksInit(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksBlob *handle, struct HksBlob *token)
{
    (void)keyAlias;
    (void)paramSet;
    (void)handle;
    (void)token;
    return 0;
}

int32_t HksUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    (void)handle;
    (void)paramSet;
    (void)inData;
    (void)outData;
    return 0;
}

int32_t HksFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    (void)handle;
    (void)paramSet;
    (void)inData;
    (void)outData;
    return 0;
}

int32_t HksAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet)
{
    (void)handle;
    (void)paramSet;
    return 0;
}

int32_t HksListAliases(const struct HksParamSet *paramSet, struct HksKeyAliasSet **outData)
{
    (void)paramSet;
    (void)outData;
    return 0;
}

int32_t HksRenameKeyAlias(const struct HksBlob *oldKeyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *newKeyAlias)
{
    (void)oldKeyAlias;
    (void)paramSet;
    (void)newKeyAlias;
    return 0;
}

int32_t HksChangeStorageLevel(const struct HksBlob *keyAlias, const struct HksParamSet *srcParamSet,
    const struct HksParamSet *destParamSet)
{
    (void)keyAlias;
    (void)srcParamSet;
    (void)destParamSet;
    return 0;
}