/*
* Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef HKS_API_H
#define HKS_API_H

#include "hks_type.h"

#ifdef __cplusplus
extern "C" {
#endif
int32_t HksExportProviderCertificates(const struct HksBlob *providerName,
    const struct HksParamSet *paramSetIn, struct HksExtCertInfoSet *certSet);
int32_t HksExportCertificate(const struct HksBlob *resourceId,
    const struct HksParamSet *paramSetIn, struct HksExtCertInfoSet *certSet);

// 句柄管理
int32_t HksOpenRemoteHandle(const struct HksBlob *resourceId,
    const struct HksParamSet *paramSetIn);
int32_t HksGetRemoteHandle(const struct HksBlob *resourceId,
    const struct HksParamSet *paramSetIn);
int32_t HksCloseRemoteHandle(const struct HksBlob *resourceId,
    const struct HksParamSet *paramSetIn);

// PIN码认证
int32_t HksAuthUkeyPin(const struct HksBlob *resourceId, const struct HksParamSet *paramSetIn,
    uint32_t *retryCount);
int32_t HksGetUkeyPinAuthState(const struct HksBlob *name, const struct HksParamSet *paramSetIn,
    int32_t *status);
int32_t HksClearUkeyPinAuthState(const struct HksBlob *resourceId);

// 签名验签
int32_t HksUkeySign(const struct HksBlob *resourceId, const struct HksParamSet *paramSetIn,
    const struct HksBlob *srcData, struct HksBlob *signatureOut);
int32_t HksUkeyVerify(const struct HksBlob *resourceId, const struct HksParamSet *paramSetIn,
    const struct HksBlob *srcData, struct HksBlob *signatureOut);

int32_t HksGetRemoteProperty(const struct HksBlob *resourceId, const struct HksBlob *propertyId,
    const struct HksParamSet *paramSetIn, struct HksParamSet **propertySetOut);

int32_t HksGetSdkVersion(struct HksBlob *sdkVersion);

int32_t HksInitialize(void);

int32_t HksRefreshKeyInfo(void);

int32_t HksGenerateKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, struct HksParamSet *paramSetOut);

int32_t HksImportKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *key);

int32_t HksImportWrappedKey(const struct HksBlob *keyAlias, const struct HksBlob *wrappingKeyAlias,
    const struct HksParamSet *paramSet, const struct HksBlob *wrappedKeyData);

int32_t HksExportPublicKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *key);

int32_t HksDeleteKey(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet);

int32_t HksGetKeyParamSet(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSetIn, struct HksParamSet *paramSetOut);

int32_t HksKeyExist(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet);

int32_t HksGenerateRandom(const struct HksParamSet *paramSet, struct HksBlob *random);

int32_t HksSign(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *signature);

int32_t HksVerify(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, const struct HksBlob *signature);

int32_t HksEncrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *plainText, struct HksBlob *cipherText);

int32_t HksDecrypt(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *cipherText, struct HksBlob *plainText);

int32_t HksAgreeKey(const struct HksParamSet *paramSet, const struct HksBlob *privateKey,
    const struct HksBlob *peerPublicKey, struct HksBlob *agreedKey);

int32_t HksDeriveKey(const struct HksParamSet *paramSet, const struct HksBlob *mainKey,
    struct HksBlob *derivedKey);

int32_t HksMac(const struct HksBlob *key, const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *mac);

int32_t HksHash(const struct HksParamSet *paramSet,
    const struct HksBlob *srcData, struct HksBlob *hash);

int32_t HksGetKeyInfoList(const struct HksParamSet *paramSet,
    struct HksKeyInfo *keyInfoList, uint32_t *listCount);

int32_t HksAttestKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksCertChain *certChain);

int32_t HksAnonAttestKey(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksCertChain *certChain);

int32_t HksGetCertificateChain(const struct HksBlob *keyAlias,
    const struct HksParamSet *paramSet, struct HksCertChain *certChain);

int32_t HksWrapKey(const struct HksBlob *keyAlias, const struct HksBlob *targetKeyAlias,
    const struct HksParamSet *paramSet, struct HksBlob *wrappedData);

int32_t HksUnwrapKey(const struct HksBlob *keyAlias, const struct HksBlob *targetKeyAlias,
    const struct HksBlob *wrappedData, const struct HksParamSet *paramSet);

int32_t HksBnExpMod(struct HksBlob *x, const struct HksBlob *a,
    const struct HksBlob *e, const struct HksBlob *n);

int32_t HcmIsDeviceKeyExist(const struct HksParamSet *paramSet);

int32_t HksValidateCertChain(const struct HksCertChain *certChain, struct HksParamSet *paramSetOut);

int32_t HksInit(const struct HksBlob *keyAlias, const struct HksParamSet *paramSet,
    struct HksBlob *handle, struct HksBlob *token);

int32_t HksUpdate(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData);

int32_t HksFinish(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData);

int32_t HksAbort(const struct HksBlob *handle, const struct HksParamSet *paramSet);

int32_t HksListAliases(const struct HksParamSet *paramSet, struct HksKeyAliasSet **outData);

int32_t HksRenameKeyAlias(const struct HksBlob *oldKeyAlias, const struct HksParamSet *paramSet,
    const struct HksBlob *newKeyAlias);

int32_t HksChangeStorageLevel(const struct HksBlob *keyAlias, const struct HksParamSet *srcParamSet,
    const struct HksParamSet *destParamSet);

#ifdef __cplusplus
}
#endif

#endif /* HKS_API_H */
