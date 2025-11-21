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

#ifndef HKS_TYPE_H
#define HKS_TYPE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HKS_API_PUBLIC
    #if defined(WIN32) || defined(_WIN32) || defined(__CYGWIN__) || defined(__ICCARM__)
        #define
    #else
        #define ATTRIBUTE_VISIBILITY_DEFAULT ((visibility("default")))
    #endif
#else
    #define ATTRIBUTE_VISIBILITY_DEFAULT ((visibility("default")))
#endif

#define HKS_SDK_VERSION "2.0.0.4"


struct HksBlob {
    uint32_t size;
    uint8_t *data;
};

struct HksExtCertInfo {
    int32_t purpose;
    struct HksBlob index;
    struct HksBlob cert;
};

struct HksExtCertInfoSet {
    uint32_t count;
    struct HksExtCertInfo *certs;
};

/**
 * @brief hks param
 */
struct HksParam {
    uint32_t tag;
    union {
        bool boolParam;
        int32_t int32Param;
        uint32_t uint32Param;
        uint64_t uint64Param;
        struct HksBlob blob;
    };
};

/**
 * @brief hks param set
 */
struct HksParamSet {
    uint32_t paramSetSize;
    uint32_t paramsCnt;
    struct HksParam params[];
};

struct HksExtParam {
    uint32_t tag;
    union {
        bool boolParam;
        int32_t int32Param;
        uint32_t uint32Param;
        uint64_t uint64Param;
        struct HksBlob blob;
    };
};

struct HksExtParamSet {
    uint32_t paramSetSize;
    uint32_t paramsCnt;
    struct HksExtParam params[];
};

/**
 * @brief hks certificate chain
 */
struct HksCertChain {
    struct HksBlob *certs;
    uint32_t certsCount;
};

/**
 * @brief hks key info
 */
struct HksKeyInfo {
    struct HksBlob alias;
    struct HksParamSet *paramSet;
};

struct SecInfoWrap {
    uint64_t secureUid;
    uint32_t enrolledInfoLen;
    struct EnrolledInfoWrap *enrolledInfo;
};

/**
 * @brief hks alias set
 */
struct HksKeyAliasSet {
    uint32_t aliasesCnt;
    struct HksBlob *aliases;
};


#define HKS_DERIVE_DEFAULT_SALT_LEN 16
#define HKS_HMAC_DIGEST_SHA512_LEN 64
#define HKS_DEFAULT_RANDOM_LEN 16
#define HKS_MAX_KEY_AUTH_ID_LEN 64
#define HKS_KEY_MATERIAL_NUM 3
#define HKS_MAX_KEY_LEN (HKS_KEY_BYTES(HKS_RSA_KEY_SIZE_4096) * HKS_KEY_MATERIAL_NUM)
#define HKS_MAX_KEY_MATERIAL_LEN (sizeof(struct HksPubKeyInfo) + HKS_MAX_KEY_LEN + HKS_AE_TAG_LEN)
#define COMMON_EVENT_HKS_BINDER_DIED "ohos.hks.action.BINDER_DIED"

/**
 * @brief hks store header info
 */
struct HksStoreHeaderInfo {
    uint16_t version;
    uint16_t keyCount;
    uint32_t totalLen; /* key buffer total len */
    uint32_t sealingAlg;
    uint8_t salt[HKS_DERIVE_DEFAULT_SALT_LEN];
    uint8_t hmac[HKS_HMAC_DIGEST_SHA512_LEN];
};

/**
 * @brief hks store key info
 */
struct HksStoreKeyInfo {
    uint16_t keyInfoLen; /* current keyinfo len */
    uint16_t keySize;    /* keySize of key from crypto hal after encrypted */
    uint8_t random[HKS_DEFAULT_RANDOM_LEN];
    uint8_t flag;        /* import or generate key */
    uint8_t keyAlg;
    uint8_t keyMode;
    uint8_t digest;
    uint8_t padding;
    uint8_t rsv;
    uint16_t keyLen;     /* keyLen from paramset, e.g. aes-256 */
    uint32_t purpose;
    uint32_t role;
    uint16_t domain;
    uint8_t aliasSize;
    uint8_t authIdSize;
};

struct ErrorInfoHead {
    int32_t version;
    int32_t errorType;
    int32_t innerErrCode;
    int32_t extErrCode;
};

/**
 * @brief hks 25519 key pair
 */
struct Hks25519KeyPair {
    uint32_t publicBufferSize;
    uint32_t privateBufferSize;
};

/**
 * @brief hks import keystore args
 */
struct HksImportKeyStoreArgs {
    const struct HksBlob keyAlias;
    uint32_t uidInt;
};

#ifdef __cplusplus
}
#endif

#endif