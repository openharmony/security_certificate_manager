/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "cert_manager_app_cert_process.h"
#include "cert_manager_auth_list_mgr.h"

#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "securec.h"

#include "cert_manager.h"
#include "cert_manager_check.h"
#include "cert_manager_file_operator.h"
#include "cert_manager_key_operation.h"
#include "cert_manager_mem.h"
#include "cert_manager_storage.h"
#include "cert_manager_crypto_operation.h"
#include "cert_manager_service.h"
#include "cert_manager_uri.h"
#include "cert_manager_query.h"
#include "cert_manager_permission_check.h"
#include "cm_log.h"
#include "cm_pfx.h"
#include "cm_type.h"
#include "cm_x509.h"

#include "hks_type.h"

#define ECC_KEYPAIR_CNT 3
#define CM_RSA_KEYPAIR_CNT 3
#define CURVE25519_KEY_LEN_BYTES 32
#define CM_OPENSSL_SUCCESS 1

static int32_t TransEccKeyToKeyBlob(const EC_KEY *eccKey, const struct HksKeyMaterialEcc *keyMaterial,
    struct CmBlob *rawMaterial)
{
    /* rawMaterial size ensure enougth */
    int32_t ret = CMR_ERROR_OPENSSL_FAIL;
    BIGNUM *pubX = BN_new();
    BIGNUM *pubY = BN_new();
    do {
        if ((pubX == NULL) || (pubY == NULL)) {
            CM_LOG_E("new Bn x or y failed");
            break;
        }

        const EC_GROUP *ecGroup = EC_KEY_get0_group(eccKey);
        int retCode = EC_POINT_get_affine_coordinates_GFp(ecGroup, EC_KEY_get0_public_key(eccKey), pubX, pubY, NULL);
        if (retCode <= 0) {
            CM_LOG_E("EC_POINT_get_affine_coordinates_GFp failed");
            break;
        }

        uint32_t offset = sizeof(struct HksKeyMaterialEcc);
        retCode = BN_bn2binpad(pubX, rawMaterial->data + offset, keyMaterial->xSize);
        if (retCode <= 0) {
            CM_LOG_E("BN_bn2binpad pubX failed");
            break;
        }
        offset += keyMaterial->xSize;

        retCode = BN_bn2binpad(pubY, rawMaterial->data + offset, keyMaterial->ySize);
        if (retCode <= 0) {
            CM_LOG_E("BN_bn2binpad pubY failed");
            break;
        }
        offset += keyMaterial->ySize;

        const BIGNUM *priv = EC_KEY_get0_private_key(eccKey);
        retCode = BN_bn2binpad(priv, rawMaterial->data + offset, keyMaterial->zSize);
        if (retCode <= 0) {
            CM_LOG_E("BN_bn2binpad priv failed");
            break;
        }
        ret = CM_SUCCESS;
    } while (0);
    if (pubX != NULL) {
        BN_free(pubX);
    }
    if (pubY != NULL) {
        BN_free(pubY);
    }

    return ret;
}

static int32_t SaveKeyMaterialEcc(const EC_KEY *eccKey, const uint32_t keySize,
    const enum HksKeyAlg algType, struct CmBlob *keyOut)
{
    struct CmBlob rawMaterial = { 0, NULL };
    /* public exponent x and y, and private exponent, so need size is: keySize / 8 * 3 */
    rawMaterial.size = sizeof(struct HksKeyMaterialEcc) + CM_KEY_BYTES(keySize) * ECC_KEYPAIR_CNT;
    rawMaterial.data = (uint8_t *)CMMalloc(rawMaterial.size);
    if (rawMaterial.data == NULL) {
        CM_LOG_E("malloc buffer failed!");
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(rawMaterial.data, rawMaterial.size, 0, rawMaterial.size);

    /*
     * ECC key data internal struct:
     * struct KeyMaterialEcc + pubX_data + pubY_data + pri_data
     */
    struct HksKeyMaterialEcc *keyMaterial = (struct HksKeyMaterialEcc *)rawMaterial.data;
    keyMaterial->keyAlg = algType;
    keyMaterial->keySize = keySize;
    keyMaterial->xSize = CM_KEY_BYTES(keySize);
    keyMaterial->ySize = CM_KEY_BYTES(keySize);
    keyMaterial->zSize = CM_KEY_BYTES(keySize);

    int32_t ret = TransEccKeyToKeyBlob(eccKey, keyMaterial, &rawMaterial);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("transfer ecc key to key blob failed");
        (void)memset_s(rawMaterial.data, rawMaterial.size, 0, rawMaterial.size);
        CM_FREE_BLOB(rawMaterial);
        return ret;
    }

    keyOut->data = rawMaterial.data;
    keyOut->size = rawMaterial.size;
    return ret;
}

static int32_t SaveKeyMaterialRsa(const RSA *rsa, const uint32_t keySize, struct CmBlob *keyOut)
{
    const uint32_t keyByteLen = keySize / CM_BITS_PER_BYTE;
    const uint32_t rawMaterialLen = sizeof(struct HksKeyMaterialRsa) + keyByteLen * CM_RSA_KEYPAIR_CNT;
    uint8_t *rawMaterial = (uint8_t *)CMMalloc(rawMaterialLen);
    if (rawMaterial == NULL) {
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(rawMaterial, rawMaterialLen, 0, rawMaterialLen);

    struct HksKeyMaterialRsa *keyMaterial = (struct HksKeyMaterialRsa *)rawMaterial;
    keyMaterial->keyAlg = HKS_ALG_RSA;
    keyMaterial->keySize = keySize;

    uint8_t tmpBuff[HKS_RSA_KEY_SIZE_4096] = {0};
    int32_t ret = CMR_ERROR_MEM_OPERATION_COPY;
    do {
        uint32_t offset = sizeof(*keyMaterial);
        keyMaterial->nSize = (uint32_t)BN_bn2bin(RSA_get0_n(rsa), tmpBuff);
        if (memcpy_s(rawMaterial + offset, keyByteLen, tmpBuff, keyMaterial->nSize) != EOK) {
            CM_LOG_E("copy rsa n failed");
            break;
        }

        offset += keyMaterial->nSize;
        keyMaterial->eSize = (uint32_t)BN_bn2bin(RSA_get0_e(rsa), tmpBuff);
        if (memcpy_s(rawMaterial + offset, keyByteLen, tmpBuff, keyMaterial->eSize) != EOK) {
            CM_LOG_E("copy rsa e failed");
            break;
        }

        offset += keyMaterial->eSize;
        keyMaterial->dSize = (uint32_t)BN_bn2bin(RSA_get0_d(rsa), tmpBuff);
        if (memcpy_s(rawMaterial + offset, keyByteLen, tmpBuff, keyMaterial->dSize) != EOK) {
            CM_LOG_E("copy rsa d failed");
            break;
        }

        keyOut->data = rawMaterial;
        keyOut->size = sizeof(struct HksKeyMaterialRsa) + keyMaterial->nSize + keyMaterial->eSize + keyMaterial->dSize;
        ret = CM_SUCCESS;
    } while (0);

    (void)memset_s(tmpBuff, sizeof(tmpBuff), 0, sizeof(tmpBuff));
    if (ret != CM_SUCCESS) {
        (void)memset_s(rawMaterial, rawMaterialLen, 0, rawMaterialLen);
        CMFree(rawMaterial);
        rawMaterial = NULL;
    }

    return ret;
}

static int32_t SaveKeyMaterialCurve25519(uint32_t algType, const EVP_PKEY *pKey, struct CmBlob *keyOut)
{
    uint32_t totalSize = sizeof(struct HksKeyMaterial25519) + (CURVE25519_KEY_LEN_BYTES << 1);
    uint8_t *buffer = (uint8_t *)CMMalloc(totalSize);
    if (buffer == NULL) {
        CM_LOG_E("malloc size %u failed", totalSize);
        return CMR_ERROR_MALLOC_FAIL;
    }
    (void)memset_s(buffer, totalSize, 0, totalSize);

    uint32_t offset = sizeof(struct HksKeyMaterial25519);

    size_t tmpPubKeyLen = CURVE25519_KEY_LEN_BYTES;
    size_t tmpPriKeyLen = CURVE25519_KEY_LEN_BYTES;
    if (EVP_PKEY_get_raw_public_key(pKey, buffer + offset, &tmpPubKeyLen) != CM_OPENSSL_SUCCESS) {
        CM_LOG_E("EVP_PKEY_get_raw_public_key failed");
        (void)memset_s(buffer, totalSize, 0, totalSize);
        CMFree(buffer);
        return CMR_ERROR_OPENSSL_FAIL;
    }
    uint32_t pubKeyLen = (uint32_t)tmpPubKeyLen;

    offset += pubKeyLen;
    if (EVP_PKEY_get_raw_private_key(pKey, buffer + offset, &tmpPriKeyLen) != CM_OPENSSL_SUCCESS) {
        CM_LOG_E("EVP_PKEY_get_raw_private_key");
        (void)memset_s(buffer, totalSize, 0, totalSize);
        CMFree(buffer);
        return CMR_ERROR_OPENSSL_FAIL;
    }
    uint32_t priKeyLen = (uint32_t)tmpPriKeyLen;

    struct HksKeyMaterial25519 *keyMaterial = (struct HksKeyMaterial25519 *)buffer;
    keyMaterial->keyAlg = algType;
    keyMaterial->keySize = HKS_CURVE25519_KEY_SIZE_256;
    keyMaterial->pubKeySize = pubKeyLen;
    keyMaterial->priKeySize = priKeyLen;

    keyOut->data = buffer;
    keyOut->size = totalSize;
    return CM_SUCCESS;
}

static int32_t ImportRsaKey(const EVP_PKEY *priKey, const struct CmBlob *keyUri, enum CmAuthStorageLevel level)
{
    struct CmBlob keyPair = { 0, NULL };
    int32_t ret;
    do {
        const RSA *rsa = EVP_PKEY_get0_RSA((EVP_PKEY *)priKey);
        if (rsa == NULL) {
            CM_LOG_E("EVP_PKEY_get1_RSA error %s", ERR_reason_error_string(ERR_get_error()));
            ret = CMR_ERROR_OPENSSL_FAIL;
            break;
        }
        uint32_t keySize = ((uint32_t)RSA_size(rsa)) * CM_BITS_PER_BYTE;

        ret = SaveKeyMaterialRsa(rsa, keySize, &keyPair);
        if (ret != CMR_OK) {
            CM_LOG_E("save rsa key material failed ret=0x%x", ret);
            break;
        }

        struct CmKeyProperties props = {
            .algType = HKS_ALG_RSA,
            .keySize = keySize,
            .purpose = CM_KEY_PURPOSE_SIGN | CM_KEY_PURPOSE_VERIFY,
            .level = level,
        };

        ret = CmKeyOpImportKey(keyUri, &props, &keyPair);
        if (ret != CMR_OK) {
            CM_LOG_E("rsa keypair import faild");
            break;
        }
    } while (0);
    if (keyPair.data != NULL) {
        (void)memset_s(keyPair.data, keyPair.size, 0, keyPair.size);
        CM_FREE_BLOB(keyPair);
    }
    return ret;
}

static int32_t ImportEccKey(const EVP_PKEY *priKey, const struct CmBlob *keyUri, enum CmAuthStorageLevel level)
{
    struct CmBlob keyPair = { 0, NULL };
    int32_t ret;
    do {
        const EC_KEY *eccKey = EVP_PKEY_get0_EC_KEY((EVP_PKEY *)priKey);
        if (eccKey == NULL) {
            CM_LOG_E("EVP_PKEY_get0_EC_KEY faild");
            ret = CMR_ERROR_OPENSSL_FAIL;
            break;
        }

        enum HksKeyAlg algType = HKS_ALG_ECC;
        uint32_t keyLen = (uint32_t)EC_GROUP_order_bits(EC_KEY_get0_group(eccKey));
        int curveName = EC_GROUP_get_curve_name(EC_KEY_get0_group(eccKey));
        if (curveName == NID_sm2) {
            algType = HKS_ALG_SM2;
        }
        ret = SaveKeyMaterialEcc(eccKey, keyLen, algType, &keyPair);
        if (ret != CMR_OK) {
            CM_LOG_E("save ec key material failed ret=0x%x, curveName = %d", ret, curveName);
            break;
        }

        const struct CmKeyProperties props = {
            .algType = (uint32_t)algType,
            .keySize = keyLen,
            .purpose = CM_KEY_PURPOSE_SIGN | CM_KEY_PURPOSE_VERIFY,
            .level = level,
        };

        ret = CmKeyOpImportKey(keyUri, &props, &keyPair);
        if (ret != CMR_OK) {
            CM_LOG_E("ecc Key type import faild");
            break;
        }
    } while (0);
    if (keyPair.data != NULL) {
        (void)memset_s(keyPair.data, keyPair.size, 0, keyPair.size);
        CMFree(keyPair.data);
    }

    return ret;
}

static int32_t ImportEd25519Key(const EVP_PKEY *priKey, const struct CmBlob *keyUri, enum CmAuthStorageLevel level)
{
    struct CmBlob keyPair = { 0, NULL };
    int32_t ret = SaveKeyMaterialCurve25519(HKS_ALG_ED25519, priKey, &keyPair);
    if (ret != CMR_OK) {
        CM_LOG_E("save curve25519 key material failed");
        return ret;
    }

    struct CmKeyProperties props = {
        .algType = HKS_ALG_ED25519,
        .keySize = HKS_CURVE25519_KEY_SIZE_256,
        .purpose = CM_KEY_PURPOSE_SIGN | CM_KEY_PURPOSE_VERIFY,
        .level = level,
    };
    ret = CmKeyOpImportKey(keyUri, &props, &keyPair);
    if (ret != CMR_OK) {
        CM_LOG_E("Ed25519 key type import faild");
    }
    if (keyPair.data != NULL) {
        (void)memset_s(keyPair.data, keyPair.size, 0, keyPair.size);
        CM_FREE_BLOB(keyPair);
    }

    return ret;
}

static int32_t ImportKeyPair(const EVP_PKEY *priKey, const struct CmBlob *keyUri,
    enum CmAuthStorageLevel level)
{
    switch (EVP_PKEY_base_id(priKey)) {
        case EVP_PKEY_RSA:
            return ImportRsaKey(priKey, keyUri, level);
        case EVP_PKEY_EC:
            return ImportEccKey(priKey, keyUri, level);
        case EVP_PKEY_ED25519:
            return ImportEd25519Key(priKey, keyUri, level);
        case NID_undef:
            CM_LOG_E("key's baseid is not specified");
            return CMR_ERROR_INVALID_CERT_FORMAT;
        default:
            CM_LOG_E("Import key type not suported");
            return CMR_ERROR_INVALID_ARGUMENT_APP_CERT;
    }
}

static int32_t StoreAppCert(const struct CmContext *context, struct AppCert *appCert,
    const uint32_t store, const struct CmBlob *keyUri)
{
    char pathBuf[CERT_MAX_PATH_LEN] = {0};
    int32_t ret = ConstructUidPath(context, store, pathBuf, sizeof(pathBuf));
    if (ret != CMR_OK) {
        CM_LOG_E("Failed obtain path for store:%u", store);
        return ret;
    }

    appCert->keyCount = 1;
    struct CmBlob certBlob = { 0, NULL };
    certBlob.size = sizeof(struct AppCert) - MAX_LEN_CERTIFICATE_CHAIN + appCert->certSize;
    certBlob.data = (uint8_t *)appCert;

    ret = CmFileWrite(pathBuf, (char *)keyUri->data, 0, certBlob.data, certBlob.size);
    if (ret != CMR_OK) {
        CM_LOG_E("Failed to write certificate");
        return CMR_ERROR_WRITE_FILE_FAIL;
    }
    return ret;
}

static int32_t ConstructKeyUri(
    const struct CmContext *context, const struct CmBlob *certAlias, uint32_t store, struct CmBlob *keyUri)
{
    uint32_t type = CM_URI_TYPE_APP_KEY; /* type is 'ak' */
    if (store == CM_SYS_CREDENTIAL_STORE) {
        type = CM_URI_TYPE_SYS_KEY; /* type is 'sk' */
    }
    struct CmBlob commonUri = { 0, NULL };
    int32_t ret;
    do {
        ret = CmConstructCommonUri(context, type, certAlias, &commonUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("construct key uri get common uri failed");
            break;
        }

        if (keyUri->size < commonUri.size) {
            CM_LOG_E("out key uri size[%u] too small", keyUri->size);
            ret = CMR_ERROR_BUFFER_TOO_SMALL;
            break;
        }

        if (memcpy_s(keyUri->data, keyUri->size, commonUri.data, commonUri.size) != EOK) {
            CM_LOG_E("copy key uri failed");
            ret = CMR_ERROR_MEM_OPERATION_COPY;
            break;
        }

        keyUri->size = commonUri.size;
    } while (0);

    CM_FREE_PTR(commonUri.data);
    return ret;
}

static int32_t ParseAppCert(const struct CmAppCertParam *certParam, EVP_PKEY **priKey,
    struct CertName *certName, struct AppCert *appCert, X509 **cert)
{
    int32_t ret = CM_SUCCESS;
    if (certParam->credFormat == FILE_P12) {
        ret = CmParsePkcs12Cert(certParam->appCert, (char *)certParam->appCertPwd->data, priKey, appCert, cert);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmParsePkcs12Cert fail");
            return ret;
        }
    } else if (certParam->credFormat == CHAIN_KEY) {
        ret = CmParseCertChainAndPrivKey(certParam->appCert, certParam->appCertPrivKey, priKey, appCert, cert);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("CmParseCertChainAndPrivKey failed");
            return ret;
        }
    }
    return ret;
}

static int32_t GetCredCertName(struct CmContext *context, const struct CmAppCertParam *certParam,
    EVP_PKEY **priKey, struct CertName *certName, struct AppCert *appCert)
{
    int32_t ret = CM_SUCCESS;
    X509 *cert = NULL;
    int32_t certManagerUid = 0;

    do {
        // only install user cred and target userid/caller user id is not 0
        if (certParam->store == CM_CREDENTIAL_STORE && context->userId != 0) {
            if (!CmGetCertManagerAppUid(&certManagerUid, (int32_t)(context->userId))) {
                ret = CM_FAILURE;
                CM_LOG_E("get cert manager uid failed");
                break;
            }
            context->uid = (uint32_t)certManagerUid;
        }

        ret = ParseAppCert(certParam, priKey, certName, appCert, &cert);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to parse app cert");
            break;
        }

        ret = GetSubjectNameAndAlias(cert, certParam->certAlias, certName->subjectName, certName->displayName);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get alias from subject name");
            break;
        }

        ret = GetObjNameFromCertData(certParam->appCert, certParam->certAlias,
            certName->objectName, certParam->aliasFormat);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to get object name from subject name");
            break;
        }
    } while (0);
    if (cert != NULL) {
        FreeCertContext(cert);
    }
    return ret;
}

static int32_t StoreKeyAndCert(const struct CmContext *context, const struct CmAppCertParam *param,
    struct AppCert *appCert, EVP_PKEY *priKey, struct CmBlob *keyUri)
{
    int32_t ret = CmCheckCertCount(context, param->store, (char *)keyUri->data);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("cert count beyond maxcount, can't install");
        return CMR_ERROR_MAX_CERT_COUNT_REACHED;
    }
    enum CmAuthStorageLevel level;
    ret = GetRdbAuthStorageLevel(keyUri, &level);
    /* Return "CM_SUCCESS" when no results are found in the query. */
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get rdb auth storage level failed, ret = %d", ret);
        return ret;
    }

    switch (param->store) {
        case CM_PRI_CREDENTIAL_STORE:
            /* The result is found, but the level does not match. */
            if (level != ERROR_LEVEL && level != param->level) {
                ret = CmRemoveAppCert(context, keyUri, CM_PRI_CREDENTIAL_STORE);
                if (ret != CM_SUCCESS) {
                    /* Don't return when the deletion fails to increase fault tolerance. */
                    CM_LOG_E("remove private app cert failed, ret = %d", ret);
                }
            }
            level = param->level;
            break;
        case CM_CREDENTIAL_STORE:
            /* If not found, specify the level el2 */
            if (level == ERROR_LEVEL) {
                level = CM_AUTH_STORAGE_LEVEL_EL2;
            }
            break;
        default:
            /* whether you find it or not, specify the level el1 */
            level = CM_AUTH_STORAGE_LEVEL_EL1;
            break;
    }

    ret = ImportKeyPair(priKey, keyUri, level);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("import key pair failed");
        return ret;
    }

    ret = StoreAppCert(context, appCert, param->store, keyUri);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("store App Cert failed");
        return ret;
    }
    return CM_SUCCESS;
}

int32_t CmInstallAppCertPro(
    struct CmContext *context, const struct CmAppCertParam *certParam, struct CmBlob *keyUri)
{
    struct AppCert appCert;
    (void)memset_s(&appCert, sizeof(struct AppCert), 0, sizeof(struct AppCert));
    EVP_PKEY *priKey = NULL;
    uint8_t subjectBuf[MAX_LEN_SUBJECT_NAME] = { 0 };
    struct CmBlob subjectName = { sizeof(subjectBuf), subjectBuf };
    uint8_t objectBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    struct CmBlob objectName = { sizeof(objectBuf), objectBuf };
    uint8_t displayBuf[MAX_LEN_CERT_ALIAS] = { 0 };
    struct CmBlob displayName = { sizeof(displayBuf), displayBuf };
    struct CertName certName = { &displayName, &objectName, &subjectName };
    int32_t ret;
    do {
        ret = GetCredCertName(context, certParam, &priKey, &certName, &appCert);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("GetCredCertName fail");
            break;
        }

        ret = ConstructKeyUri(context, &objectName, certParam->store, keyUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("construct app cert uri fail");
            break;
        }

        ret = StoreKeyAndCert(context, certParam, &appCert, priKey, keyUri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("StoreKeyAndCert fail");
            break;
        }
        struct CertPropertyOri propertyOri = { context, keyUri, &displayName, &subjectName,
            certParam->store, certParam->level };

        ret = RdbInsertCertProperty(&propertyOri);
        if (ret != CM_SUCCESS) {
            CM_LOG_E("Failed to RdbInsertCertProperty");
            break;
        }
    } while (0);

    EVP_PKEY_free(priKey);
    return ret;
}
 
