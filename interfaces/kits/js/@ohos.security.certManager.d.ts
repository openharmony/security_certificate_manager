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

import {AsyncCallback} from './basic';

/**
 * OpenHarmony Universal CertManager
 * @since 9
 * @syscap SystemCapability.Security.CertManager
 * @permission N/A
 */
declare namespace certManager {
    /**
     * Get a list of system root certificates.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     */
    function getSystemTrustedCertificateList(context: CMContext, callback: AsyncCallback<CMResult>) : void;
    function getSystemTrustedCertificateList(context: CMContext) : Promise<CMResult>;

    /**
     * Get the detail of system root certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param certUri Indicates the certificate's name.
     */
    function getSystemTrustedCertificate(context: CMContext, certUri: string, callback: AsyncCallback<CMResult>) : void;
    function getSystemTrustedCertificate(context: CMContext, certUri: string) : Promise<CMResult>;

    /**
     * Set the status of root certificates.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param certUri Indicates the certificate's name.
     * @param store Indicates the type of certificate.
     * @param context Indicates the context of the calling interface application.
     * @param status Indicates the status of certificate to be set.
     */
    function setCertificateStatus(context: CMContext, certUri: string, store: number, status: boolean, callback: AsyncCallback<CMResult>) : void;
    function setCertificateStatus(context: CMContext, certUri: string, store: number, status: boolean) : Promise<CMResult>;

    /**
     * Install the user root certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param certificate Indicates the certificate file.
     */
    function installUserTrustedCertificate(context: CMContext, certificate: CMBlob, callback: AsyncCallback<CMResult>) : void;
    function installUserTrustedCertificate(context: CMContext, certificate: CMBlob,) : Promise<CMResult>;

    /**
     * Uninstall all user root certificates.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     */
    function uninstallAllUserTrustedCertificate(context: CMContext, callback: AsyncCallback<CMResult>) : void;
    function uninstallAllUserTrustedCertificate(context: CMContext) : Promise<CMResult>;

    /**
     * Uninstall the specified user root certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param certUri Indicates the certificate's name.
     */
    function uninstallUserTrustedCertificate(context: CMContext, certUri: string, callback: AsyncCallback<CMResult>) : void;
    function uninstallUserTrustedCertificate(context: CMContext, certUri: string) : Promise<CMResult>;

    /**
     * Get a list of user root certificates.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     */
    function getUserTrustedCertificateList(context: CMContext, callback: AsyncCallback<CMResult>) : void;
    function getUserTrustedCertificateList(context: CMContext) : Promise<CMResult>;

    /**
     * Get the detail of user root certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param certUri Indicates the certificate's name.
     */
    function getUserTrustedCertificate(context: CMContext, certUri: string, callback: AsyncCallback<CMResult>) : void;
    function getUserTrustedCertificate(context: CMContext, certUri: string) : Promise<CMResult>;

    /**
     * Install normal application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param keystore Indicates the keystore file with key pair and certificate.
     * @param keystorePwd Indicates the password of keystore file.
     * @param certAlias Indicates the certificate name inputted by the user.
     * @param keyProperties Indicates the properties of keys in keystore file.
     */
    function installAppCertificate(context: CMContext, keystore: CMBlob, keystorePwd: string, certAlias: string, keyProperties: CMKeyProperties, callback: AsyncCallback<CMResult>) : void;
    function installAppCertificate(context: CMContext, keystore: CMBlob, keystorePwd: string, certAlias: string, keyProperties: CMKeyProperties) : Promise<CMResult>;

    /**
     * Install private application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param keystore Indicates the keystore file with key pair and certificate.
     * @param keystorePwd Indicates the password of keystore file.
     * @param certAlias Indicates the certificate name inputted by the user.
     * @param keyProperties Indicates the properties of keys in keystore file.
     */
    function installPrivateCertificate(context: CMContext, keystore: CMBlob, keystorePwd: string, certAlias: string, keyProperties: CMKeyProperties, callback: AsyncCallback<CMResult>) : void;
    function installPrivateCertificate(context: CMContext, keystore: CMBlob, keystorePwd: string, certAlias: string, keyProperties: CMKeyProperties) : Promise<CMResult>;

    /**
     * Generate private application certificate locally.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param keyAlias Indicates the key alias inputted by the user.
     * @param keyProperties Indicates the properties of keys in keystore file.
     */
    function generatePrivateCertificate(context: CMContext, keyAlias: string, keyProperties: CMKeyProperties, callback: AsyncCallback<CMResult>) : void;
    function generatePrivateCertificate(context: CMContext, keyAlias: string, keyProperties: CMKeyProperties) : Promise<CMResult>;

    /**
     * Update private application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param type Indicates the type of the certificate used.
     * @param keyUri Indicates key's name.
     * @param certificate Indicates the certificate file.
     */
    function updatePrivateCertificate(context: CMContext, type: string, keyUri: string, certificate: CMBlob, callback: AsyncCallback<CMResult>) : void;
    function updatePrivateCertificate(context: CMContext, type: string, keyUri: string, certificate: CMBlob) : Promise<CMResult>;

    /**
     * Uninstall all application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     */
    function uninstallAllAppCertificate(context: CMContext, callback: AsyncCallback<CMResult>) : void;
    function uninstallAllAppCertificate(context: CMContext) : Promise<CMResult>;

    /**
     * Uninstall the specified normal application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param keyUri Indicates key's name.
     */
    function uninstallAppCertificate(context: CMContext, keyUri: string, callback: AsyncCallback<CMResult>) : void;
    function uninstallAppCertificate(context: CMContext, keyUri: string) : Promise<CMResult>;

    /**
     * Uninstall the specified normal application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param keyUri Indicates key's name.
     */
    function uninstallPrivateCertificate(context: CMContext, keyUri: string, callback: AsyncCallback<CMResult>) : void;
    function uninstallPrivateCertificate(context: CMContext, keyUri: string) : Promise<CMResult>;

    /**
     * Get a list of normal application certificates.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     */
    function getAppCertificateList(context: CMContext, callback: AsyncCallback<CMResult>) : void;
    function getAppCertificateList(context: CMContext) : Promise<CMResult>;

    /**
     * Get a list of private application certificates.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     */
    function getPrivateCertificateList(context: CMContext, callback: AsyncCallback<CMResult>) : void;
    function getPrivateCertificateList(context: CMContext) : Promise<CMResult>;

    /**
     * Get the detail of normal application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param keyUri Indicates key's name.
     */
    function getAppCertificate(context: CMContext, keyUri: string, callback: AsyncCallback<CMResult>) : void;
    function getAppCertificate(context: CMContext, keyUri: string, ) : Promise<CMResult>;

    /**
     * Get the detail of private application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param keyUri Indicates key's name.
     */
    function getPrivateCertificate(context: CMContext, keyUri: string, callback: AsyncCallback<CMResult>) : void;
    function getPrivateCertificate(context: CMContext, keyUri: string) : Promise<CMResult>;

    /**
     * Authorize the specified application certificate for the specified application.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param keyUri Indicates key's name.
     * @param clientApp Indicates the context of the authorized application.
     */
    function grantAppCertificate(context: CMContext, keyUri: string, clientApp: CMContext, callback: AsyncCallback<CMResult>) : void;
    function grantAppCertificate(context: CMContext, keyUri: string, clientApp: CMContext) : Promise<CMResult>;

    /**
     * Whether the current application is authorized by the specified application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param keyUri Indicates key's name.
     */
    function isAuthorizedApp(context: CMContext, keyUri: string, callback: AsyncCallback<CMResult>) : void;
    function isAuthorizedApp(context: CMContext, keyUri: string) : Promise<CMResult>;

    /**
     * Get the list of applications authorized by the specified certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param keyUri Indicates key's name.
     */
    function getAuthorizedAppList(context: CMContext, keyUri: string, callback: AsyncCallback<CMResult>) : void;
    function getAuthorizedAppList(context: CMContext, keyUri: string) : Promise<CMResult>;

    /**
     * Deauthorize the specified application from the specified application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param keyUri Indicates key's name.
     * @param clientApp Indicates the context of the deauthorized application.
     */
    function removeGrantAppCertificate(context: CMContext, keyUri: string, clientApp: CMContext, callback: AsyncCallback<CMResult>) : void;
    function removeGrantAppCertificate(context: CMContext, keyUri: string, clientApp: CMContext) : Promise<CMResult>;

    /**
     * Init Operation.
     * @since 8
     * @syscap SystemCapability.Security.CertManager
     * @param context Indicates the context of the calling interface application.
     * @param authUri Indicates the authorization relationship between application and application certificate.
     * @param spec Indicates the properties of the signature and verification..
     * @return The handle of the init Operation.
     */
    function init(context: CMContext, authUri: string, spec: CMSignatureSpec, callback: AsyncCallback<CMHandle>) : void; 
    function init(context: CMContext, authUri: string, spec: CMSignatureSpec) : Promise<CMHandle>;

    /**
     * Update Operation.
     * @since 8
     * @syscap SystemCapability.Security.Huks
     * @param context Indicates the context of the calling interface application.
     * @param handle Indicates the handle of the init operation.
     * @param data Indicates the input value.
     * @param token Indicates the value of token.
     */
    function update(context: CMContext, handle: number, data: Uint8Array, callback: AsyncCallback<CMResult>) : void;
    function update(context: CMContext, handle: number, data: Uint8Array, token: Uint8Array, callback: AsyncCallback<CMResult>) : void;
    function update(context: CMContext, handle: number, data: Uint8Array, token?: Uint8Array) : Promise<CMResult>;


    /**
     * Finish Operation.
     * @since 8
     * @syscap SystemCapability.Security.Huks
     * @param context Indicates the context of the calling interface application.
     * @param handle Indicates the handle of the init operation.
     * @param signature Indicates the sign data.
     */
    function finish(context: CMContext, handle: number, callback: AsyncCallback<CMResult>) : void;
    function finish(context: CMContext, handle: number, signature: Uint8Array, callback: AsyncCallback<CMResult>) : void;
    function finish(context: CMContext, handle: number, signature?: Uint8Array) : Promise<CMResult>;

    /**
     * Abort Operation.
     * @since 8
     * @syscap SystemCapability.Security.Huks
     * @param context Indicates the context of the calling interface application.
     * @param handle Indicates the handle of the init operation.
     */
    function abort(context: CMContext, handle: number, callback: AsyncCallback<CMResult>) : void;
    function abort(context: CMContext, handle: number) : Promise<CMResult>;

    export interface CMContext {
        userId: string;
        uid: string;
        packageName: string;
    }

    export interface CertInfo {
        uri: string;
        certAlias: string;
        status: boolean;
        issuerName: string;
        subjectName: string;
        serial: string;
        notBefore: string;
        notAfter: string;
        fingerprintSha1: string;
        fingerprintSha256: string;
        cert: Uint8Array;
    }

    export interface CertAbstract {
        uri: string;
        certAlias: string;
        status: boolean;
        subjectName: string;
    }

    export interface Credential {
        type: string;
        alias: string;
        keyUri: string;
        certNum: number;
        keyNum: number;
        credData:Uint8Array;
    }

    export interface CredentialAbstract {
        type: string;
        alias: string;
        keyUri: string;
    }

    export interface CMBlob {
        readonly inData?: Uint8Array;
        readonly alias?: string;
    }

    export interface CMResult {
        errorCode: number;
        certList?: Array<CertAbstract>;
        certInfo?: CertInfo;
        credentialList?: Array<CredentialAbstract>;
        credential?: Credential;
        appList?: Array<CMContext>;
        authUri?: string;
        outData?: Uint8Array;
        isAuth?: boolean;
    }

    export interface CMKeyProperties {
        type: string;
        alg: string;
        size: number;
        padding: string;
        purpose: string;
        digest: string;
        authType: string;
        authTimeout: string;
    }

    export interface CMSignatureSpec {
        alg: string;
        padding: string;
        digest: string;
        authToken: Uint8Array;
    }

    export interface CMHandle {
        errorCode: number;
        handle: number;
        token?: Uint8Array;
    }

    export enum CMErrorCode {
        CM_SUCCESS = 0,
        CM_FAILURE = -1,
        CM_ERROR_INSTALL_CERTIFICATE = -2,
        CM_ERROR_SET_STATUS = -3,
        CM_ERROR_INVALID_ARGUMENT = -3,
        CM_ERROR_INVALID_STORE = -4,
        CM_ERROR_NOT_SUPPORTED = -5,
        CM_ERROR_UNINSTALL = -6,
        CM_ERROR_NO_PERMISSION = -7,
        CM_ERROR_INSUFFICIENT_DATA = -8,
        CM_ERROR_GET_CERTIRICATE = -9,
        CM_ERROR_STORAGE_FAILURE = -10,
        CM_ERROR_HARDWARE_FAILURE = -11,
        CM_ERROR_ALREADY_EXISTS = -12,
        CM_ERROR_NOT_EXIST = -13,
        CM_ERROR_NULL_POINTER = -14,
        CM_ERROR_FILE_SIZE_FAIL = -15,
        CM_ERROR_READ_FILE_FAIL = -16,
        CM_ERROR_INVALID_PUBLIC_KEY = -17,
        CM_ERROR_INVALID_PRIVATE_KEY = -18,
        CM_ERROR_INVALID_KEY_INFO = -19,
        CM_ERROR_REMOVE_CERTIFICATE_FAIL = -20,
        CM_ERROR_OPEN_FILE_FAIL = -21,
        CM_ERROR_INVALID_KEY_FILE = -22,
        CM_ERROR_IPC_MSG_FAIL = -23,
        CM_ERROR_REQUEST_OVERFLOWS = -24,
        CM_ERROR_PARAM_NOT_EXIST = -25,
        CM_ERROR_CRYPTO_ENGINE_ERROR = -26,
        CM_ERROR_COMMUNICATION_TIMEOUT = -27,
        CM_ERROR_IPC_INIT_FAIL = -28,
        CM_ERROR_IPC_DLOPEN_FAIL = -29,
        CM_ERROR_EFUSE_READ_FAIL = -30,

        CM_ERROR_CHECK_GET_ALG_FAIL = -100,
        CM_ERROR_CHECK_GET_KEY_SIZE_FAIL = -101,
        CM_ERROR_CHECK_GET_PADDING_FAIL = -102,
        CM_ERROR_INVALID_DIGEST =  -117,

        CM_ERROR_INTERNAL_ERROR = -999,
        CM_ERROR_UNKNOWN_ERROR = -1000,
    }
}

export default certManager;
