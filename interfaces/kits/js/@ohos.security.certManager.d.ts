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
 * OpenHarmony Universal CertificateManager
 * @since 9
 * @syscap SystemCapability.Security.CertificateManager
 * @permission N/A
 */
declare namespace CertificateManager {
    /**
     * Get a list of system root certificates.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param context Indicates the context of the calling interface application.
     * @permission ohos.permission.ACCESS_CERT_MANAGER
     */
    function getSystemTrustedCertificateList(context: CMContext, callback: AsyncCallback<CMResult>) : void;
    function getSystemTrustedCertificateList(context: CMContext) : Promise<CMResult>;

    /**
     * Get the detail of system root certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param context Indicates the context of the calling interface application.
     * @param certUri Indicates the certificate's name.
     * @permission ohos.permission.ACCESS_CERT_MANAGER
     */
    function getSystemTrustedCertificate(context: CMContext, certUri: string, callback: AsyncCallback<CMResult>) : void;
    function getSystemTrustedCertificate(context: CMContext, certUri: string) : Promise<CMResult>;

    /**
     * Set the status of root certificates.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param context Indicates the context of the calling interface application.
     * @param certUri Indicates the certificate's name.
     * @param store Indicates the type of certificate.
     * @param status Indicates the status of certificate to be set.
     * @permission ohos.permission.ACCESS_CERT_MANAGER_INTERNAL
     * @systemapi Hide this for inner system use
     */
    function setCertificateStatus(context: CMContext, certUri: string, store: number, status: boolean, callback: AsyncCallback<boolean>) : void;
    function setCertificateStatus(context: CMContext, certUri: string, store: number, status: boolean) : Promise<boolean>;

    /**
     * Install the user root certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param certificate Indicates the certificate file.
     * @permission ohos.permission.ACCESS_CERT_MANAGER_INTERNAL
     * @systemapi Hide this for inner system use
     */
    function installUserTrustedCertificate(certificate: CertBlob, callback: AsyncCallback<CMResult>) : void;
    function installUserTrustedCertificate(certificate: CertBlob,) : Promise<CMResult>;

    /**
     * Uninstall all user root certificates.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @permission ohos.permission.ACCESS_CERT_MANAGER_INTERNAL
     * @systemapi Hide this for inner system use
     */
    function uninstallAllUserTrustedCertificate(callback: AsyncCallback<boolean>) : void;
    function uninstallAllUserTrustedCertificate() : Promise<boolean>;

    /**
     * Uninstall the specified user root certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param certUri Indicates the certificate's name.
     * @permission ohos.permission.ACCESS_CERT_MANAGER_INTERNAL
     * @systemapi Hide this for inner system use
     */
    function uninstallUserTrustedCertificate(certUri: string, callback: AsyncCallback<boolean>) : void;
    function uninstallUserTrustedCertificate(certUri: string) : Promise<boolean>;

    /**
     * Get a list of user root certificates.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @permission ohos.permission.ACCESS_CERT_MANAGER
     */
    function getUserTrustedCertificateList(callback: AsyncCallback<CMResult>) : void;
    function getUserTrustedCertificateList() : Promise<CMResult>;

    /**
     * Get the detail of user root certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param certUri Indicates the certificate's name.
     * @permission ohos.permission.ACCESS_CERT_MANAGER
     */
    function getUserTrustedCertificate(certUri: string, callback: AsyncCallback<CMResult>) : void;
    function getUserTrustedCertificate(certUri: string) : Promise<CMResult>;

    /**
     * Install normal application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param keystore Indicates the keystore file with key pair and certificate.
     * @param keystorePwd Indicates the password of keystore file.
     * @param certAlias Indicates the certificate name inputted by the user.
     * @permission ohos.permission.ACCESS_CERT_MANAGER_INTERNAL
     * @systemapi Hide this for inner system use
     */
    function installAppCertificate(keystore: Uint8Array, keystorePwd: string, certAlias: string, callback: AsyncCallback<CMResult>) : void;
    function installAppCertificate(keystore: Uint8Array, keystorePwd: string, certAlias: string) : Promise<CMResult>;

    /**
     * Install private application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param keystore Indicates the keystore file with key pair and certificate.
     * @param keystorePwd Indicates the password of keystore file.
     * @param certAlias Indicates the certificate name inputted by the user.
     * @permission ohos.permission.ACCESS_CERT_MANAGER
     */
    function installPrivateCertificate(keystore: Uint8Array, keystorePwd: string, certAlias: string, callback: AsyncCallback<CMResult>) : void;
    function installPrivateCertificate(keystore: Uint8Array, keystorePwd: string, certAlias: string) : Promise<CMResult>;

    /**
     * Generate private application certificate locally.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param keyAlias Indicates the key alias inputted by the user.
     * @param keyProperties Indicates the properties of keys in keystore file.
     * @permission ohos.permission.ACCESS_CERT_MANAGER
     */
    function generatePrivateCertificate(keyAlias: string, keyProperties: CMKeyProperties, callback: AsyncCallback<CMResult>) : void;
    function generatePrivateCertificate(keyAlias: string, keyProperties: CMKeyProperties) : Promise<CMResult>;

    /**
     * Update private application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param type Indicates the type of the certificate used.
     * @param keyUri Indicates key's name.
     * @param certificate Indicates the certificate file.
     * @permission ohos.permission.ACCESS_CERT_MANAGER
     */
    function updatePrivateCertificate(type: string, keyUri: string, certificate: CertBlob, callback: AsyncCallback<boolean>) : void;
    function updatePrivateCertificate(type: string, keyUri: string, certificate: CertBlob) : Promise<boolean>;

    /**
     * Uninstall all application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @permission ohos.permission.ACCESS_CERT_MANAGER_INTERNAL
     * @systemapi Hide this for inner system use
     */
    function uninstallAllAppCertificate(callback: AsyncCallback<boolean>) : void;
    function uninstallAllAppCertificate() : Promise<boolean>;

    /**
     * Uninstall the specified normal application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param keyUri Indicates key's name.
     * @permission ohos.permission.ACCESS_CERT_MANAGER_INTERNAL
     * @systemapi Hide this for inner system use
     */
    function uninstallAppCertificate(keyUri: string, callback: AsyncCallback<boolean>) : void;
    function uninstallAppCertificate(keyUri: string) : Promise<boolean>;

    /**
     * Uninstall the specified normal application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param keyUri Indicates key's name.
     * @permission ohos.permission.ACCESS_CERT_MANAGER
     */
    function uninstallPrivateCertificate(keyUri: string, callback: AsyncCallback<boolean>) : void;
    function uninstallPrivateCertificate(keyUri: string) : Promise<boolean>;

    /**
     * Get a list of normal application certificates.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @permission ohos.permission.ACCESS_CERT_MANAGER_INTERNAL
     * @systemapi Hide this for inner system use
     */
    function getAppCertificateList(callback: AsyncCallback<CMResult>) : void;
    function getAppCertificateList() : Promise<CMResult>;

    /**
     * Get a list of private application certificates.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @permission ohos.permission.ACCESS_CERT_MANAGER_INTERNAL
     * @systemapi Hide this for inner system use
     */
    function getPrivateCertificateList(callback: AsyncCallback<CMResult>) : void;
    function getPrivateCertificateList() : Promise<CMResult>;

    /**
     * Get the detail of normal application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param keyUri Indicates key's name.
     * @permission ohos.permission.ACCESS_CERT_MANAGER
     */
    function getAppCertificate(keyUri: string, callback: AsyncCallback<CMResult>) : void;
    function getAppCertificate(keyUri: string, ) : Promise<CMResult>;

    /**
     * Get the detail of private application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param keyUri Indicates key's name.
     * @permission ohos.permission.ACCESS_CERT_MANAGER
     */
    function getPrivateCertificate(keyUri: string, callback: AsyncCallback<CMResult>) : void;
    function getPrivateCertificate(keyUri: string) : Promise<CMResult>;

    /**
     * Authorize the specified application certificate for the specified application.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param keyUri Indicates key's name.
     * @param clientAppUid Indicates the uid of the authorized application.
     * @permission ohos.permission.ACCESS_CERT_MANAGER_INTERNAL
     * @systemapi Hide this for inner system use
     */
    function grantAppCertificate(keyUri: string, clientAppUid: string, callback: AsyncCallback<CMResult>) : void;
    function grantAppCertificate(keyUri: string, clientAppUid: string) : Promise<CMResult>;

    /**
     * Whether the current application is authorized by the specified application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param keyUri Indicates key's name.
     * @permission ohos.permission.ACCESS_CERT_MANAGER
     */
    function isAuthorizedApp(keyUri: string, callback: AsyncCallback<boolean>) : void;
    function isAuthorizedApp(keyUri: string) : Promise<boolean>;

    /**
     * Get the list of applications authorized by the specified certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param keyUri Indicates key's name.
     * @permission ohos.permission.ACCESS_CERT_MANAGER_INTERNAL
     * @systemapi Hide this for inner system use
     */
    function getAuthorizedAppList(keyUri: string, callback: AsyncCallback<CMResult>) : void;
    function getAuthorizedAppList(keyUri: string) : Promise<CMResult>;

    /**
     * Deauthorize the specified application from the specified application certificate.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param keyUri Indicates key's name.
     * @param clientAppUid Indicates the uid of the deauthorized application.
     * @permission ohos.permission.ACCESS_CERT_MANAGER_INTERNAL
     * @systemapi Hide this for inner system use
     */
    function removeGrantedAppCertificate(keyUri: string, clientAppUid: string, callback: AsyncCallback<boolean>) : void;
    function removeGrantedAppCertificate(keyUri: string, clientAppUid: string) : Promise<boolean>;

    /**
     * Init operation for signing and verifying etc.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param authUri Indicates the authorization relationship between application and application certificate.
     * @param spec Indicates the properties of the signature and verification..
     * @return The handle of the init Operation.
     * @permission ohos.permission.ACCESS_CERT_MANAGER
     */
    function init(authUri: string, spec: CMSignatureSpec, callback: AsyncCallback<CMHandle>) : void;
    function init(authUri: string, spec: CMSignatureSpec) : Promise<CMHandle>;

    /**
     * Update operation for signing and verifying etc.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param handle Indicates the handle of the init operation.
     * @param data Indicates the input value.
     * @param token Indicates the value of token.
     * @permission ohos.permission.ACCESS_CERT_MANAGER
     */
    function update(handle: Uint8Array, data: Uint8Array, callback: AsyncCallback<boolean>) : void;
    function update(handle: Uint8Array, data: Uint8Array) : Promise<boolean>;

    /**
     * Finish operation for signing and verifying etc.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param handle Indicates the handle of the init operation.
     * @param signature Indicates the sign data.
     * @permission ohos.permission.ACCESS_CERT_MANAGER
     */
    function finish(handle: Uint8Array, callback: AsyncCallback<CMResult>) : void;
    function finish(handle: Uint8Array, signature: Uint8Array, callback: AsyncCallback<CMResult>) : void;
    function finish(handle: Uint8Array, signature?: Uint8Array) : Promise<CMResult>;

    /**
     * Abort operation for signing and verifying etc.
     * @since 9
     * @syscap SystemCapability.Security.CertificateManager
     * @param handle Indicates the handle of the init operation.
     * @permission ohos.permission.ACCESS_CERT_MANAGER
     */
    function abort(handle: Uint8Array, callback: AsyncCallback<boolean>) : void;
    function abort(handle: Uint8Array) : Promise<boolean>;

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

    export interface CertBlob {
        inData: Uint8Array;
        alias: string;
    }

    export interface CMResult {
        certList?: Array<CertAbstract>;
        certInfo?: CertInfo;
        credentialList?: Array<CredentialAbstract>;
        credential?: Credential;
        appUidList?: Array<string>;
        uri?: string;
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

    export enum CmKeyPurpose {
        CM_KEY_PURPOSE_SIGN = 4,
        CM_KEY_PURPOSE_VERIFY = 8,
    }

    export interface CMSignatureSpec {
        purpose: CmKeyPurpose;
    }

    export interface CMHandle {
        handle: Uint8Array;
    }

    export enum CMErrorCode {
        CM_SUCCESS = 0,
        CM_ERROR_INNER_ERROR = 17500001,
        CM_ERROR_NO_PERMISSION = 17500002,
        CM_ERROR_NO_FOUND = 17500003,
        CM_ERROR_X509_FORMATE = 17500004,
    }
}

export default CertificateManager;
