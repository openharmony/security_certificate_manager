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

import type { BusinessError, AsyncCallback } from '@ohos.base';

native function installPrivateCertificateNative(keystore: ArrayBuffer, keystorePwd: string,
  certAlias: string): NativeResult<certificateManager.CMResult>;

native function uninstallPrivateCertificateNative(keyUri: string): NativeResult<void>;

native function getAllAppPrivateCertificatesNative(): NativeResult<certificateManager.CMResult>;

native function getPrivateCertificateNative(keyUri: string): NativeResult<certificateManager.CMResult>;

native function initNative(authUri: string,
  spec: certificateManager.CMSignatureSpec): NativeResult<certificateManager.CMHandle>;

native function updateNative(handle: ArrayBuffer, data: ArrayBuffer): NativeResult<void>;

native function finishNative(handle: ArrayBuffer, signature?: ArrayBuffer): NativeResult<certificateManager.CMResult>;

native function abortNative(handle: ArrayBuffer): NativeResult<void>;

native function getPublicCertificateNative(keyUri: string): NativeResult<certificateManager.CMResult>;

native function isAuthorizedAppNative(keyUri: string): NativeResult<boolean>;

native function getAllUserCANative(): NativeResult<certificateManager.CMResult>;

native function getAllUserCAByScopeNative(
  scope: certificateManager.CertScope
): NativeResult<certificateManager.CMResult>;

native function getUserCANative(certUri: string): NativeResult<certificateManager.CMResult>;

native function getAllSystemCredNative(): NativeResult<certificateManager.CMResult>;

native function getPrivateCertificatesNative(): NativeResult<certificateManager.CMResult>;

native function getCertificateStorePathNative(
  certType: certificateManager.CertType,
  certScope: certificateManager.CertScope
): NativeResult<string>;

native function installUserCASyncNative(
  cert: ArrayBuffer,
  certScope: certificateManager.CertScope
): NativeResult<certificateManager.CMResult>;

native function uninstallUserCASyncNative(certUri: string): NativeResult<void>;

native function installPrivateCertWithLevelNative(
  keystore: ArrayBuffer,
  keystorePwd: string,
  certAlias: string,
  level: certificateManager.AuthStorageLevel
): NativeResult<certificateManager.CMResult>;

class NativeResult<T> {
  code: int;
  message: string = "";
  result?: T;
}

class CredentialAbstractClass implements certificateManager.CredentialAbstract {
  type: string = '';
  alias: string = '';
  keyUri: string = '';
}

class CMResultClass implements certificateManager.CMResult{
  certList?: Array<certificateManager.CertAbstract>;
  certInfo?: certificateManager.CertInfo;
  credentialList?: Array<certificateManager.CredentialAbstract>;
  credential?: certificateManager.Credential;
  appUidList?: Array<string>;
  uri?: string;
  outData?: Uint8Array;
}

class CredentialClass implements certificateManager.Credential {
  type: string = '';
  alias: string = '';
  keyUri: string = '';
  certNum: int;
  keyNum: int;
  credentialData: Uint8Array = new Uint8Array();
}

class CMHandleClass implements certificateManager.CMHandle {
  handle: Uint8Array = new Uint8Array();
}

class CertAbstractClass implements certificateManager.CertAbstract {
  uri: string = '';
  certAlias: string = '';
  state: boolean = false;
  subjectName: string = '';
}

class CertInfoClass implements certificateManager.CertInfo {
  uri: string = '';
  certAlias: string = '';
  state: boolean = false;
  issuerName: string = '';
  subjectName: string = '';
  serial: string = '';
  notBefore: string = '';
  notAfter: string = '';
  fingerprintSha256: string = '';
  cert: Uint8Array = new Uint8Array();
}

export namespace certificateManager {

  static {
    loadLibrary("certmanager_ani.z");
  }

  export enum CMErrorCode {
    CM_ERROR_NO_PERMISSION = 201,
    CM_ERROR_NOT_SYSTEM_APP = 202,
    CM_ERROR_INVALID_PARAMS = 401,
    CM_ERROR_GENERIC = 17500001,
    CM_ERROR_NO_FOUND = 17500002,
    CM_ERROR_INCORRECT_FORMAT = 17500003,
    CM_ERROR_MAX_CERT_COUNT_REACHED = 17500004,
    CM_ERROR_NO_AUTHORIZATION = 17500005,
    CM_ERROR_DEVICE_ENTER_ADVSECMODE = 17500007,
    CM_ERROR_STORE_PATH_NOT_SUPPORTED = 17500009
  }

  export interface CertInfo {
    uri: string;
    certAlias: string;
    state: boolean;
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
    state: boolean;
    subjectName: string;
  }

  export interface Credential {
    type: string;
    alias: string;
    keyUri: string;
    certNum: int;
    keyNum: int;
    credentialData: Uint8Array;
  }

  export interface CredentialAbstract {
    type: string;
    alias: string;
    keyUri: string;
  }

  export interface CMResult {
    certList?: Array<CertAbstract>;
    certInfo?: CertInfo;
    credentialList?: Array<CredentialAbstract>;
    credential?: Credential;
    appUidList?: Array<string>;
    uri?: string;
    outData?: Uint8Array;
  }

  export enum CmKeyPurpose {
    CM_KEY_PURPOSE_SIGN = 4,
    CM_KEY_PURPOSE_VERIFY = 8
  }

  export enum CmKeyDigest {
    CM_DIGEST_NONE = 0,
    CM_DIGEST_MD5 = 1,
    CM_DIGEST_SHA1 = 2,
    CM_DIGEST_SHA224 = 3,
    CM_DIGEST_SHA256 = 4,
    CM_DIGEST_SHA384 = 5,
    CM_DIGEST_SHA512 = 6,
    CM_DIGEST_SM3 = 7
  }

  export enum CmKeyPadding {
    CM_PADDING_NONE = 0,
    CM_PADDING_PSS = 1,
    CM_PADDING_PKCS1_V1_5 = 2
  }

  export interface CMSignatureSpec {
    purpose: CmKeyPurpose;
    padding?: CmKeyPadding;
    digest?: CmKeyDigest;
  }

  export interface CMHandle {
    handle: Uint8Array;
  }

  function taskExecuteReturn<T>(pool: Promise<NullishType>, callback: AsyncCallback<T>, result: T): void {
    pool.then<void>((ret: NullishType) => {
      let nativeResult: NativeResult<T> = ret as NativeResult<T>;
      let err = new BusinessError();
      if (nativeResult.result !== undefined) {
        result = nativeResult.result as T;
      }
      if (nativeResult.code === 0) {
        err.code = 0;
        callback(err, result);
      } else {
        err.code = nativeResult.code;
        err.message = nativeResult.message;
        callback(err, result);
      }
    });
  }

  export enum CertType {
    CA_CERT_SYSTEM = 0,
    CA_CERT_USER = 1
  }

  export enum CertScope {
    CURRENT_USER = 1,
    GLOBAL_USER = 2
  }

  export interface CertStoreProperty {
    certType: CertType;
    certScope?: CertScope;
  }
  
  export enum AuthStorageLevel {
    EL1 = 1,
    EL2 = 2,
    EL4 = 4,
  }

  function createPromise<T>(task: () => NativeResult<T>, result: T): Promise<T> {
    return new Promise<T>((resolve, reject: (error: BusinessError) => void) => {
      let nativeResult: NativeResult<T> = task();
      if (nativeResult.result !== undefined) {
        result = nativeResult.result as T;
      }
      if (nativeResult.code === 0) {
        resolve(result);
      } else {
        let error: BusinessError = { code: nativeResult.code, message: nativeResult.message };
        reject(error);
      }
    })
  }

  export function installPrivateCertificate(
    keystore: Uint8Array,
    keystorePwd: string,
    certAlias: string,
    callback: AsyncCallback<CMResult>
  ): void {
    let pool = taskpool.execute(installPrivateCertificateNative, keystore.buffer, keystorePwd, certAlias);
    taskExecuteReturn<CMResult>(pool, callback, {});
  }

  export function installPrivateCertificate(
    keystore: Uint8Array,
    keystorePwd: string,
    certAlias: string
  ): Promise<CMResult> {
    return createPromise<CMResult>(() => installPrivateCertificateNative(keystore.buffer, keystorePwd, certAlias), {});
  }

  export function uninstallPrivateCertificate(keyUri: string, callback: AsyncCallback<void>): void {
    let pool = taskpool.execute(uninstallPrivateCertificateNative, keyUri);
    taskExecuteReturn<void>(pool, callback, undefined);
  }

  export function uninstallPrivateCertificate(keyUri: string): Promise<void> {
    return createPromise<void>(() => uninstallPrivateCertificateNative(keyUri), undefined);
  }

  export function getAllAppPrivateCertificates(callback: AsyncCallback<CMResult>): void {
    let pool = taskpool.execute(getAllAppPrivateCertificatesNative);
    taskExecuteReturn<CMResult>(pool, callback, {});
  }

  export function getAllAppPrivateCertificates(): Promise<CMResult> {
    return createPromise<CMResult>(() => getAllAppPrivateCertificatesNative(), {});
  }

  export function getPrivateCertificate(keyUri: string, callback: AsyncCallback<CMResult>): void {
    let pool = taskpool.execute(getPrivateCertificateNative, keyUri);
    taskExecuteReturn<CMResult>(pool, callback, {});
  }

  export function getPrivateCertificate(keyUri: string): Promise<CMResult> {
    return createPromise<CMResult>(() => getPrivateCertificateNative(keyUri), {});
  }

  export function init(authUri: string, spec: CMSignatureSpec, callback: AsyncCallback<CMHandle>): void {
    let result: CMHandle = { handle: new Uint8Array() };
    let pool = taskpool.execute(initNative, authUri, spec);
    taskExecuteReturn<CMHandle>(pool, callback, result);
  }

  export function init(authUri: string, spec: CMSignatureSpec): Promise<CMHandle> {
    let result: CMHandle = { handle: new Uint8Array() };
    return createPromise<CMHandle>(() => initNative(authUri, spec), result);
  }

  export function update(handle: Uint8Array, data: Uint8Array, callback: AsyncCallback<void>): void {
    let pool = taskpool.execute(updateNative, handle.buffer, data.buffer);
    taskExecuteReturn<void>(pool, callback, undefined);
  }

  export function update(handle: Uint8Array, data: Uint8Array): Promise<void> {
    return createPromise<void>(() => updateNative(handle.buffer, data.buffer), undefined);
  }

  export function finish(handle: Uint8Array, callback: AsyncCallback<CMResult>): void {
    let pool = taskpool.execute(finishNative, handle.buffer, undefined);
    taskExecuteReturn<CMResult>(pool, callback, {});
  }

  export function finish(handle: Uint8Array, signature: Uint8Array, callback: AsyncCallback<CMResult>): void {
    let pool = taskpool.execute(finishNative, handle.buffer, signature.buffer);
    taskExecuteReturn<CMResult>(pool, callback, {});
  }

  export function finish(handle: Uint8Array, signature?: Uint8Array): Promise<CMResult> {
    return createPromise<CMResult>(() => finishNative(handle.buffer, signature?.buffer?? undefined), {});
  }

  export function abort(handle: Uint8Array, callback: AsyncCallback<void>): void {
    let pool = taskpool.execute(abortNative, handle.buffer);
    taskExecuteReturn<void>(pool, callback, undefined);
  }

  export function abort(handle: Uint8Array): Promise<void> {
    return createPromise<void>(() => abortNative(handle.buffer), undefined);
  }

  export function getPublicCertificate(keyUri: string): Promise<CMResult> {
    return createPromise<CMResult>(() => getPublicCertificateNative(keyUri), {});
  }

  export function isAuthorizedApp(keyUri: string): Promise<boolean> {
    return createPromise<boolean>(() => isAuthorizedAppNative(keyUri), false);
  }

  export function getAllUserTrustedCertificates(): Promise<CMResult> {
    return createPromise<CMResult>(() => getAllUserCANative(), {});
  }

  export function getAllUserTrustedCertificates(scope: CertScope): Promise<CMResult> {
    return createPromise<CMResult>(() => getAllUserCAByScopeNative(scope), {});
  }

  export function getUserTrustedCertificate(certUri: string): Promise<CMResult> {
    return createPromise<CMResult>(() => getUserCANative(certUri), {});
  }

  export function getAllSystemAppCertificates(): Promise<CMResult> {
    return createPromise<CMResult>(() => getAllSystemCredNative(), {});
  }

  export function getPrivateCertificates(): Promise<CMResult> {
    return createPromise<CMResult>(() => getPrivateCertificatesNative(), {});
  }

  export function getCertificateStorePath(property: CertStoreProperty): string {
    let certType: CertType = property.certType;
    let certScope: CertScope = property.certScope?? CertScope.CURRENT_USER;
    let nativeResult: NativeResult<string> = getCertificateStorePathNative(certType, certScope);
    if (nativeResult.code === 0) {
      return nativeResult.result?? '';
    } else {
      let error = new BusinessError();
      error.code = nativeResult.code;
      error.message = nativeResult.message;
      throw error;
    }
  }

  export function installUserTrustedCertificateSync(cert: Uint8Array, certScope: CertScope) : CMResult {
    let nativeResult: NativeResult<CMResult> = installUserCASyncNative(cert.buffer, certScope);
    if (nativeResult.code === 0) {
      let result: CMResult = nativeResult.result?? {} as CMResult;
      return result;
    } else {
      let error = new BusinessError();
      error.code = nativeResult.code;
      error.message = nativeResult.message;
      throw error;
    }
  }

  export function uninstallUserTrustedCertificateSync(certUri: string) : void {
    let nativeResult: NativeResult<void> = uninstallUserCASyncNative(certUri);
    if (nativeResult.code === 0) {
      return;
    } else {
      let error = new BusinessError();
      error.code = nativeResult.code;
      error.message = nativeResult.message;
      throw error;
    }
  }

  export function installPrivateCertificate(
    keystore: Uint8Array,
    keystorePwd: string,
    certAlias: string,
    level: AuthStorageLevel): Promise<CMResult> {
    return createPromise<CMResult>(
      () => installPrivateCertWithLevelNative(keystore.buffer, keystorePwd, certAlias, level),
      {}
    );
  }
}
