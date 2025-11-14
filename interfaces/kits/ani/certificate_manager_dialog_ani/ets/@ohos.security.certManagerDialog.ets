/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

import type common from '@ohos.app.ability.common';
import { BusinessError, AsyncCallback } from '@ohos.base';
import util from '@ohos.util';
import type certificateManager from '@ohos.security.certManager';

native function openCertificateManagerDialogNative(
  context: common.Context,
  pageType: certificateManagerDialog.CertificateDialogPageType,
  callback: AsyncCallbackWrapper<void>
): NativeResult<void>;

native function openInstallCertificateDialogNative(
  context: common.Context,
  params: InstallDialogParams,
  callback: AsyncCallbackWrapper<string>
): NativeResult<void>;

interface InstallDialogParams {
  certType: certificateManagerDialog.CertificateType,
  certScope: certificateManagerDialog.CertificateScope,
  certStr: string,
}

native function openUninstallCertificateDialogNative(
  context: common.Context,
  certType: certificateManagerDialog.CertificateType,
  certUri: string,
  callback: AsyncCallbackWrapper<void>
): NativeResult<void>;

native function openCertificateDetailDialogNative(
  context: common.Context,
  cert: string,
  showInstallButton: boolean,
  callback: AsyncCallbackWrapper<void>
): NativeResult<void>;

native function openAuthorizeDialogNative(context: common.Context,
  callback: AsyncCallbackWrapper<string>): NativeResult<void>;

native function openAuthorizeDialogWithReqNative(
  context: common.Context,
  certTypes: Array<certificateManagerDialog.CertificateType>,
  certPurpose: certificateManager.CertificatePurpose,
  callback: AsyncCallbackWrapper<certificateManagerDialog.CertReference>
): NativeResult<void>;

native function openUkeyAuthDialogNative(
  context: common.Context,
  keyUri: string,
  callback: AsyncCallbackWrapper<void>
): NativeResult<void>;

class NativeResult<T> {
  code: int;
  message: string = "";
  result?: T;
}

class AsyncCallbackWrapper<T> {
  private wrapperCallback: AsyncCallback<T, void> = (err: BusinessError | null, data: T | undefined) => {};

  constructor(callback: AsyncCallback<T, void>) {
    this.wrapperCallback = callback;
  }

  invoke(err: BusinessError, data: T) {
    this.wrapperCallback(err, data);
  }
}

class CertReferenceClass implements certificateManagerDialog.CertReference {
    certType: certificateManagerDialog.CertificateType = certificateManagerDialog.CertificateType.CA_CERT;
    keyUri: string = '';
}

export namespace certificateManagerDialog {

  static {
    loadLibrary("certmanager_dialog_ani.z");
  }

  export interface AuthorizeRequest {
    certTypes: Array<CertificateType>;
    certPurpose?: certificateManager.CertificatePurpose;
  }

  export interface CertReference {
    certType: CertificateType;
    keyUri: string;
  }

  export interface UkeyAuthRequest {
    keyUri: string
  }

  export enum CertificateDialogErrorCode {
    ERROR_GENERIC = 29700001,
    ERROR_OPERATION_CANCELED = 29700002,
    ERROR_OPERATION_FAILED = 29700003,
    ERROR_DEVICE_NOT_SUPPORTED = 29700004,
    ERROR_NOT_COMPLY_SECURITY_POLICY = 29700005,
  }

  export enum CertificateDialogPageType {
    PAGE_MAIN = 1,
    PAGE_CA_CERTIFICATE = 2,
    PAGE_CREDENTIAL = 3,
    PAGE_INSTALL_CERTIFICATE = 4
  }

  export enum CertificateType {
    CA_CERT = 1,
    CREDENTIAL_USER = 2,
    CREDENTIAL_APP = 3,
    CREDENTIAL_UKEY = 4,
  }

  export enum CertificateScope {
    NOT_SPECIFIED = 0,
    CURRENT_USER = 1,
    GLOBAL_USER = 2,
  }

  const MIN_DATA_LEN: double = 1;
  const MAX_DATA_LEN: double = 0x6400000;

  function checkBufferLen(buffer: Uint8Array, minLen: double, maxLen: double) {
    if (buffer.length < minLen || buffer.length > maxLen) {
      let error = new BusinessError();
      error.code = 401;
      error.message = 'the input parameters is invalid.';
      throw error;
    }
  }

  function checkStrLen(str: string, minLen: double, maxLen: double) {
    if (str.length < minLen || str.length > maxLen) {
      let error = new BusinessError();
      error.code = 401;
      error.message = 'the input parameters is invalid.';
      throw error;
    }
  }

  export function openCertificateManagerDialog(context: common.Context, pageType: CertificateDialogPageType): Promise<void> {
    return new Promise<void>((resolve, reject: (error: BusinessError) => void) => {
        let callback = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
          if (err?.code !== 0) {
              reject(err as BusinessError);
          } else {
              resolve(undefined);
          }
        });
        let result: NativeResult<void> = openCertificateManagerDialogNative(context, pageType, callback);
        if (result.code !== 0) {
          let err = new BusinessError();
          err.code = result.code;
          err.message = result.message;
          reject(err);
        }
    });
  }

  export function openInstallCertificateDialog(context: common.Context, certType: CertificateType, certScope: CertificateScope, cert: Uint8Array): Promise<string> {
    checkBufferLen(cert, MIN_DATA_LEN, MAX_DATA_LEN);
    return new Promise<string>((resolve, reject: (error: BusinessError) => void) => {
        let callback = new AsyncCallbackWrapper<string>((err: BusinessError | null, data: string | undefined) => {
            if (err?.code !== 0) {
                reject(err as BusinessError);
            } else {
                resolve(data?? '');
            }
        });
        // convert cert data to base64 string
        let base64Helper = new util.Base64Helper();
        let certStringBase64 = base64Helper.encodeToStringSync(cert, util.Type.BASIC);
        let result: NativeResult<void> = openInstallCertificateDialogNative(context, {
          certType: certType,
          certScope: certScope,
          certStr: certStringBase64
        }, callback);
        if (result.code !== 0) {
          let err = new BusinessError();
          err.code = result.code;
          err.message = result.message;
          reject(err);
        }
    });
  }

  export function openUninstallCertificateDialog(context: common.Context, certType: CertificateType, certUri: string): Promise<void> {
    checkStrLen(certUri, MIN_DATA_LEN, MAX_DATA_LEN);
    return new Promise<void>((resolve, reject: (error: BusinessError) => void) => {
        let callback = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
            if (err?.code !== 0) {
                reject(err as BusinessError);
            } else {
                resolve(undefined);
            }
        });
        let result: NativeResult<void> = openUninstallCertificateDialogNative(context, certType, certUri, callback);
        if (result.code !== 0) {
          let err = new BusinessError();
          err.code = result.code;
          err.message = result.message;
          reject(err);
        }
    });
  }

  export interface CertificateDialogProperty {
    showInstallButton: boolean;
  }

  export function openCertificateDetailDialog(context: common.Context, cert: Uint8Array, property: CertificateDialogProperty): Promise<void> {
    checkBufferLen(cert, MIN_DATA_LEN, MAX_DATA_LEN);
    return new Promise<void>((resolve, reject: (error: BusinessError) => void) => {
        let callback = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
            if (err?.code !== 0) {
                reject(err as BusinessError);
            } else {
                resolve(undefined);
            }
        });
        // convert cert data to base64 string
        let base64Helper = new util.Base64Helper();
        let certStringBase64 = base64Helper.encodeToStringSync(cert, util.Type.BASIC);
        let result: NativeResult<void> = openCertificateDetailDialogNative(context, certStringBase64, property.showInstallButton, callback);
        if (result.code !== 0) {
          let err = new BusinessError();
          err.code = result.code;
          err.message = result.message;
          reject(err);
        }
    });
  }

  export function openAuthorizeDialog(context: common.Context): Promise<string> {
    return new Promise<string>((resolve, reject: (error: BusinessError) => void) => {
        let callback = new AsyncCallbackWrapper<string>((err: BusinessError | null, data: string | undefined) => {
            if (err?.code !== 0) {
                reject(err as BusinessError);
            } else {
                resolve(data?? '');
            }
        });
        let result: NativeResult<void> = openAuthorizeDialogNative(context, callback);
        if (result.code !== 0) {
          let err = new BusinessError();
          err.code = result.code;
          err.message = result.message;
          reject(err);
        }
    });
  }

  export function openAuthorizeDialog(context: common.Context, authorizeRequest: AuthorizeRequest): Promise<CertReference> {
    return new Promise<CertReference>((resolve, reject: (error: BusinessError) => void) => {
        let certReference: CertReference = {
           certType: CertificateType.CA_CERT,
           keyUri: "" 
        };
        let callback = new AsyncCallbackWrapper<CertReference>((err: BusinessError | null, data: CertReference | undefined) => {
            if (err?.code !== 0) {
                reject(err as BusinessError);
            } else {
                resolve(data?? certReference);
            }
        });
        let certTypes: Array<CertificateType> = authorizeRequest.certTypes;
        if (certTypes === undefined) {
          let error = new BusinessError();
          error.code = 401;
          error.message = 'the input parameters is invalid.';
          throw error;
        }
        let certPurpose: certificateManager.CertificatePurpose = authorizeRequest.certPurpose??
          certificateManager.CertificatePurpose.PURPOSE_DEFAULT;
        let result: NativeResult<void> = openAuthorizeDialogWithReqNative(context, certTypes, certPurpose, callback);
        if (result.code !== 0) {
          let err = new BusinessError();
          err.code = result.code;
          err.message = result.message;
          reject(err);
        }
    });
  }

  export function openUkeyAuthDialog(context: common.Context, ukeyAuthRequest: UkeyAuthRequest): Promise<void> {
    return new Promise<void>((resolve, reject: (error: BusinessError) => void) => {
        let callback = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
            if (err?.code !== 0) {
                reject(err as BusinessError);
            } else {
                resolve(undefined);
            }
        });

        let keyUri: string = ukeyAuthRequest.keyUri;
        if (keyUri === undefined) {
          let error = new BusinessError();
          error.code = 401;
          error.message = 'the input parameters is invalid.';
          throw error;
        }
        let result: NativeResult<void> = openUkeyAuthDialogNative(context, keyUri, callback);
        if (result.code !== 0) {
          let err = new BusinessError();
          err.code = result.code;
          err.message = result.message;
          reject(err);
        }
    });
  }
}
