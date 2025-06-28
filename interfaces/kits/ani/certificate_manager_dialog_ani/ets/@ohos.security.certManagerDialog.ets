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
import type buffer from '@ohos.buffer'

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

export namespace certificateManagerDialog {

  static {
    loadLibrary("certmanager_dialog_ani.z");
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
    CA_CERT = 1
  }

  export enum CertificateScope {
    NOT_SPECIFIED = 0,
    CURRENT_USER = 1,
    GLOBAL_USER = 2,
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
    return new Promise<string>((resolve, reject: (error: BusinessError) => void) => {
        let callback = new AsyncCallbackWrapper<string>((err: BusinessError | null, data: string | undefined) => {
            if (err?.code !== 0) {
                reject(err as BusinessError);
            } else {
                resolve(data?? '');
            }
        });
        // convert cert data to base64 string
        let certStringBase64 = buffer.from(cert.buffer as ArrayBuffer).toString('base64');
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
    return new Promise<void>((resolve, reject: (error: BusinessError) => void) => {
        let callback = new AsyncCallbackWrapper<void>((err: BusinessError | null) => {
            if (err?.code !== 0) {
                reject(err as BusinessError);
            } else {
                resolve(undefined);
            }
        });
        // convert cert data to base64 string
        let certStringBase64 = buffer.from(cert.buffer as ArrayBuffer).toString('base64');
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
}
