/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CM_RDB_OPEN_CALLBACK_H
#define CM_RDB_OPEN_CALLBACK_H

#include "rdb_open_callback.h"

#include "cm_rdb_config.h"

namespace OHOS {
namespace Security {
namespace CertManager {
class CmRdbOpenCallback : public NativeRdb::RdbOpenCallback {
public:
    CmRdbOpenCallback(const RdbConfig &rdbConfig);
    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;
    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion) override;
    int32_t OnDowngrade(NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion) override;
    int32_t OnOpen(NativeRdb::RdbStore &rdbStore) override;

private:
    RdbConfig rdbConfig_;
};
} // namespace CertManager
} // namespace Security
} // namespace OHOS

#endif // CM_RDB_OPEN_CALLBACK_H