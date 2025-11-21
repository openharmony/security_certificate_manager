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

#include "hks_param.h"

int32_t HksInitParamSet(struct HksParamSet **paramSet)
{
    return 0;
}

int32_t HksAddParams(struct HksParamSet *paramSet,
    const struct HksParam *params, uint32_t paramCnt)
{
    return 0;
}

int32_t HksAddParamsWithFilter(struct HksParamSet *paramSet,
    const struct HksParam *params, uint32_t paramCnt)
{
    return 0;
}

int32_t HksBuildParamSet(struct HksParamSet **paramSet)
{
    return 0;
}

void HksFreeParamSet(struct HksParamSet **paramSet)
{
    if (paramSet == NULL) {
        return;
    }
    
    if (*paramSet != NULL) {
        free(*paramSet);
        *paramSet = NULL;
    }
}

void HksFreeKeyAliasSet(struct HksKeyAliasSet *aliasSet)
{
    if (aliasSet == NULL) {
        return;
    }
    free(aliasSet);
}

void HksFreeExtCertSet(struct HksExtCertInfoSet *certInfoSet)
{
    if (certInfoSet == NULL) {
        return;
    }
    free(certInfoSet);
}

int32_t HksGetParamSet(const struct HksParamSet *inParamSet, uint32_t inParamSetSize,
    struct HksParamSet **outParamSet)
{
    return 0;
}

int32_t HksGetParam(const struct HksParamSet *paramSet, uint32_t tag, struct HksParam **param)
{
    return 0;
}

int32_t HksFreshParamSet(struct HksParamSet *paramSet, bool isCopy)
{
    return 0;
}

int32_t HksCheckParamSetTag(const struct HksParamSet *paramSet)
{
    return 0;
}

int32_t HksCheckParamSet(const struct HksParamSet *paramSet, uint32_t size)
{
    return 0;
}

int32_t HksCheckParamMatch(const struct HksParam *baseParam, const struct HksParam *param)
{
    return 0;
}

int32_t HksCheckIsTagAlreadyExist(const struct HksParam *params, uint32_t paramsCnt,
    const struct HksParamSet *targetParamSet)
{
    return 0;
}

int32_t HksDeleteTagsFromParamSet(const uint32_t *tag, uint32_t tagCount,
    const struct HksParamSet *paramSet, struct HksParamSet **outParamSet)
{
    return 0;
}