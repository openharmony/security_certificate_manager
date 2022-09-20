/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "cm_asn1.h"
#include "cm_log.h"
#include "securec.h"

#define BIT_NUM_OF_UINT8 8
#define ASN_1_EXPLICIT_TAG_LEN 3
#define ASN_1_EXPLICIT_TAG_TYPE_BOOL 0xA0
#define ASN_1_TAG_TYPE_EXTRA_IDENTIFIER 0x1F
#define TLV_HEADER_TYPE_2_LEN 4
#define BASE128_ENCODE_BIT_LEN 7

static int32_t Asn1GetObj(struct CmBlob *next, struct CmAsn1Obj *obj, const struct CmBlob *data)
{
    uint8_t *buf = data->data;
    uint32_t length = 0;
    obj->header.data = buf;
    CM_ASN1_DECODE_BYTE(buf, obj->header.type);
    if (buf[0] < ASN_1_MIN_VAL_1_EXTRA_LEN_BYTE) {
        CM_ASN1_DECODE_BYTE(buf, length);
    } else {
        uint32_t b;
        CM_ASN1_DECODE_BYTE(buf, b);

        switch (b) {
            case ASN_1_TAG_TYPE_1_BYTE_LEN:
                CM_ASN1_DECODE_BYTE(buf, length);
                break;
            case ASN_1_TAG_TYPE_2_BYTE_LEN:
                if (data->size < ASN_1_MIN_HEADER_LEN + 1) {
                    CM_LOG_E("invalid data to decode two bytes.\n");
                    return CMR_ERROR_INSUFFICIENT_DATA;
                }
                CM_ASN1_DECODE_TWO_BYTE(buf, length);
                break;
            default:
                CM_LOG_E("Object length does not make sense.\n");
                return CMR_ERROR_INVALID_ARGUMENT;
        }
    }
    obj->header.size = buf - data->data;
    if (length > data->size - obj->header.size) {
        CM_LOG_E("data buffer is not big enough to hold %u bytes.\n", length);
        return CMR_ERROR_INSUFFICIENT_DATA;
    }

    obj->value.type = obj->header.type;
    obj->value.size = length;
    obj->value.data = buf;
    next->data = data->data + obj->header.size + obj->value.size;
    next->size = data->size - obj->header.size - obj->value.size;

    return CM_SUCCESS;
}

int32_t CmAsn1ExtractTag(struct CmBlob *next, struct CmAsn1Obj *obj, const struct CmBlob *data,
    uint32_t expectedTag)
{
    if ((next == NULL) || (obj == NULL) || (data == NULL) || (data->size < ASN_1_MIN_HEADER_LEN)) {
        CM_LOG_E("invalid params");
        return CMR_ERROR_INVALID_ARGUMENT;
    }

    int32_t ret = Asn1GetObj(next, obj, data);
    if (ret != CM_SUCCESS) {
        CM_LOG_E("get asn1 obj fail.\n");
        return ret;
    }
    if (obj->header.type != expectedTag) {
        CM_LOG_E("tag %u does not match expected: %u\n", obj->header.type, expectedTag);
        return CM_FAILURE;
    }
    return CM_SUCCESS;
}