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

#ifndef RED_BLACK_TREE_H
#define RED_BLACK_TREE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t RbTreeKey;
typedef void* RbTreeValue;
typedef void (*RbTreeNodeHandler)(RbTreeKey key, RbTreeValue value, const void *context);

typedef int (*RbTreeValueEncoder)(RbTreeValue value, uint8_t *buf, uint32_t *size);
typedef int (*RbTreeValueDecoder)(RbTreeValue *value, const uint8_t *buf, uint32_t size);
typedef void (*RbTreeValueFree)(RbTreeValue *value);

enum TraverseOrder {
    IN, PRE, POST
};

struct RbTreeNode {
    RbTreeKey key;
    RbTreeValue value;
    struct RbTreeNode *p;
    struct RbTreeNode *left;
    struct RbTreeNode *right;
};

struct RbTree {
    struct RbTreeNode *nil;
    struct RbTreeNode *root;
};

int RbTreeNew(struct RbTree *t);

RbTreeKey RbTreeNodeKey(const struct RbTreeNode *n);

int32_t RbTreeDelete(struct RbTree *t, struct RbTreeNode *z);

int32_t RbTreeInsert(struct RbTree *t, RbTreeKey key, const RbTreeValue value);

int32_t RbTreeFindNode(struct RbTreeNode **nodePtr, RbTreeKey key, const struct RbTree *tree);

int32_t RbTreeDecode(struct RbTree *t, RbTreeValueDecoder dec, RbTreeValueFree freeFunc,
    uint8_t *buf, uint32_t size);

int32_t RbTreeEncode(const struct RbTree *t, RbTreeValueEncoder enc, uint8_t *buf, uint32_t *size);

void RbTreeDestroyEx(struct RbTree *t, RbTreeNodeHandler freeFunc);

#ifdef __cplusplus
}
#endif
#endif