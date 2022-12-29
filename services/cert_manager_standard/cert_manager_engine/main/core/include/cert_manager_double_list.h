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

#ifndef CERT_MANAGER_DOUBLE_LIST_H
#define CERT_MANAGER_DOUBLE_LIST_H

#include "cm_type.h"

#ifdef __cplusplus
extern "C" {
#endif

struct DoubleList {
    struct DoubleList *prev;
    struct DoubleList *next;
};

void CmInitList(struct DoubleList *listNode);

void CmAddNodeAfterListHead(struct DoubleList *listHead, struct DoubleList *listNode);

void CmAddNodeAtListTail(struct DoubleList *listHead, struct DoubleList *listNode);

void CmRemoveNodeFromList(struct DoubleList *listNode);

#ifdef __cplusplus
}
#endif

/*
 * CM_DLIST_ITER - iterate over double list of struct st, double list should be the first member of struct st
 * @st:        the struct in the double list
 * @head:      the head for double list.
 */
#define CM_DLIST_ITER(st, head) \
    struct DoubleList *p = NULL; \
    for (p = (head)->next, (st) = (__typeof__(st))p; p != (head); p = p->next, (st) = (__typeof__(st))p)

#define CM_DLIST_SAFT_ITER(st, head) \
    struct DoubleList *p = NULL; \
    struct DoubleList tmp = { NULL, NULL }; \
    for (p = (head)->next, (st) = (__typeof__(st))p, tmp = *p; p != (head); \
        p = tmp.next, tmp = *p, (st) = (__typeof__(st))p)

#endif /* CERT_MANAGER_DOUBLE_LIST_H */

