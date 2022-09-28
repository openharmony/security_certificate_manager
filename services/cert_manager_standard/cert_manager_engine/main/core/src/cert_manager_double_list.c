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

#include "cert_manager_double_list.h"

#ifndef NULL
#define NULL ((void *)0)
#endif

void CmInitList(struct DoubleList *listNode)
{
    if (listNode == NULL) {
        return;
    }

    listNode->prev = listNode;
    listNode->next = listNode;
}

void CmAddNodeAfterListHead(struct DoubleList *listHead, struct DoubleList *listNode)
{
    if ((listHead == NULL) || (listNode == NULL)) {
        return;
    }

    if (listHead->next == NULL) {
        listHead->next = listHead;
    }

    listHead->next->prev = listNode;
    listNode->next = listHead->next;
    listNode->prev = listHead;
    listHead->next = listNode;
}

void CmAddNodeAtListTail(struct DoubleList *listHead, struct DoubleList *listNode)
{
    if ((listHead == NULL) || (listNode == NULL)) {
        return;
    }

    if (listHead->prev == NULL) {
        listHead->prev = listHead;
    }

    listHead->prev->next = listNode;
    listNode->next = listHead;
    listNode->prev = listHead->prev;
    listHead->prev = listNode;
}

void CmRemoveNodeFromList(struct DoubleList *listNode)
{
    if (listNode == NULL) {
        return;
    }

    if (listNode->next != NULL) {
        listNode->next->prev = listNode->prev;
    }

    if (listNode->prev != NULL) {
        listNode->prev->next = listNode->next;
    }

    listNode->prev = NULL;
    listNode->next = NULL;
}

