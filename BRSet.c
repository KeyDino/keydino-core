//
//  BRSet.c
//
//  Created by Aaron Voisine on 9/11/15.
//  Copyright (c) 2015 breadwallet LLC
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#include "BRSet.h"
#include <stdlib.h>
#include <string.h>

// linear probed hash table for good cache performance, maximum load factor is 2/3

static const size_t tableSizes[] = { // starting with 1, multiply by 3/2, round up and find next largest prime
    1, 3, 7, 13, 23, 37, 59, 97, 149, 227, 347, 523, 787, 1187, 1783, 2677, 4019, 6037, 9059, 13591, 20389, 30593,
    45887, 68863, 103307, 154981, 232487, 348739, 523129, 784697, 1177067, 1765609, 2648419, 3972643, 5958971, 8938469,
    13407707, 20111563, 30167359, 45251077, 67876637, 101814991, 152722489, 229083739, 343625629, 515438447, 773157683,
    1159736527, 1739604799, 2609407319, 3914111041
};

static int removed = 1; // placeholder for removed items

struct _BRSet {
    void **table; // hash table
    size_t sizeIdx; // index into tableSizes[]
    size_t count; // number of items in set
    size_t (*hash)(const void *); // hash function
    int (*eq)(const void *, const void *); // equality function
};

void BRSetInit(BRSet *set, size_t (*hash)(const void *), int (*eq)(const void *, const void *), size_t capacity)
{
    size_t i = 0;
    
    while (i < sizeof(tableSizes)/sizeof(*tableSizes) && tableSizes[i] < capacity) i++;
    if (i + 1 < sizeof(tableSizes)/sizeof(*tableSizes)) set->table = calloc(tableSizes[i + 1], sizeof(void *));
    set->sizeIdx = i + 1;
    set->hash = hash;
    set->eq = eq;
}

BRSet *BRSetNew(size_t (*hash)(const void *), int (*eq)(const void *, const void *), size_t capacity)
{
    BRSet *set = calloc(1, sizeof(BRSet));
    
    if (set) {
        BRSetInit(set, hash, eq, capacity);
        if (! set->table) free(set), set = NULL;
    }
    
    return set;
}

void BRSetGrow(BRSet *set, size_t capacity)
{
    BRSet newSet;
    
    BRSetInit(&newSet, set->hash, set->eq, capacity);
    BRSetUnion(&newSet, set);
    free(set->table);
    set->table = newSet.table;
    set->sizeIdx = newSet.sizeIdx;
}

inline size_t BRSetCount(BRSet *set)
{
    return set->count;
}

void BRSetAdd(BRSet *set, void *item)
{
    size_t size = tableSizes[set->sizeIdx];
    size_t i = set->hash(item) % size;
    
    while (set->table[i] && set->table[i] != &removed && ! set->eq(set->table[i], item)) i = (i + 1) % size;
    if (! set->table[i] || set->table[i] == &removed) set->count++;
    set->table[i] = item;
    if (set->count > ((size + 2)/3)*2) BRSetGrow(set, size);
}

void BRSetRemove(BRSet *set, const void *item)
{
    size_t size = tableSizes[set->sizeIdx];
    size_t i = set->hash(item) % size;
    
    while (set->table[i] && (set->table[i] == &removed || ! set->eq(set->table[i], item))) i = (i + 1) % size;
    if (set->table[i]) set->count--, set->table[i] = &removed;
}

void BRSetClear(BRSet *set)
{
    memset(set->table, 0, tableSizes[set->sizeIdx]);
    set->count = 0;
}

int BRSetContains(BRSet *set, const void *item)
{
    return (BRSetGet(set, item) != NULL);
}

void *BRSetGet(BRSet *set, const void *item)
{
    size_t size = tableSizes[set->sizeIdx];
    size_t i = set->hash(item) % size;
    
    while (set->table[i] && (set->table[i] == &removed || ! set->eq(set->table[i], item))) i = (i + 1) % size;
    return set->table[i];
}

void *BRSetFirst(BRSet *set)
{
    size_t size = tableSizes[set->sizeIdx], i = 0;
    
    while (i < size && (! set->table[i] || set->table[i] == &removed)) i++;
    return (i < size) ? set->table[i] : NULL;
}

void *BRSetNext(BRSet *set, const void *item)
{
    size_t size = tableSizes[set->sizeIdx];
    size_t i = set->hash(item) % size;
    
    while (set->table[i] && (set->table[i] == &removed || ! set->eq(set->table[i], item))) i = (i + 1) % size;
    do { i++; } while (i < size && (! set->table[i] || set->table[i] == &removed));
    return (i < size) ? set->table[i] : NULL;
}

void BRSetUnion(BRSet *set, const BRSet *otherSet)
{
    size_t size = tableSizes[otherSet->sizeIdx], i;
    
    if (otherSet->count > ((tableSizes[set->sizeIdx] + 2)/3)*2) BRSetGrow(set, otherSet->count);
    
    for (i = 0; i < size; i++) {
        if (otherSet->table[i] && otherSet->table[i] != &removed) BRSetAdd(set, otherSet->table[i]);
    }
}

void BRSetMinus(BRSet *set, const BRSet *otherSet)
{
    size_t size = tableSizes[otherSet->sizeIdx], i;
    
    for (i = 0; i < size; i++) {
        if (otherSet->table[i] && otherSet->table[i] != &removed) BRSetRemove(set, otherSet->table[i]);
    }
}

void BRSetFree(BRSet *set)
{
    free(set->table);
    free(set);
}