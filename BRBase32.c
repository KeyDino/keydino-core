//
//  BRBase32.c
//  keydino-core
//
//  Created by Brendan E. Mahon on 1/18/18.
//  Copyright © 2018 KeyDino LLC. All rights reserved.
//

#include "BRBase32.h"
#include "BRCrypto.h"
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// base32 and base32check encoding: https://github.com/Bitcoin-UAHF/spec/blob/master/cashaddr.md

static const char base32chars[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// returns the number of characters written to str including NULL terminator, or total strLen needed if str is NULL
size_t BRBase32Encode(char *str, size_t strLen, const uint8_t *data, size_t dataLen)
{
    size_t i, j, len, zcount = 0;
    
    assert(data != NULL);
    while (zcount < dataLen && data && data[zcount] == 0) zcount++; // count leading zeroes
    
    uint8_t buf[(dataLen - zcount)*16/10 + 1]; // log(256)/log(32)
    
    memset(buf, 0, sizeof(buf));
    
    for (i = zcount; data && i < (dataLen); i++) {
        uint32_t carry = data[i];
        
        for (j = sizeof(buf); j > 0; j--) {
            carry += (uint32_t)buf[j - 1] << 8;
            buf[j - 1] = carry % 32;
            carry /= 32;
        }
        
        var_clean(&carry);
    }
    
    i = 0;
    while (i < sizeof(buf) && buf[i] == 0) i++; // skip leading zeroes
    len = (zcount + sizeof(buf) - i) + 1;
    
    if (str && len <= strLen) {
        while (zcount-- > 0) *(str++) = base32chars[0];
        while (i < sizeof(buf)) *(str++) = base32chars[buf[i++]];
        *str = '\0';
    }
    
    mem_clean(buf, sizeof(buf));
    return (! str || len <= strLen) ? len : 0;
}

// returns the number of bytes written to data, or total dataLen needed if data is NULL
size_t BRBase32Decode(uint8_t *data, size_t dataLen, const char *str)
{
    size_t i = 0, j, len, zcount = 0;
    
    assert(str != NULL);
    while (str && *str == base32chars[0]) str++, zcount++; // count leading zeroes
    
    uint8_t buf[(str) ? strlen(str)*625/1000 + 1 : 0]; // log(32)/log(256)
    
    memset(buf, 0, sizeof(buf));
    
    while (str && *str) {
        uint32_t carry = *(const uint8_t *)(str++);
        
        switch (carry) {
            case 'q': case 'p': case 'z': case 'r': case 'y': case '9': case 'x': case '8':
                carry -= 'q';
                break;
                
            case 'g': case 'f': case '2': case 't': case 'v': case 'd': case 'w': case '0':
                carry += 8 - '8';
                break;
                
            case 's': case '3': case 'j': case 'n': case '5': case '4': case 'k': case 'h':
                carry += 16 - '0';
                break;
                
            case 'c': case 'e': case '6': case 'm': case 'u': case 'a': case '7': case 'l':
                carry += 24 - 'h';
                break;
                
            default:
                carry = UINT32_MAX;
        }
        
        if (carry >= 32) break; // invalid base32 digit
        
        for (j = sizeof(buf); j > 0; j--) {
            carry += (uint32_t)buf[j - 1]*32;
            buf[j - 1] = carry & 0xff;
            carry >>= 8;
        }
        
        var_clean(&carry);
    }
    
    while (i < sizeof(buf) && buf[i] == 0) i++; // skip leading zeroes
    len = zcount + sizeof(buf) - i;
    
    if (data && len <= dataLen) {
        if (zcount > 0) memset(data, 0, zcount);
        memcpy(&data[zcount], &buf[i], sizeof(buf) - i);
    }
    
    mem_clean(buf, sizeof(buf));
    return (! data || len <= dataLen) ? len : 0;
}

// returns the number of characters written to str including NULL terminator, or total strLen needed if str is NULL
size_t BRBase32CheckEncode(char *str, size_t strLen, const uint8_t *data, size_t dataLen)
{
    size_t len = 0, bufLen = dataLen + 256/8;
    uint8_t _buf[(bufLen <= 0x1000) ? bufLen : 0], *buf = (bufLen <= 0x1000) ? _buf : malloc(bufLen);
    
    assert(buf != NULL);
    assert(data != NULL || dataLen == 0);
    
    if (data || dataLen == 0) {
        memcpy(buf, data, dataLen);
        BRSHA256_2(&buf[dataLen], data, dataLen);
        len = BRBase32Encode(str, strLen, buf, dataLen + 4);
    }
    
    mem_clean(buf, bufLen);
    if (buf != _buf) free(buf);
    return len;
}

// returns the number of bytes written to data, or total dataLen needed if data is NULL
size_t BRBase32CheckDecode(uint8_t *data, size_t dataLen, const char *str)
{
    size_t len, bufLen = (str) ? strlen(str) : 0;
    uint8_t md[256/8], _buf[(bufLen <= 0x1000) ? bufLen : 0], *buf = (bufLen <= 0x1000) ? _buf : malloc(bufLen);
    
    assert(str != NULL);
    assert(buf != NULL);
    len = BRBase32Decode(buf, bufLen, str);
    
    if (len >= 4) {
        len -= 4;
        BRSHA256_2(md, buf, len);
        if (memcmp(&buf[len], md, sizeof(uint32_t)) != 0) len = 0; // verify checksum
        if (data && len <= dataLen) memcpy(data, buf, len);
    }
    else len = 0;
    
    mem_clean(buf, bufLen);
    if (buf != _buf) free(buf);
    return (! data || len <= dataLen) ? len : 0;
}

//Shelved, CashAddr implemented later
/*
uint64_t PolyMod(char *str, size_t strLen, const uint8_t *data, size_t dataLen)
{
    
    uint64_t c = 1;

    for (uint8_t d : v) {
        uint8_t c0 = c >> 35;
        c = ((c & 0x07ffffffff) << 5) ^ d;
        
        if (c0 & 0x01) c ^= 0x98f2bc8e61;
        if (c0 & 0x02) c ^= 0x79b76d99e2;
        if (c0 & 0x04) c ^= 0xf33e5fb3c4;
        if (c0 & 0x08) c ^= 0xae2eabe2a8;
        if (c0 & 0x10) c ^= 0x1e4f43e470;
    }

    return c ^ 1;
}
*/
