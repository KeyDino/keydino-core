//
//  BRBase32.h
//  keydino-core
//
//  Created by Brendan E. Mahon on 1/18/18.
//  Copyright © 2018 KeyDino LLC. All rights reserved.
//

#ifndef BRBase32_h
#define BRBase32_h

#include <stdio.h>
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif
    
// base32 and base32check encoding: https://github.com/Bitcoin-UAHF/spec/blob/master/cashaddr.md
    
// returns the number of characters written to str including NULL terminator, or total strLen needed if str is NULL
size_t BRBase32Encode(char *str, size_t strLen, const uint8_t *data, size_t dataLen);
    
// returns the number of bytes written to data, or total dataLen needed if data is NULL
size_t BRBase32Decode(uint8_t *data, size_t dataLen, const char *str);
    
// returns the number of characters written to str including NULL terminator, or total strLen needed if str is NULL
size_t BRBase32CheckEncode(char *str, size_t strLen, const uint8_t *data, size_t dataLen);
    
// returns the number of bytes written to data, or total dataLen needed if data is NULL
size_t BRBase32CheckDecode(uint8_t *data, size_t dataLen, const char *str);
    

#ifdef __cplusplus
}
#endif

#endif /* BRBase32_h */
