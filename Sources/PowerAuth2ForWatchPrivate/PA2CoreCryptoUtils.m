/*
 * Copyright 2021 Wultra s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// PA2_SHARED_SOURCE PowerAuth2ForWatch private
// PA2_SHARED_SOURCE PowerAuth2ForExtensions private

#import "PA2CoreCryptoUtils.h"
#import "PowerAuthLog.h"

#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>

@implementation PA2CoreCryptoUtils

static NSData * _CalculateHash(NSData * data, const EVP_MD * md, size_t out_size)
{
    NSMutableData * hash = [NSMutableData dataWithLength:out_size];
    EVP_MD_CTX * ctx = NULL;
    BOOL success = NO;
    do {
        if (!(ctx = EVP_MD_CTX_new())) {
            break;
        }
        if (1 != EVP_DigestInit(ctx, md)) {
            break;
        }
        if (data) {
            if (1 != EVP_DigestUpdate(ctx, data.bytes, data.length)) {
                break;
            }
        }
        if (1 != EVP_DigestFinal(ctx, hash.mutableBytes, NULL)) {
            break;
        }
        success = YES;
    } while (false);
    if (ctx) EVP_MD_CTX_free(ctx);
    return success ? hash : nil;
}

static NSData * _CalculateMac(NSData * data, NSData * key, NSData * custom,
                              const char * alg, const char * md,
                              size_t out_size)
{
    BOOL success = NO;
    NSMutableData * result = [NSMutableData dataWithLength:out_size];
    EVP_MAC * mac = NULL;
    EVP_MAC_CTX * ctx = NULL;
    OSSL_PARAM_BLD * builder = NULL;
    OSSL_PARAM * params = NULL;
    do {
        // Fetch MAC & prepare CTX object
        if (!(mac = EVP_MAC_fetch(NULL, alg, NULL))) {
            break;
        }
        if (!(ctx = EVP_MAC_CTX_new(mac))) {
            break;
        }
        // Parametrize MAC with params builder
        if (!(builder = OSSL_PARAM_BLD_new())) {
            break;
        }
        if (md) {
            OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_MAC_PARAM_DIGEST,
                                            md, strlen(md));
        }
        if (custom) {
            OSSL_PARAM_BLD_push_octet_string(builder, OSSL_MAC_PARAM_CUSTOM,
                                             custom.bytes, custom.length);
        }
        OSSL_PARAM_BLD_push_size_t(builder, OSSL_MAC_PARAM_SIZE, out_size);
        // Initialize params
        if (!(params = OSSL_PARAM_BLD_to_param(builder))) {
            break;
        }
        // Initialize MAC CTX
        if (!EVP_MAC_init(ctx, key.bytes, key.length, params)) {
            break;
        }
        // Update MAC
        if (!EVP_MAC_update(ctx, data.bytes, data.length)) {
            break;
        }
        // Finalize MAC calculation
        size_t mac_length;
        if (!EVP_MAC_final(ctx, result.mutableBytes, &mac_length, result.length)) {
            break;
        }
        if (mac_length != out_size) {
            break;
        }
        success = YES;
    } while (false);
    if (params) OSSL_PARAM_free(params);
    if (builder) OSSL_PARAM_BLD_free(builder);
    if (ctx) EVP_MAC_CTX_free(ctx);
    if (mac) EVP_MAC_free(mac);
    return success ? result : nil;
}

+ (nullable NSData*) hashSha256:(nullable NSData*)data
{
    return _CalculateHash(data, EVP_sha256(), 32);
}

+ (nullable NSData*) hmacSha256:(nullable NSData*)data
                            key:(nonnull NSData*)key
{
    return _CalculateMac(data, key, NULL, "HMAC", "SHA-256", 32);
}

+ (nullable NSData*) kmac256:(nullable NSData*)data
                         key:(nonnull NSData*)key
                      custom:(nonnull NSData*)custom
                        size:(NSUInteger)size
{
    return _CalculateMac(data, key, custom, "KMAC-256", NULL, size);
}

+ (nullable NSData*) randomBytes:(NSUInteger)count
{
    if (count == 0) {
        return nil;
    }
    NSMutableData * data = [NSMutableData dataWithLength:count];
    size_t attempts = 16;
    while (1) {
        if (1 == RAND_bytes(data.mutableBytes, (int)data.length)) {
            break;
        }
        if (--attempts == 0) {
            data = nil;
            break;
        }
    }
    return data;
}

+ (nullable NSData*) hashSha3_256:(nullable NSData*)data
{
    return _CalculateHash(data, EVP_sha3_256(), 32);
}

@end
