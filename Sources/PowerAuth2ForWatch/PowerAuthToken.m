/**
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

// PA2_SHARED_SOURCE PowerAuth2ForWatch .
// PA2_SHARED_SOURCE PowerAuth2ForExtensions .

#import <PowerAuth2ForWatch/PowerAuthToken.h>
#import <PowerAuth2ForWatch/PowerAuthAuthorizationHttpHeader.h>
#import <PowerAuth2ForWatch/PowerAuthLog.h>

#import "PA2PrivateTokenInterfaces.h"
#import "PA2PrivateTokenData.h"

// Extensions/watchOS SDK
#import "PA2CoreCryptoUtils.h"

@implementation PowerAuthToken
{
    PA2PrivateTokenData * _tokenData;
    __weak id<PowerAuthPrivateTokenStore> _tokenStore;
}

#pragma mark - Public getters

- (PA2PrivateTokenData*) privateTokenData
{
    return _tokenData;
}

- (NSString*) tokenName
{
    return _tokenData.name;
}

- (NSString*) tokenIdentifier
{
    return _tokenData.identifier;
}

- (BOOL) isValid
{
    return _tokenData != nil;
}

- (BOOL) canGenerateHeader
{
    return _tokenData != nil && [_tokenStore canGenerateHeaderForToken:self];
}

#pragma mark - Public methods

- (PowerAuthAuthorizationHttpHeader*) generateHeader
{
    if (!self.canGenerateHeader) {
#if defined(DEBUG)
        if (!self.isValid) {
            PowerAuthLog(@"PowerAuthToken: Token contains invalid data.");
        } else {
            PowerAuthLog(@"PowerAuthToken: The associated token store has no longer valid activation.");
        }
#endif
        return nil;
    }
    NSString * version = _tokenStore.protocolVersion;
    NSString * algorithm = _tokenStore.algorithm;
    if (!version || !algorithm) {
        PowerAuthLog(@"PowerAuthToken: Protocol version or algorithm is unknown.");
        return nil;
    }

    NSData * tokenSecret = nil;
    NSString * tokenIdentifier = nil;
    
    tokenSecret = _tokenData.secret;
    tokenIdentifier = _tokenData.identifier;

    // Prepare data for HMAC
    NSNumber * currentTimeMs = @((int64_t)([[NSDate date] timeIntervalSince1970] * 1000));
    NSString * currentTimeString = [currentTimeMs stringValue];
    NSData * currentTimeData = [currentTimeString dataUsingEncoding:NSASCIIStringEncoding];
    NSData * versionData = [version dataUsingEncoding:NSASCIIStringEncoding];
    NSData * nonce = [PA2CoreCryptoUtils randomBytes:16];
    if (!nonce) {
        PowerAuthLog(@"PowerAuthToken: Failed to generate nonce.");
        return nil;
    }
    NSMutableData * data = [nonce mutableCopy];
    [data appendBytes:"&" length:1];
    [data appendData:currentTimeData];
    [data appendBytes:"&" length:1];
    [data appendData:versionData];
    
    // Calculate digest...
    NSData * digest;
    if ([@"LEGACY_P256" isEqualToString:algorithm]) {
        // V3
        digest = [PA2CoreCryptoUtils hmacSha256:data
                                            key:tokenSecret];
    } else {
        // V4
        digest = [PA2CoreCryptoUtils kmac256:data
                                         key:tokenSecret
                                      custom:[@"PA4DIGEST" dataUsingEncoding:NSASCIIStringEncoding]
                                        size:32];
    }
    if (!digest) {
        PowerAuthLog(@"PowerAuthToken: Digest calculation did fail.");
        return nil;
    }
    NSString * digestBase64 = [digest base64EncodedStringWithOptions:0];
    NSString * nonceBase64 = [nonce base64EncodedStringWithOptions:0];
    NSString * value = [NSString stringWithFormat:
                        @"PowerAuth version=\"%@\""
                        @", token_id=\"%@\""
                        @", token_digest=\"%@\""
                        @", nonce=\"%@\""
                        @", timestamp=\"%@\"",
                        _version, tokenIdentifier, digestBase64, nonceBase64, currentTimeString];
    return [PowerAuthAuthorizationHttpHeader tokenHeaderWithValue:value];
}

- (BOOL) isEqualToToken:(nonnull PowerAuthToken*)token
{
    if (token == self) {
        return YES;
    }
    if (_tokenStore != token.tokenStore || !_tokenData) {
        return NO;
    }
    return [_tokenData isEqualToTokenData:token.privateTokenData];
}

#pragma mark - Copying

- (id) copyWithZone:(NSZone *)zone
{
    return [[PowerAuthToken alloc] initWithStore:_tokenStore
                                            data:[_tokenData copy]];
}

#pragma mark - Private methods

- (id) init
{
    return nil;
}

- (id) initWithStore:(id<PowerAuthPrivateTokenStore>)store
                data:(PA2PrivateTokenData*)data
{
    self = [super init];
    if (self) {
        _tokenStore = store;
        _algorithm = store.algorithm;
        _version = store.protocolVersion;
        _tokenData = data;
    }
    return self;
}

- (id<PowerAuthTokenStore>) tokenStore
{
    return _tokenStore;
}

#pragma mark - Debug

#if defined(DEBUG)
- (NSString*) description
{
    return [NSString stringWithFormat:@"<PowerAuthToken name='%@' identifier='%@' canGenerateHeader=%@>",
            self.tokenName,
            self.tokenIdentifier,
            @(self.canGenerateHeader)];
}
#endif // DEBUG

@end
