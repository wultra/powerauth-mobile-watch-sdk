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

// Do not edit this file in PowerAuth2ForWatch project. Use version in
// PowerAuht2ForExtensions and the shared file will be copied in the next
// copy-shared-sources.sh run.

#import <PowerAuth2ForWatch/PowerAuthAuthentication.h>
#import <PowerAuth2ForWatch/PowerAuthKeychainAuthentication.h>
#import <PowerAuth2ForWatch/PowerAuthLog.h>
#import "PowerAuthAuthentication+Private.h"

@implementation PowerAuthAuthentication

- (id) initWithPassword:(NSString*)password
               biometry:(BOOL)biometry
         biometryPrompt:(NSString*)biometryPrompt
        biometryContext:(id)biometryContext
    customPossessionKey:(NSData*)customPossessionKey
      customBiometryKey:(NSData*)customBiometryKey
{
    self = [super init];
    if (self) {
        _usePossession = YES;
        _password = password;
        _useBiometry = biometry;
        _biometryPrompt = biometryPrompt;
        _biometryContext = biometryContext;
        _overridenPossessionKey = customPossessionKey;
        _overridenBiometryKey = customBiometryKey;
    }
    return self;
}

- (PowerAuthKeychainAuthentication *) keychainAuthentication
{
#if PA2_HAS_LACONTEXT == 1
    if (_biometryContext) {
        return [[PowerAuthKeychainAuthentication alloc] initWithContext:_biometryContext];
    }
#endif // PA2_HAS_LACONTEXT
    if (_biometryPrompt) {
        return [[PowerAuthKeychainAuthentication alloc] initWithPrompt:_biometryPrompt];
    }
    return nil;
}

#if DEBUG
- (NSString*) description
{
    NSMutableArray * factors = [NSMutableArray arrayWithCapacity:3];
    if (_usePossession) {
        [factors addObject:@"possession"];
    }
    if (_password) {
        [factors addObject:@"knowledge"];
    }
    if (_useBiometry) {
        [factors addObject:@"biometry"];
    }
    NSString * factors_str = [factors componentsJoinedByString:@"_"];
    NSMutableArray * info = [NSMutableArray array];
    if (_biometryPrompt) {
        [info addObject:@"+prompt"];
    }
#if PA2_HAS_LACONTEXT == 1
    if (_biometryContext) {
        [info addObject:@"+context"];
    }
#endif
    if (_overridenBiometryKey) {
        [info addObject:@"+extBK"];
    }
    if (_overridenPossessionKey) {
        [info addObject:@"+extPK"];
    }
    NSString * info_str = info.count == 0 ? @"" : [@", " stringByAppendingString:[info componentsJoinedByString:@" "]];
    return [NSString stringWithFormat:@"<PowerAuthAuthentication: %@%@>", factors_str, info_str];
}
#endif

@end


@implementation PowerAuthAuthentication (EasyAccessors)

// MARK: - Signing, Possession only

+ (PowerAuthAuthentication *) possession
{
    return [[PowerAuthAuthentication alloc] initWithPassword:nil
                                                    biometry:NO
                                              biometryPrompt:nil
                                             biometryContext:nil
                                         customPossessionKey:nil
                                           customBiometryKey:nil];
}

+ (PowerAuthAuthentication *) possessionWithCustomPossessionKey:(NSData*)customPossessionKey
{
    return [[PowerAuthAuthentication alloc] initWithPassword:nil
                                                    biometry:NO
                                              biometryPrompt:nil
                                             biometryContext:nil
                                         customPossessionKey:customPossessionKey
                                           customBiometryKey:nil];
}

// MARK: Signing, Possession + Biometry

+ (PowerAuthAuthentication *) possessionWithBiometry
{
    return [[PowerAuthAuthentication alloc] initWithPassword:nil
                                                    biometry:YES
                                              biometryPrompt:nil
                                             biometryContext:nil
                                         customPossessionKey:nil
                                           customBiometryKey:nil];
}

+ (PowerAuthAuthentication *) possessionWithBiometryPrompt:(NSString*)biometryPrompt
{
    return [[PowerAuthAuthentication alloc] initWithPassword:nil
                                                    biometry:YES
                                              biometryPrompt:biometryPrompt
                                             biometryContext:nil
                                         customPossessionKey:nil
                                           customBiometryKey:nil];
}

+ (PowerAuthAuthentication *) possessionWithBiometryPrompt:(NSString*)biometryPrompt
                                       customPossessionKey:(NSData*)customPossessionKey
{
    return [[PowerAuthAuthentication alloc] initWithPassword:nil
                                                    biometry:YES
                                              biometryPrompt:biometryPrompt
                                             biometryContext:nil
                                         customPossessionKey:customPossessionKey
                                           customBiometryKey:nil];
}

+ (PowerAuthAuthentication *) possessionWithBiometryWithCustomBiometryKey:(NSData*)customBiometryKey
                                                      customPossessionKey:(NSData*)customPossessionKey
{
    return [[PowerAuthAuthentication alloc] initWithPassword:nil
                                                    biometry:YES
                                              biometryPrompt:nil
                                             biometryContext:nil
                                         customPossessionKey:customPossessionKey
                                           customBiometryKey:customBiometryKey];
}

#if PA2_HAS_LACONTEXT == 1
+ (PowerAuthAuthentication *) possessionWithBiometryContext:(LAContext *)context
{
    return [[PowerAuthAuthentication alloc] initWithPassword:nil
                                                    biometry:YES
                                              biometryPrompt:nil
                                             biometryContext:context
                                         customPossessionKey:nil
                                           customBiometryKey:nil];
}
+ (PowerAuthAuthentication *) possessionWithBiometryContext:(LAContext*)context
                                        customPossessionKey:(NSData*)customPossessionKey
{
    return [[PowerAuthAuthentication alloc] initWithPassword:nil
                                                    biometry:YES
                                              biometryPrompt:nil
                                             biometryContext:context
                                         customPossessionKey:customPossessionKey
                                           customBiometryKey:nil];
}
#endif // PA2_HAS_LACONTEXT

// MARK: Signing, Possession + Knowledge

+ (PowerAuthAuthentication *) possessionWithPassword:(NSString *)password
{
    return [[PowerAuthAuthentication alloc] initWithPassword:password
                                                    biometry:NO
                                              biometryPrompt:nil
                                             biometryContext:nil
                                         customPossessionKey:nil
                                           customBiometryKey:nil];
}

+ (PowerAuthAuthentication *) possessionWithPassword:(NSString*)password
                                 customPossessionKey:(NSData*)customPossessionKey
{
    return [[PowerAuthAuthentication alloc] initWithPassword:password
                                                    biometry:NO
                                              biometryPrompt:nil
                                             biometryContext:nil
                                         customPossessionKey:customPossessionKey
                                           customBiometryKey:nil];
}

@end


@implementation PowerAuthAuthentication (Private)

- (NSInteger) signatureFactorMask
{
    NSUInteger result = 0;
    if (_usePossession) result |= 1;
    if (_password)      result |= 2;
    if (_useBiometry)   result |= 4;
    return result;
}

- (BOOL) validateUsage:(BOOL)forPersist
{
    // Keep for compatibility with shared sources
    return !forPersist;
}

@end
