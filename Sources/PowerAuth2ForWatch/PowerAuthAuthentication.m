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

#import "PowerAuthAuthentication.h"
#import "PowerAuthKeychainAuthentication.h"
#import "PowerAuthLog.h"
#import "PowerAuthAuthentication+Private.h"

@implementation PowerAuthAuthentication

- (id) initWithPossession
{
    return [super init];
}

- (BOOL) usePossession
{
    return YES;
}

- (BOOL) useBiometry
{
    return NO;
}

- (NSString*) password
{
    return nil;
}

- (PowerAuthKeychainAuthentication *) keychainAuthentication
{
    return nil;
}

- (NSString*) description
{
    return @"<PowerAuthAuthentication: possession>";
}

@end


@implementation PowerAuthAuthentication (EasyAccessors)

// MARK: - Signing, Possession only

+ (PowerAuthAuthentication *) possession
{
    return [[PowerAuthAuthentication alloc] initWithPossession];
}

@end

@implementation PowerAuthAuthentication (Private)

- (NSInteger) signatureFactorMask
{
    return 1;
}

- (BOOL) validateUsage:(BOOL)forPersist
{
    // Keep for compatibility with shared sources
    return !forPersist;
}

@end
