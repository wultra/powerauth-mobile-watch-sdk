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

#import <PowerAuth2ForWatch/PowerAuthKeychain.h>
#import <PowerAuth2ForWatch/PowerAuthLog.h>

#import "PA2PrivateMacros.h"

#if !defined(PA2_EXTENSION_SDK) && defined(PA2_BIOMETRY_SUPPORT)
// LA is not available for watchOS or Extensions
#import <LocalAuthentication/LocalAuthentication.h>
#include <pthread.h>
#endif

@implementation PowerAuthKeychain {
    NSDictionary *_baseQuery;
}

#pragma mark - Initializer

- (instancetype) initWithIdentifier:(NSString*)identifier
{
    return [self initWithIdentifier:identifier accessGroup:nil];
}

- (instancetype) initWithIdentifier:(NSString*)identifier accessGroup:(NSString*)accessGroup
{
    self = [super init];
    if (self) {
        _identifier = identifier;
        _accessGroup = accessGroup;
        _baseQuery = [NSMutableDictionary dictionary];
        [_baseQuery setValue:(__bridge id)kSecClassGenericPassword  forKey:(__bridge id)kSecClass];
        [_baseQuery setValue:_identifier                            forKey:(__bridge id)kSecAttrService];
        [_baseQuery setValue:@YES                                   forKey:(__bridge id)kSecReturnData];
#if !TARGET_OS_SIMULATOR
        if (_accessGroup != nil) {
            [_baseQuery setValue:_accessGroup                       forKey:(__bridge id)kSecAttrAccessGroup];
        }
#endif
    }
    return self;
}

#pragma mark - Adding a new records

- (PowerAuthKeychainStoreItemResult) addValue:(NSData *)data forKey:(NSString *)key
{
    return [self addValue:data forKey:key access:PowerAuthKeychainItemAccess_None];
}

- (PowerAuthKeychainStoreItemResult) addValue:(nonnull NSData*)data forKey:(nonnull NSString*)key access:(PowerAuthKeychainItemAccess)access
{
    if ([self containsDataForKey:key]) {
        return PowerAuthKeychainStoreItemResult_Duplicate;
    }
    return [self implAddValue:data forKey:key access:access];
}


#pragma mark - Updating existing records

- (PowerAuthKeychainStoreItemResult)updateValue:(NSData *)data forKey:(NSString *)key
{
    if ([self containsDataForKey:key]) {
        return [self implUpdateValue:data forKey:key];
    } else {
        return PowerAuthKeychainStoreItemResult_NotFound;
    }
}

#pragma mark - Removing records

- (BOOL)deleteDataForKey:(NSString *)key
{
    NSMutableDictionary *query = [_baseQuery mutableCopy];
    [query setValue:key forKey:(__bridge id)kSecAttrAccount];
    return SecItemDelete((__bridge CFDictionaryRef)(query)) == errSecSuccess;
}

+ (void) deleteAllData
{
    NSArray *secItemClasses = @[(__bridge id)kSecClassGenericPassword,
                                (__bridge id)kSecClassInternetPassword,
                                (__bridge id)kSecClassCertificate,
                                (__bridge id)kSecClassKey,
                                (__bridge id)kSecClassIdentity];
    for (id secItemClass in secItemClasses) {
        NSDictionary *spec = @{(__bridge id)kSecClass: secItemClass};
        SecItemDelete((__bridge CFDictionaryRef)spec);
    }
}

- (void) deleteAllData
{
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    [query setValue:_identifier                             forKey:(__bridge id)kSecAttrService];
    [query setValue:(__bridge id)kSecClassGenericPassword   forKey:(__bridge id)kSecClass];
    SecItemDelete((__bridge CFDictionaryRef)(query));
}

#pragma mark - Obtaining record information

- (NSData*) dataForKey:(NSString *)key status:(OSStatus *)status
{
    return [self dataForKey:key status:status authentication:nil];
}

- (NSData*) dataForKey:(NSString *)key status:(OSStatus *)status authentication:(PowerAuthKeychainAuthentication *)authentication
{
    // Build query
    NSMutableDictionary *query = [_baseQuery mutableCopy];
    [query setValue:key forKey:(__bridge id)kSecAttrAccount];
    
    // Add authentication for items protected with biometry.
    if (authentication) {
        if (!_AddKeychainAuthentication(query, authentication, status)) {
            return nil;
        }
    }
    
    // Obtain data and return result
    CFTypeRef dataTypeRef = NULL;
    OSStatus s = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &dataTypeRef);
    if (status != NULL) {
        *status = s;
    }
    if (s == errSecSuccess) {
        return (__bridge_transfer NSData *)dataTypeRef;
    }
    else {
        return nil;
    }
}


static BOOL _AddKeychainAuthentication(NSMutableDictionary * query, PowerAuthKeychainAuthentication * auth, OSStatus * status)
{
    // PowerAuthKeychainAuthentication is not supported on this platform.
    PowerAuthLog(@"PowerAuthKeychainAuthentication is not supported.");
    if (status) { *status = errSecUnimplemented; }
    return NO;
}

static void _AddUseNoAuthenticationUI(NSMutableDictionary * query)
{
    query[(__bridge id)kSecUseAuthenticationUI] = (__bridge id)kSecUseAuthenticationUIFail;
}

- (BOOL) containsDataForKey:(NSString *)key
{
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    [query setValue:_identifier                             forKey:(__bridge id)kSecAttrService];
    [query setValue:(__bridge id)kSecClassGenericPassword   forKey:(__bridge id)kSecClass];
    [query setValue:key                                     forKey:(__bridge id)kSecAttrAccount];
    _AddUseNoAuthenticationUI(query);
#if !TARGET_OS_SIMULATOR
    if (_accessGroup != nil) {
        [query setValue:_accessGroup                        forKey:(__bridge id)kSecAttrAccessGroup];
    }
#endif
    
    CFTypeRef dataTypeRef = NULL;
    OSStatus const status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &dataTypeRef);
    if (status == errSecItemNotFound
        || status == errSecUnimplemented
        || status == errSecParam
        || status == errSecUserCanceled
        || status == errSecBadReq
        || status == errSecNotAvailable
        || status == errSecDecode) {
        return NO;
    } else {
        return YES;
    }
}


#pragma mark - Data in-memory caching

- (NSDictionary*) allItemsWithAuthentication:(PowerAuthKeychainAuthentication *)authentication withStatus:(OSStatus *)status
{
    // Build query to return all results
    NSMutableDictionary *query = [_baseQuery mutableCopy];
    [query setObject:(__bridge id)kSecMatchLimitAll forKey:(__bridge id)kSecMatchLimit];
    [query setObject:@YES forKey:(__bridge id)kSecReturnAttributes];

    // Add authentication for items protected with biometry.
    if (authentication) {
        if (!_AddKeychainAuthentication(query, authentication, status)) {
            return nil;
        }
    }

    // Obtain data and return result
    CFTypeRef dataTypeRef = NULL;
    OSStatus s = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &dataTypeRef);
    NSArray *queryResult = (__bridge_transfer NSArray *)dataTypeRef;
    NSMutableDictionary *result = [NSMutableDictionary dictionary];

    if (status != NULL) {
        *status = s;
    }

    if (s == errSecSuccess) {
        for (NSDictionary *const item in queryResult) {
            NSString *key = [item valueForKey:(__bridge id)kSecAttrAccount];
            NSData *value = [item valueForKey:(__bridge id)kSecValueData];
            [result setObject:value forKey:key];
        }
    }
    else {
        return nil;
    }
    return result;
}

- (NSDictionary*) allItems
{
    return [self allItemsWithAuthentication:nil withStatus:nil];
}

#pragma mark - Biometry support

/**
 Returns information about biometric support on the system. This is a special implementation
 returning information that biometry is not supported on watchOS & IOS App Extension.
 */
static PowerAuthBiometricAuthenticationInfo _getBiometryInfo(void)
{
    PowerAuthBiometricAuthenticationInfo info = { PowerAuthBiometricAuthenticationStatus_NotSupported, PowerAuthBiometricAuthenticationType_None };
    return info;
}

/**
 This platform doesn't support biometry, so always return kNilOptions.
 */
static SecAccessControlCreateFlags _getBiometryAccessControlFlags(PowerAuthKeychainItemAccess access)
{
    return kNilOptions;
}

/**
 Do nothing on watchOS or when the class is running in app extension.
 */
+ (BOOL) tryLockBiometryAndExecuteBlock:(void (^_Nonnull)(void))block
{
    return NO;
}

//
// High level biometry interfaces
//

+ (BOOL) canUseBiometricAuthentication
{
    // The behavior of this property is that it returns YES, only if biometry policy can be evaluated.
    return NO;
}

+ (PowerAuthBiometricAuthenticationType) supportedBiometricAuthentication
{
    PowerAuthBiometricAuthenticationInfo info = _getBiometryInfo();
    // The behavior of this property is that if the biometry policy cannot be evaluated, then returns "None".
    if (info.currentStatus == PowerAuthBiometricAuthenticationStatus_Available) {
        return info.biometryType;
    }
    return PowerAuthBiometricAuthenticationType_None;
}

+ (PowerAuthBiometricAuthenticationInfo) biometricAuthenticationInfo
{
    return _getBiometryInfo();
}

#pragma mark - Private methods

static BOOL _AddAccessControlObject(NSMutableDictionary * dictionary, BOOL isAddOperation, PowerAuthKeychainItemAccess access)
{
#if TARGET_OS_SIMULATOR
    //
    // Workaround for bug in iOS13 simulator (Xcode 11)
    //
    // iOS13 simulator are not able to store the data to keychain when AC object is present in the query.
    // In this case, we simply skip this step.
    //
    // Associated ticket: https://github.com/wultra/powerauth-mobile-sdk/issues/248
    //
    if (@available(iOS 13, *)) {
        return YES;
    }
#endif
    SecAccessControlCreateFlags flags;
    if (isAddOperation) {
        // For add operation, translate requested access to control flags.
        flags = _getBiometryAccessControlFlags(access);
    } else {
        // For update operation, or if biometry is not requested, use the kNilOptions.
        flags = kNilOptions;
    }
    // Create access control object
    CFErrorRef error = NULL;
    SecAccessControlRef sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, flags, &error);
    if (sacObject == NULL || error != NULL) {
        // make sure to release the object
        if (sacObject != NULL) {
            CFRelease(sacObject);
        }
        return NO;
    }
    // Add the access control constraint to the query.
    [dictionary setValue:(__bridge_transfer id)sacObject forKey:(__bridge id)kSecAttrAccessControl];
    return YES;
}

- (PowerAuthKeychainStoreItemResult) implAddValue:(NSData*)data forKey:(NSString*)key access:(PowerAuthKeychainItemAccess)access
{
    // Return if iOS version is lower than iOS 9.0 - we cannot securely store a biometric key here.
    // Call is moved here so that we spare further object allocations.
    if (access != PowerAuthKeychainItemAccess_None) {
        if (![PowerAuthKeychain canUseBiometricAuthentication]) {
            return PowerAuthKeychainStoreItemResult_BiometryNotAvailable;
        }
    }
    
    // Build default query with base data.
    NSMutableDictionary *query = [_baseQuery mutableCopy];
    [query setValue:key     forKey:(__bridge id)kSecAttrAccount];
    [query setValue:data    forKey:(__bridge id)kSecValueData];
    _AddUseNoAuthenticationUI(query);
    if (!_AddAccessControlObject(query, YES, access)) {
        return PowerAuthKeychainStoreItemResult_Other;
    }
    
    // Return result of kechain item add.
    OSStatus keychainResult = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    switch (keychainResult) {
        case errSecDuplicateItem:
            return PowerAuthKeychainStoreItemResult_Duplicate;
        case errSecSuccess:
            return PowerAuthKeychainStoreItemResult_Ok;
        default:
            return PowerAuthKeychainStoreItemResult_Other;
    }
}

- (PowerAuthKeychainStoreItemResult) implUpdateValue:(NSData*)data forKey:(NSString*)key
{
    // Build default query with base data.
    NSMutableDictionary *query = [NSMutableDictionary dictionary];
    [query setValue:(__bridge id)kSecClassGenericPassword   forKey:(__bridge id)kSecClass];
    [query setValue:_identifier                             forKey:(__bridge id)kSecAttrService];
    [query setValue:key                                     forKey:(__bridge id)kSecAttrAccount];
#if !TARGET_OS_SIMULATOR
    if (_accessGroup != nil) {
        [query setValue:_accessGroup                        forKey:(__bridge id)kSecAttrAccessGroup];
    }
#endif
    
    // Data to be updated.
    NSMutableDictionary *dictionary = [NSMutableDictionary dictionary];
    [dictionary setValue:_identifier                        forKey:(__bridge id)kSecAttrService];
    [dictionary setValue:key                                forKey:(__bridge id)kSecAttrAccount];
    [dictionary setValue:data                               forKey:(__bridge id)kSecValueData];
    if (!_AddAccessControlObject(dictionary, NO, PowerAuthKeychainItemAccess_None)) {
        return PowerAuthKeychainStoreItemResult_Other;
    }
    
    // Return result of keychain item update.
    OSStatus keychainResult =  SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)dictionary);
    switch (keychainResult) {
        case errSecItemNotFound:
            return PowerAuthKeychainStoreItemResult_NotFound;
        case errSecSuccess:
            return PowerAuthKeychainStoreItemResult_Ok;
        default:
            return PowerAuthKeychainStoreItemResult_Other;
    }
}

@end
