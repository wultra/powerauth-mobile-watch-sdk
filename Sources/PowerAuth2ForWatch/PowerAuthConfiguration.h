/**
 * Copyright 2023 Wultra s.r.o.
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

#import <PowerAuth2ForWatch/PowerAuthSharingConfiguration.h>

/** Class that represents a PowerAuth2ForExtensions or PowerAuth2ForWatch instance configuration.
 */
@interface PowerAuthConfiguration : NSObject<NSCopying>

/// No longer available. Use `init(instanceId:baseEndpointUrl:configuration:)` instead.
- (nonnull instancetype) init NS_UNAVAILABLE;

/// Initialize object with all required parameters.
/// - Parameters:
///   - instanceId: Identifier of the PowerAuthSDK instance, used as a 'key' to store session state in the session state keychain.
///   - baseEndpointUrl: Base URL to the PowerAuth Standard RESTful API (the URL part before "/pa/...").
///   - configuration: String with the cryptographic configuration.
- (nonnull instancetype) initWithInstanceId:(nonnull NSString*)instanceId
                            baseEndpointUrl:(nonnull NSString*)baseEndpointUrl
                              configuration:(nonnull NSString*)configuration;

/** Identifier of the PowerAuthSDK instance, used as a 'key' to store session state in the session state keychain.
 */
@property (nonatomic, strong, nonnull, readonly) NSString *instanceId;

/** Base URL to the PowerAuth Standard RESTful API (the URL part before "/pa/...").
 */
@property (nonatomic, strong, nonnull, readonly) NSString *baseEndpointUrl;

/** String with the cryptographic configuration.
 */
@property (nonatomic, strong, nonnull, readonly) NSString *configuration;

/** This value specifies 'key' used to store this PowerAuthSDK instance biometry related key in the biometry key keychain.
 */
@property (nonatomic, strong, nonnull) NSString *keychainKey_Biometry;

/** Encryption key provided by an external context, used to encrypt possession and biometry related factor keys under the hood.
 */
@property (nonatomic, strong, nullable) NSData  *externalEncryptionKey;

/**
 If set, then this instance of PowerAuthSDK can be shared between multiple vendor applications.
 */
@property (nonatomic, strong, nullable) PowerAuthSharingConfiguration * sharingConfiguration;

/** Validate that the configuration is properly set (all required values were filled in).
 */
- (BOOL) validateConfiguration
            NS_SWIFT_NAME(validate());

@end
