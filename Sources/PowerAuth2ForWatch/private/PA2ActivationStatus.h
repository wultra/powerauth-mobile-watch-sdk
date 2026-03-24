/*
 * Copyright 2026 Wultra s.r.o.
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

#import "PA2WCSessionPacket_ActivationStatus.h"

/// The `PA2ActivationStatus` class contains activation data stored in the keychain.
@interface PA2ActivationStatus : NSObject

@property (nonatomic, readonly) NSUInteger dataVersion;
@property (nonatomic, strong, readonly, nullable) NSString * activationId;
@property (nonatomic, strong, readonly, nullable) NSString * protocolVersion;
@property (nonatomic, strong, readonly, nullable) NSString * algorithm;

/// Serialize object to data.
- (nonnull NSData*) toData;

/// Deserialize object from data.
/// - Parameter data: Previously serialized data.
+ (nonnull PA2ActivationStatus*) fromData:(nullable NSData*)data;

/// Create object from received status packet. If `nil` is provided, then creates an empty object.
/// - Parameter status: Received status packet.
+ (nonnull PA2ActivationStatus*) fromPacket:(nullable PA2WCSessionPacket_ActivationStatus*)status;

- (BOOL) isEqual:(nullable id)object;

@end

