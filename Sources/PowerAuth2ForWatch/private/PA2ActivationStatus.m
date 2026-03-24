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

#import "PA2ActivationStatus.h"
#import "PA2PrivateMacros.h"

#import <PowerAuth2ForWatch/PowerAuthLog.h>

static const NSUInteger DATA_VER = 1;

static NSString * const KEY_DATA_VER        = @"ver";
static NSString * const KEY_PROTOCOL        = @"pro";
static NSString * const KEY_ALGORITHM       = @"alg";
static NSString * const KEY_ACTIVATION_ID   = @"aid";

static NSString * const FALLBACK_ALGORITHM  = @"LEGACY_P256";
static NSString * const FALLBACK_PROTOCOL   = @"3.3";

@implementation PA2ActivationStatus

- (instancetype) init
{
    self = [super init];
    if (self) {
        _dataVersion = DATA_VER;
    }
    return self;
}

- (instancetype) initWithDataVersion:(NSUInteger)dataVersion
                        activationId:(NSString*)activationId
                           algorithm:(NSString*)algorithm
                            protocol:(NSString*)protocol
{
    self = [super init];
    if (self) {
        _dataVersion = dataVersion;
        _activationId = activationId;
        _algorithm = algorithm;
        _protocolVersion = protocol;
    }
    return self;
}

- (NSData*) toData
{
    NSMutableDictionary * dict = [NSMutableDictionary dictionaryWithCapacity:4];
    dict[KEY_DATA_VER] = @(_dataVersion);
    if (_protocolVersion) {
        dict[KEY_PROTOCOL] = _protocolVersion;
    }
    if (_algorithm) {
        dict[KEY_ALGORITHM] = _algorithm;
    }
    if (_activationId) {
        dict[KEY_ACTIVATION_ID] = _activationId;
    }
    return [NSJSONSerialization dataWithJSONObject:dict options:0 error:NULL];
}

+ (instancetype) fromData:(NSData*)data
{
    if (data) {
        NSString * stringRepr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (stringRepr) {
            if ([stringRepr hasPrefix:@"{"]) {
                // New "JSON" format
                NSError * error = nil;
                id jsonRepr = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
                if (jsonRepr && !error) {
                    NSDictionary * dict = PA2ObjectAs(jsonRepr, NSDictionary);
                    if (dict) {
                        NSUInteger dataVersion = [PA2ObjectAs(dict[KEY_DATA_VER], NSNumber) unsignedIntegerValue];
                        NSString * activationId = PA2ObjectAs(dict[KEY_ACTIVATION_ID], NSString);
                        NSString * protocolVer = PA2ObjectAs(dict[KEY_PROTOCOL], NSString);
                        NSString * algorithm = PA2ObjectAs(dict[KEY_ALGORITHM], NSString);
                        if (dataVersion == DATA_VER) {
                            return [[PA2ActivationStatus alloc] initWithDataVersion:dataVersion
                                                                       activationId:activationId
                                                                          algorithm:algorithm
                                                                           protocol:protocolVer];
                        }
                        PowerAuthLog(@"PA2ActivationStatus: Unsupported data version");
                    } else {
                        PowerAuthLog(@"PA2ActivationStatus: Deserialized object is not dictionary");
                    }
                } else {
                    PowerAuthLog(@"PA2ActivationStatus: Failed to deserialize activation status: %@", error);
                }
            } else {
                // Legacy format, when only activation ID was serialized
                return [[PA2ActivationStatus alloc] initWithDataVersion:DATA_VER
                                                           activationId:stringRepr
                                                              algorithm:FALLBACK_ALGORITHM
                                                               protocol:FALLBACK_PROTOCOL];
            }
        }
    }
    return [[PA2ActivationStatus alloc] init];
    
}

+ (instancetype) fromPacket:(PA2WCSessionPacket_ActivationStatus*)status
{
    if (status) {
        return [[PA2ActivationStatus alloc] initWithDataVersion:DATA_VER
                                                   activationId:status.activationId
                                                      algorithm:status.algorithm
                                                       protocol:status.protocolVersion];
    }
    return [[PA2ActivationStatus alloc] init];
}

- (BOOL) isEqual:(id)object
{
    if (object == self) {
        // Same instance
        return YES;
    }
    PA2ActivationStatus * other = PA2ObjectAs(object, PA2ActivationStatus);
    if (!other) {
        // Different object type
        return NO;
    }
    return _dataVersion == other->_dataVersion &&
            [_activationId isEqualToString:other->_activationId] &&
            [_algorithm isEqualToString:other->_algorithm] &&
            [_protocolVersion isEqualToString:other->_protocolVersion];
}

@end
