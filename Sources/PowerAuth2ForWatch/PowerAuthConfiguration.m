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

#import <PowerAuth2ForWatch/PowerAuthConfiguration.h>

@implementation PowerAuthConfiguration

- (instancetype) initWithInstanceId:(nonnull NSString*)instanceId
{
    self = [super init];
    if (self) {
        _instanceId = instanceId;
    }
    return self;
}

// PA2_DEPRECATED(2.0.0)
- (id) initWithInstanceId:(NSString *)instanceId
          baseEndpointUrl:(NSString *)baseEndpointUrl
            configuration:(NSString *)configuration
{
    self = [super init];
    if (self) {
        _instanceId = instanceId;
        _baseEndpointUrl = baseEndpointUrl;
        _configuration = configuration;
    }
    return self;
}

- (BOOL) validateConfiguration
{
    BOOL result = YES;
    result = result && (_instanceId.length > 0);
    return result;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
- (id) copyWithZone:(NSZone *)zone
{
    return [[self.class allocWithZone:zone] initWithInstanceId:_instanceId
                                               baseEndpointUrl:_baseEndpointUrl
                                                 configuration:_configuration];
}
#pragma clang diagnostic pop

@end
