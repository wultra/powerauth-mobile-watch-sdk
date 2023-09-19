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

#import <PowerAuth2ForWatch/PowerAuthConfiguration.h>

@implementation PowerAuthConfiguration

- (id) initWithInstanceId:(NSString *)instanceId baseEndpointUrl:(NSString *)baseEndpointUrl configuration:(NSString *)configuration
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
    result = result && (_baseEndpointUrl.length > 0);
    if (_sharingConfiguration) {
        result = result && [_sharingConfiguration validateConfiguration];
    }
    // TODO:...
    //result = result && [PowerAuthCoreSessionSetup validateConfiguration:_configuration];
    return result;
}

- (id)copyWithZone:(NSZone *)zone
{
    PowerAuthConfiguration * c = [[self.class allocWithZone:zone] init];
    if (c) {
        c->_instanceId = _instanceId;
        c->_baseEndpointUrl = _baseEndpointUrl;
        c->_configuration = _configuration;
        c->_keychainKey_Biometry = _keychainKey_Biometry;
        c->_externalEncryptionKey = _externalEncryptionKey;
        c->_sharingConfiguration = [_sharingConfiguration copy];
    }
    return c;
}

@end
