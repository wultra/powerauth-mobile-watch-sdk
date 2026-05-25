/**
 * Copyright 2022 Wultra s.r.o.
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

#import <WatchKit/WatchKit.h>

//! Project version number for PowerAuth2ForWatch.
FOUNDATION_EXPORT double PowerAuth2ForWatchVersionNumber;

//! Project version string for PowerAuth2ForWatch.
FOUNDATION_EXPORT const unsigned char PowerAuth2ForWatchVersionString[];

// Import all public headers...
#import "PowerAuthMacros.h"
#import "PowerAuthWatchSDK.h"
#import "PowerAuthToken.h"
#import "PowerAuthHttpHeader.h"
#import "PowerAuthAuthentication.h"
#import "PowerAuthConfiguration.h"
#import "PowerAuthErrorConstants.h"
#import "PowerAuthKeychain.h"
#import "PowerAuthKeychainConfiguration.h"
#import "PowerAuthLog.h"
#import "PowerAuthSystem.h"
#import "PowerAuthWCSessionManager.h"
#import "PowerAuthTimeSynchronizationService.h"
#import "PowerAuthDeprecated.h"
