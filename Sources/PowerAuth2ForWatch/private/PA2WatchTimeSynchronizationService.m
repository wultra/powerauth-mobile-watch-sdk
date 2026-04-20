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

#import "PA2WatchTimeSynchronizationService.h"

#import "PA2PrivateMacros.h"
#import "PA2WCSessionPacket_TimeSync.h"
#import "PA2WCSessionPacket_Success.h"
#import "PA2CompositeTask.h"
#import "PowerAuthWCSessionManager+Private.h"

#import <PowerAuth2ForWatch/PowerAuthLog.h>


@implementation PA2WatchTimeSynchronizationService
{
    NSString * _target;
    BOOL _isTimeSynchronized;
    NSTimeInterval _localTimeAdjustment;
    NSTimeInterval _localTimeAdjustmentPrecision;
}

- (instancetype) initWithInstanceId:(NSString *)instanceId
{
    self = [super init];
    if (self) {
        _target = [PA2WCSessionPacket_TIME_SERVICE_TARGET stringByAppendingString:instanceId];
        _isTimeSynchronized = NO;
        _localTimeAdjustment = 0.0;
        _localTimeAdjustmentPrecision = 0.0;
    }
    return self;
}

- (BOOL) isTimeSynchronized
{
    @synchronized (self) {
        return _isTimeSynchronized;
    }
}

- (NSTimeInterval) localTimeAdjustment
{
    @synchronized (self) {
        return _localTimeAdjustment;
    }
}

- (NSTimeInterval) localTimeAdjustmentPrecision
{
    @synchronized (self) {
        return _localTimeAdjustmentPrecision;
    }
}

- (NSTimeInterval) currentTime
{
    @synchronized (self) {
        return [[NSDate date] timeIntervalSince1970] + _localTimeAdjustment;
    }
}

- (id<PowerAuthOperationTask>) synchronizeTimeWithCallback:(void (^)(NSError * error))callback
                                             callbackQueue:(dispatch_queue_t)callbackQueue
{
    if (!callbackQueue) {
        callbackQueue = dispatch_get_main_queue();
    }
    // Prepare operation task
    PA2CompositeTask * task = [[PA2CompositeTask alloc] initWithCancelBlock:nil];
    
    // Prepare request packet
    PA2WCSessionPacket_TimeSync * packetData = [[PA2WCSessionPacket_TimeSync alloc] init];
    packetData.command = PA2WCSessionPacket_CMD_TIME_SERVICE_GET;
    PA2WCSessionPacket * packet = [PA2WCSessionPacket packetWithData:packetData target:_target];
    
    // Send packet with asynchronous response processing
    [[PowerAuthWCSessionManager sharedInstance] sendPacketWithResponse:packet responseClass:[PA2WCSessionPacket_TimeSync class] completion:^(PA2WCSessionPacket *response, NSError *error) {
        if (response) {
            [self processReceivedPacket:response error:&error];
        }
        dispatch_async(callbackQueue, ^{
            if ([task setCompleted]) {
                callback(error);
            }
        });
    }];
    return task;
}

- (void) resetTimeSynchronization
{
    @synchronized (self) {
        if (_isTimeSynchronized) {
            PowerAuthLog(@"PA2WatchTimeSynchronizationService: time is no longer synchronized");
        }
        _isTimeSynchronized = NO;
        _localTimeAdjustment = 0.0;
        _localTimeAdjustmentPrecision = 0.0;
    }
}

// MARK: Private methods

- (BOOL) processReceivedPacket:(PA2WCSessionPacket*)packet error:(NSError**)error
{
    NSString * target = packet.target;
    if (![target isEqualToString:_target] && ![target isEqualToString:PA2WCSessionPacket_RESPONSE_TARGET]) {
        // Internal error in previous processing.
        PA2SetError(error, PowerAuthErrorCode_Other, @"Wrong target in processReceivedPacket function");
        return NO;
    }
    PA2WCSessionPacket_TimeSync * timeData = [[PA2WCSessionPacket_TimeSync alloc] initWithDictionary:packet.sourceData];
    if ([timeData validatePacketData]) {
        if ([timeData.command isEqualToString:PA2WCSessionPacket_CMD_TIME_SERVICE_PUT]) {
            @synchronized (self) {
                if (!_isTimeSynchronized) {
                    PowerAuthLog(@"PA2WatchTimeSynchronizationService: time is now synchronized");
                }
                _isTimeSynchronized = YES;
                _localTimeAdjustment = timeData.localTimeAdjustment;
                _localTimeAdjustmentPrecision = timeData.localTimeAdjustmentPrecision;
            }
            return YES;
        }
    }
    NSString * message = [NSString stringWithFormat:@"PA2WatchTimeSynchronizationService: Received packet has invalid data. Target: %@", packet.target];
    PA2SetError(error, PowerAuthErrorCode_WatchConnectivity, message);
    return NO;
}

// MARK: - PA2WCSessionDataHandler

- (BOOL) canProcessPacket:(PA2WCSessionPacket*)packet
{
    return [packet.target isEqualToString:_target];
}

- (PA2WCSessionDataHandlerResponse*) sessionManager:(PowerAuthWCSessionManager*)manager responseForPacket:(PA2WCSessionPacket*)packet
{
    NSError * error = nil;
    [self processReceivedPacket:packet error:&error];
    if (error) {
        return [PA2WCSessionDataHandlerResponse responseWithError:error];
    }
    return [PA2WCSessionDataHandlerResponse responseWithPacket:[PA2WCSessionPacket packetWithSuccess]];
}
 
@end
