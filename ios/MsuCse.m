#import <React/RCTBridgeModule.h>

@interface RCT_EXTERN_MODULE(MsuCse, NSObject)

RCT_EXTERN_METHOD(multiply:(float)a withB:(float)b
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(isValidCVV:(NSString)cvv withPan:(NSString)pan
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(detectBrand:(NSString)pan
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(isValidPan:(NSString)pan
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(isValidExpiry:(NSInteger)month withYear:(NSInteger)year
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(encrypt:(NSString)pan
                 withName:(NSString)cardHolderName
                 withExpiryYear:(NSInteger)expiryYear
                 withExpiryMonth:(NSInteger)expiryMonth
                 withCVV:(NSString)cvv
                 withNonce:(NSString)nonce
                 withResolver:(RCTPromiseResolveBlock)resolve
                 withRejecter:(RCTPromiseRejectBlock)reject)


+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

@end
