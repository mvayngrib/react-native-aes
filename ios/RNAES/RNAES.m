//
//  RNAESManager.m
//  ReactNativeAES
//
//  Created by Mark Vayngrib on 12/16/15.
//  Copyright © 2015 Tradle. All rights reserved.
//

#import "RNAES.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import "RCTBridgeModule.h"
#import "RCTLog.h"

@implementation RNAES

RCT_EXPORT_MODULE();

@synthesize bridge = _bridge;

NSString * const kRNAESErrorDomain = @"io.tradle.RNAES";

//const NSDictionary *CBC = @{
//  @"alogrithm": [NSNumber kCCAlgorithmAES128,
//  @"keySize": kCCKeySizeAES128,
//  @"blockSize": kCCBlockSizeAES128,
//  @"ivSize": kCCBlockSizeAES128
//}

const CCAlgorithm kAlgorithm = kCCAlgorithmAES128;
const NSUInteger kAlgorithmKeySize = kCCKeySizeAES128;
const NSUInteger kAlgorithmBlockSize = kCCBlockSizeAES128;
const NSUInteger kAlgorithmIVSize = kCCBlockSizeAES128;

// ===================

RCT_EXPORT_METHOD(addEvent:(NSString *)name location:(NSString *)location)
{
    RCTLogInfo(@"Pretending to create an event %@ at %@", name, location);
}

RCT_EXPORT_METHOD(encryptWithCipher:(NSString *)cipherName
                  data:(NSString *) base64Plaintext
                  key:(NSString *)base64Key
                  callback:(RCTResponseSenderBlock)callback)
{
    if ([cipherName caseInsensitiveCompare:@"aes-256-cbc"] != NSOrderedSame) {
        NSString* errMsg = [NSString stringWithFormat:@"cipher %@ not supported", cipherName];
        callback(@[errMsg]);
        return;
    }
    
    NSData *data = [[NSData alloc] initWithBase64EncodedString:base64Plaintext options:0];
    NSData *key = [[NSData alloc] initWithBase64EncodedString:base64Key options:0];
    NSData *iv = nil;
    NSError *error = nil;
    NSData* cipherData = [RNAES encryptData:data key:key iv:&iv error:&error];
    if (error) {
        NSString* msg = [[error userInfo] valueForKey:@"NSLocalizedFailureReason"];
        callback(@[msg]);
    } else {
        NSString *base64Ciphertext = [cipherData base64EncodedStringWithOptions:0];
        NSString *base64IV = [iv base64EncodedStringWithOptions:0];
        callback(@[[NSNull null], @{
                       @"iv": base64IV,
                       @"ciphertext": base64Ciphertext
                       }]);
    }
}

RCT_EXPORT_METHOD(decryptWithCipher:(NSString *)cipherName
                  data: base64Str
                  key:(NSString *)base64Key
                  iv:(NSString *)base64IV
                  callback:(RCTResponseSenderBlock)callback)
{
    if ([cipherName caseInsensitiveCompare:@"aes-256-cbc"] != NSOrderedSame) {
        NSString* errMsg = [NSString stringWithFormat:@"cipher %@ not supported", cipherName];
        callback(@[errMsg]);
        return;
    }
    
    NSData *data = [[NSData alloc] initWithBase64EncodedString:base64Str options:0];
    NSData *iv = [[NSData alloc] initWithBase64EncodedString:base64IV options:0];
    NSData *key = [[NSData alloc] initWithBase64EncodedString:base64Key options:0];
    NSError *error = nil;
    NSData* plaintext = [RNAES decryptData:data key:key iv:iv error:&error];
    if (error) {
        NSString* msg = [[error userInfo] valueForKey:@"NSLocalizedFailureReason"];
        callback(@[msg]);
    } else {
        NSString * base64Plaintext = [plaintext base64EncodedStringWithOptions:0];
        callback(@[[NSNull null], base64Plaintext]);
    }
}

+ (NSData *)encryptData:(NSData *)data
                    key:(NSData *)key
                     iv:(NSData **)iv
                  error:(NSError **)error {
    NSAssert(iv, @"IV must not be NULL");
    
    *iv = [self randomDataOfLength:kAlgorithmIVSize];
    
    size_t outLength;
    NSMutableData *
    cipherData = [NSMutableData dataWithLength:data.length +
                  kAlgorithmBlockSize];
    
    CCCryptorStatus
    result = CCCrypt(kCCEncrypt, // operation
                     kAlgorithm, // Algorithm
                     kCCOptionPKCS7Padding, // options
                     key.bytes, // key
                     key.length, // keylength
                     (*iv).bytes,// iv
                     data.bytes, // dataIn
                     data.length, // dataInLength,
                     cipherData.mutableBytes, // dataOut
                     cipherData.length, // dataOutAvailable
                     &outLength); // dataOutMoved
    
    if (result == kCCSuccess) {
        cipherData.length = outLength;
    }
    else {
        if (error) {
            *error = [NSError errorWithDomain:kRNAESErrorDomain
                                         code:result
                                     userInfo:nil];
        }
        return nil;
    }
    
    return cipherData;
}

+ (NSData *)decryptData:(NSData *)data
                    key:(NSData *)key
                     iv:(NSData *)iv
                  error:(NSError **)error {
    NSAssert(iv, @"IV must not be NULL");
    
    size_t outLength;
    NSMutableData *plaintext = [NSMutableData dataWithLength:data.length + kAlgorithmBlockSize];
    
    CCCryptorStatus
    result = CCCrypt(kCCDecrypt, // operation
                     kAlgorithm, // Algorithm
                     kCCOptionPKCS7Padding, // options
                     key.bytes, // key
                     key.length, // keylength
                     iv.bytes,// iv
                     data.bytes, // dataIn
                     data.length, // dataInLength,
                     plaintext.mutableBytes, // dataOut
                     plaintext.length, // dataOutAvailable
                     &outLength); // dataOutMoved
    
    if (result == kCCSuccess) {
        plaintext.length = outLength;
    }
    else {
        if (error) {
            *error = [NSError errorWithDomain:kRNAESErrorDomain
                                         code:result
                                     userInfo:nil];
        }
        return nil;
    }
    
    return plaintext;
}

// ===================

+ (NSData *)randomDataOfLength:(size_t)length {
    NSMutableData *data = [NSMutableData dataWithLength:length];
    
    int result = SecRandomCopyBytes(kSecRandomDefault,
                                    length,
                                    data.mutableBytes);
    NSAssert(result == 0, @"Unable to generate random bytes: %d",
             errno);
    
    return data;
}

//- (dispatch_queue_t)methodQueue
//{
//  return dispatch_queue_create("com.tradle.io.React.AESQueue", DISPATCH_QUEUE_SERIAL);
//}

@end
