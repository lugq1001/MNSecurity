//
//  MNCryptor+OTP.m
//  MNToolkit
//
//  Created by 陆广庆 on 14-7-11.
//  Copyright (c) 2014年 陆广庆. All rights reserved.
//

#import "MNCryptor.h"
#import <CommonCrypto/CommonHMAC.h>

static NSInteger kTimeSeed[] = {0,1};
static NSUInteger kOtpLength = 6;

@implementation MNCryptor (OTP)

+ (NSString *) oneTimePassword:(NSString *)gen serverTime:(unsigned long long)serverTimeSecond
{
    NSString *time = [self formatTime2String:serverTimeSecond];
    NSString *otp = [self generateOTP:[self toHexString:gen] clearText:[self toHexString:time]];
    return otp;
}

+ (NSString *) formatTime2String:(unsigned long long)serverTimeSecond
{
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"yyyyMMddHHmm-ss"];
    NSString *timeString = [formatter stringFromDate:[NSDate dateWithTimeIntervalSince1970:serverTimeSecond]];
    NSArray *arr = [timeString componentsSeparatedByString:@"-"];
    NSString *prefix = arr[0];
    NSInteger suffix = [arr[1] unsignedIntValue] < 30 ? kTimeSeed[0] : kTimeSeed[1];
    NSString *result = [NSString stringWithFormat:@"%@%ld",prefix,(long)suffix];
    return result;
}

+ (NSString *) toHexString:(NSString *)str
{
    NSMutableString *result = [[NSMutableString alloc] init];
    NSUInteger length = [str length];
    for (int i=0;i<length;i++) {
        int ch = [str characterAtIndex:i];
        NSString *s = [NSString stringWithFormat:@"%x",ch];
        [result appendString:s];
    }
    return result;
}

+ (NSString *) generateOTP:(NSString *)seed clearText:(NSString *)clearText
{
    while ([clearText length] < 16) {
        clearText = [NSString stringWithFormat:@"0%@",clearText];
    }
    seed = [seed stringByAddingPercentEscapesUsingEncoding:NSUTF16BigEndianStringEncoding];
    clearText = [clearText stringByAddingPercentEscapesUsingEncoding:NSUTF16BigEndianStringEncoding];
    NSData *dSeed  = [self hexStr2Bytes:seed];
    NSData *dClearText = [self hexStr2Bytes:clearText];
    NSData *hash = [self hmac_sha:dSeed data:dClearText];
    Byte *hashByte = (Byte *)[hash bytes];
    int offset = hashByte[[hash length] -1] & 0xf;
    
    int binary = ((hashByte[offset] & 0x7f) << 24) | ((hashByte[offset + 1] & 0xff) << 16)
    | ((hashByte[offset + 2] & 0xff) << 8) | (hashByte[offset + 3] & 0xff);
    
    int opt = binary % 1000000;
    NSString *optCode = [NSString stringWithFormat:@"%d",opt];
    while ([optCode length] < kOtpLength) {
        optCode = [NSString stringWithFormat:@"0%@",optCode];
    }
    return optCode;
}

+ (NSData *) hexStr2Bytes:(NSString *)hex
{
    NSMutableData* data = [NSMutableData data];
    int idx;
    NSUInteger length = [hex length];
    for (idx = 0; idx+2 <= length; idx+=2) {
        NSRange range = NSMakeRange(idx, 2);
        NSString *hexStr = [hex substringWithRange:range];
        NSScanner *scanner = [NSScanner scannerWithString:hexStr];
        unsigned int intValue;
        [scanner scanHexInt:&intValue];
        [data appendBytes:&intValue length:1];
    }
    return data;
}

+ (NSData *) hmac_sha:(NSData *)key data:(NSData *)data
{
    unsigned char cHMAC[CC_SHA512_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA512, [key bytes], [key length], [data bytes], [data length], cHMAC);
    NSData *HMAC = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
    NSMutableString *ms = [[NSMutableString alloc] init];
    NSUInteger length = [HMAC length];
    for (int i=0 ; i<length; i++) {
        [ms appendFormat:@"%d,",cHMAC[i]];
    }
    return HMAC;
}

@end
