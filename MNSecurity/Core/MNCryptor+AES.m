//
//  MNCryptor+AES.m
//  MNToolkit
//
//  Created by 陆广庆 on 14/7/9.
//  Copyright (c) 2014年 陆广庆. All rights reserved.
//

#import "MNCryptor.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>

static const NSUInteger kAesOutputUnit = 16;
static const NSUInteger kMaxReadSize = 8196;
const CCAlgorithm kAlgorithm = kCCAlgorithmAES128;
const NSUInteger kAlgorithmKeySize = kCCKeySizeAES256;
const NSUInteger kAlgorithmBlockSize = kCCBlockSizeAES128;
const NSUInteger kPBKDFRounds = 10000;
static Byte salt[] = {5,2,1,1,9,9,4,4};
static Byte iv[]   = {5,2,1,1,9,9,4,4};

@implementation MNCryptor (AES)

+ (NSData *) aes256Encrypt:(id)stringOrData key:(id)key
{
    NSParameterAssert([stringOrData isKindOfClass: [NSData class]] || [stringOrData isKindOfClass: [NSString class]]);
    NSData *data;
    if ([stringOrData isKindOfClass:[NSString class]]) {
        NSString *string = (NSString *)stringOrData;
        data = [string dataUsingEncoding:NSUTF8StringEncoding];
    } else {
        data = (NSData *)stringOrData;
    }
    NSData *password = [self generatePasswordWithKey:key];
    return [self aes256cryptor:kCCEncrypt data:data key:password];
}

+ (NSData *) aes256Decrypt:(id)stringOrData key:(id)key
{
    NSParameterAssert([stringOrData isKindOfClass: [NSData class]] || [stringOrData isKindOfClass: [NSString class]]);
    NSData *data;
    if ([stringOrData isKindOfClass:[NSString class]]) {
        NSString *string = (NSString *)stringOrData;
        data = [string dataUsingEncoding:NSUTF8StringEncoding];
    } else {
        data = (NSData *)stringOrData;
    }
    NSData *password = [self generatePasswordWithKey:key];
    return [self aes256cryptor:kCCDecrypt data:data key:password];
}

+ (BOOL) aes256EncryptFile:(NSString *)filePath
                        to:(NSString *)targetFilePath
                        key:(id)key
{
    return [self aes256cryptorForFile:kCCEncrypt
                                 from:filePath
                                   to:targetFilePath
                                  key:key];
}

+ (BOOL) aes256DecryptFile:(NSString *)filePath
                        to:(NSString *)targetFilePath
                        key:(id)key
{
    return [self aes256cryptorForFile:kCCDecrypt
                                 from:filePath
                                   to:targetFilePath
                                  key:key];
}

+ (BOOL) aes256cryptorForFile:(CCOperation)operation
                         from:(NSString *)filePath
                           to:(NSString *)targetFilePath
                          key:(id)key
{
    NSData *password = [self generatePasswordWithKey:key];
    NSFileManager *manager = [NSFileManager defaultManager];
    if (![manager fileExistsAtPath:filePath]) {
        return NO;
    }
    if ([manager fileExistsAtPath:targetFilePath]) {
        [manager removeItemAtPath:targetFilePath error:nil];
    }
    [manager createFileAtPath:targetFilePath contents:nil attributes:nil];
    
    NSFileHandle *readHandle = [NSFileHandle fileHandleForReadingAtPath:filePath];
    NSFileHandle *writehHandler = [NSFileHandle fileHandleForWritingAtPath:targetFilePath];
    [writehHandler seekToFileOffset:0];
    unsigned long long fileSize = [[manager attributesOfItemAtPath:filePath error:nil] fileSize];
    
    NSUInteger offset = 0;
    NSData *readData;
    
    /**
     *  @note
     *  输入是16*n字节，没有填充的情况下，输出和输入相同；
     *  有填充的情况下，输出是16*（n+1）。
     *  如果输入不是16字节整数倍，而是大于16*n小于16*（n+1),没有填充的情况下(CFB、OFB),输出和输入长度相同;有填充情况下,输出长度是16+1）
     */
    NSUInteger readLen = operation == kCCEncrypt ?
                        kMaxReadSize : kMaxReadSize - kMaxReadSize % kAesOutputUnit + kAesOutputUnit;
    while ((offset += readLen) < fileSize) {
        readData = [readHandle readDataOfLength:readLen];
        readData = [self aes256cryptor:operation
                                  data:readData
                                   key:password];
        [writehHandler writeData:readData];
        [readHandle seekToFileOffset:offset];
    }
    readData = [readHandle readDataToEndOfFile];
    readData = [self aes256cryptor:operation
                              data:readData
                               key:password];
    [writehHandler writeData:readData];
    [readHandle closeFile];
    [writehHandler closeFile];
    return YES;
}

+ (NSData *) aes256cryptor:(CCOperation)operation data:(NSData *)data key:(NSData *)key
{
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kAlgorithmBlockSize;
    void *buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(operation,
                                          kAlgorithm,
                                          kCCOptionPKCS7Padding,
                                          [key bytes],
                                          kAlgorithmKeySize,
                                          iv,
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesDecrypted);
    if (cryptStatus != kCCSuccess) {
        free(buffer);
        return nil;
    }
    return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
}

+ (NSData *) generatePasswordWithKey:(id)key
{
    NSString *keyStr;
    NSParameterAssert([key isKindOfClass: [NSData class]] || [key isKindOfClass: [NSString class]]);
    if ([key isKindOfClass:[NSString class]]) {
        keyStr = (NSString *)key;
    } else if ([key isKindOfClass:[NSData class]]) {
        NSData *keyData = (NSData *)key;
        keyStr = [[NSString alloc] initWithData:keyData encoding:NSUTF8StringEncoding];
    }
    NSMutableData *keyData = [NSMutableData dataWithLength:kAlgorithmKeySize];
    NSData *saltData = [NSData dataWithBytes:salt length:kCCKeySizeAES128];
    CCKeyDerivationPBKDF(kCCPBKDF2,
                         keyStr.UTF8String,
                         keyStr.length,
                         saltData.bytes,
                         saltData.length,
                         kCCPRFHmacAlgSHA1,
                         kPBKDFRounds,
                         keyData.mutableBytes,
                         keyData.length);
    return keyData;
}
@end
