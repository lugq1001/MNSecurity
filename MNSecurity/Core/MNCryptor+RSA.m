//
//  MNCryptor+RSA.m
//  MNToolkit
//
//  Created by 陆广庆 on 14-7-11.
//  Copyright (c) 2014年 陆广庆. All rights reserved.
//

#import "MNCryptor.h"
#import <CommonCrypto/CommonDigest.h>

@implementation MNCryptor (RSA)

+ (SecKeyRef) rsaPublicKeyRef:(NSString *)publicKeyPath
{
    NSData *certData = [NSData dataWithContentsOfFile:publicKeyPath];
    SecCertificateRef cert = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certData);
    SecKeyRef key = NULL;
    SecTrustRef trust = NULL;
    SecPolicyRef policy = NULL;
    if (cert != NULL) {
        policy = SecPolicyCreateBasicX509();
        if (policy) {
            if (SecTrustCreateWithCertificates((CFTypeRef)cert, policy, &trust) == noErr) {
                SecTrustResultType result;
                if (SecTrustEvaluate(trust, &result) == noErr) {
                    key = SecTrustCopyPublicKey(trust);
                }
            }
        }
    }
    if (policy) CFRelease(policy);
    if (trust) CFRelease(trust);
    if (cert) CFRelease(cert);
    return key;
}

+ (SecKeyRef) rsaPrivateKeyRef:(NSString *)privateKeyPath keyPassword:(NSString *)password
{
    NSData *p12Data = [NSData dataWithContentsOfFile:privateKeyPath];
    NSMutableDictionary *options = [[NSMutableDictionary alloc] init];
    SecKeyRef privateKeyRef = NULL;
    [options setObject:password forKey:(__bridge id)kSecImportExportPassphrase];
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus securityError = SecPKCS12Import((__bridge CFDataRef) p12Data,
                                             (__bridge CFDictionaryRef)options, &items);
    if (securityError == noErr && CFArrayGetCount(items) > 0) {
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identityApp =
        (SecIdentityRef)CFDictionaryGetValue(identityDict,
                                             kSecImportItemIdentity);
        securityError = SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
        if (securityError != noErr) {
            privateKeyRef = NULL;
        }
    }
    CFRelease(items);
    return privateKeyRef;
}

+ (NSData *) rsaEncryptWithPublicKey:(NSData *)data publicKeyRef:(SecKeyRef)publicKeyRef
{
    size_t cipherBufferSize = SecKeyGetBlockSize(publicKeyRef);
    uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    double totalLength = [data length];
    size_t blockSize = cipherBufferSize - 12;
    size_t blockCount = (size_t)ceil(totalLength / blockSize);
    NSMutableData *encryptedData = [NSMutableData data];
    for (int i = 0; i < blockCount; i++) {
        NSUInteger loc = i * blockSize;
        int dataSegmentRealSize = MIN(blockSize, [data length] - loc);
        NSData *dataSegment = [data subdataWithRange:NSMakeRange(loc, dataSegmentRealSize)];
        OSStatus status = SecKeyEncrypt(publicKeyRef, kSecPaddingPKCS1, (const uint8_t *)[dataSegment bytes], dataSegmentRealSize, cipherBuffer, &cipherBufferSize);
        if (status == errSecSuccess) {
            NSData *encryptedDataSegment = [[NSData alloc] initWithBytes:(const void *)cipherBuffer length:cipherBufferSize];
            [encryptedData appendData:encryptedDataSegment];
        } else {
            if (cipherBuffer) {
                free(cipherBuffer);
            }
            return nil;
        }
    }
    if (cipherBuffer) {
        free(cipherBuffer);
    }
    return encryptedData;
}

+ (NSData *) rsaDecryptWithPrivateKey:(NSData *)data privateKeyRef:(SecKeyRef)privateKeyRef
{
    size_t plainBufferSize = SecKeyGetBlockSize(privateKeyRef);
    uint8_t *plainBuffer = malloc(plainBufferSize * sizeof(uint8_t));
    double totalLength = [data length];
    size_t blockSize = plainBufferSize;
    size_t blockCount = (size_t)ceil(totalLength / blockSize);
    NSMutableData *decryptedData = [NSMutableData data];
    for (int i = 0; i < blockCount; i++) {
        NSUInteger loc = i * blockSize;
        int dataSegmentRealSize = MIN(blockSize, totalLength - loc);
        NSData *dataSegment = [data subdataWithRange:NSMakeRange(loc, dataSegmentRealSize)];
        OSStatus status = SecKeyDecrypt(privateKeyRef, kSecPaddingPKCS1, (const uint8_t *)[dataSegment bytes], dataSegmentRealSize, plainBuffer, &plainBufferSize);
        if (status == errSecSuccess) {
            NSData *decryptedDataSegment = [[NSData alloc] initWithBytes:(const void *)plainBuffer length:plainBufferSize];
            [decryptedData appendData:decryptedDataSegment];
        } else {
            if (plainBuffer) {
                free(plainBuffer);
            }
            return nil;
        }
    }
    if (plainBuffer) {
        free(plainBuffer);
    }
    return decryptedData;
}

+ (NSData *) rsaSignWithPrivateKey:(NSData *)data privateKeyRef:(SecKeyRef)privateKeyRef
{
    size_t signedHashBytesSize = SecKeyGetBlockSize(privateKeyRef);
    uint8_t *signedHashBytes = malloc(signedHashBytesSize);
    memset(signedHashBytes, 0x0, signedHashBytesSize);
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t *hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([data bytes], (CC_LONG)[data length], hashBytes)) {
        return nil;
    }
    SecKeyRawSign(privateKeyRef,
                  kSecPaddingPKCS1SHA256,
                  hashBytes,
                  hashBytesSize,
                  signedHashBytes,
                  &signedHashBytesSize);
    
    NSData *signedHash = [NSData dataWithBytes:signedHashBytes
                                        length:(NSUInteger)signedHashBytesSize];
    
    if (hashBytes)
        free(hashBytes);
    if (signedHashBytes)
        free(signedHashBytes);
    return signedHash;
}

+ (BOOL) rsaVerifyWithPublicKey:(NSData *)data signature:(NSData *)signature publicKeyRef:(SecKeyRef)publicKeyRef
{
    size_t signedHashBytesSize = SecKeyGetBlockSize(publicKeyRef);
    const void *signedHashBytes = [signature bytes];
    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
    uint8_t *hashBytes = malloc(hashBytesSize);
    if (!CC_SHA256([data bytes], (CC_LONG)[data length], hashBytes)) {
        return NO;
    }
    OSStatus status = SecKeyRawVerify(publicKeyRef,
                                      kSecPaddingPKCS1SHA256,
                                      hashBytes,
                                      hashBytesSize,
                                      signedHashBytes,
                                      signedHashBytesSize);
    return status == errSecSuccess;
}

@end
