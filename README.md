###API
#####Common:
```
+ (NSString *) b64Encode:(id)stringOrData;
+ (NSString *) b64Decode:(NSString *)b64String;
+ (NSData *)   b64Decode4Data:(NSString *)b64String;

+ (NSString *) urlEncode:(NSString *)clearText;
+ (NSString *) urlDecode:(NSString *)urlString;

+ (NSString *) oneTimePassword:(NSString *)gen serverTime:(unsigned long long)serverTimeSecond;
```
#####MD5:
```
+ (NSString *) md5:(id)stringOrData;
+ (NSString *) md5File:(NSString *)filePath;
+ (NSString *) md5To16bit:(NSString *)md5_32bit;
```
#####SHA:
```
+ (NSString *) sha1:(id)stringOrData;
+ (NSString *) sha224:(id)stringOrData;
+ (NSString *) sha256:(id)stringOrData;
+ (NSString *) sha384:(id)stringOrData;
+ (NSString *) sha512:(id)stringOrData;

+ (NSString *) sha1File:(NSString *)filePath;
+ (NSString *) sha224File:(NSString *)filePath;
+ (NSString *) sha256File:(NSString *)filePath;
+ (NSString *) sha384File:(NSString *)filePath;
+ (NSString *) sha512File:(NSString *)filePath;
```
#####AES:
```
+ (NSData *) aes256Encrypt:(id)stringOrData key:(id)key;
+ (NSData *) aes256Decrypt:(id)stringOrData key:(id)key;

+ (BOOL)     aes256EncryptFile:(NSString *)filePath
                            to:(NSString *)targetFilePath
                            key:(id)key;
+ (BOOL)     aes256DecryptFile:(NSString *)filePath
                            to:(NSString *)targetFilePath
                            key:(id)key;
```
#####RSA:
```
+ (SecKeyRef) rsaPublicKeyRef:(NSString *)publicKeyPath;
+ (SecKeyRef) rsaPrivateKeyRef:(NSString *)privateKeyPath keyPassword:(NSString *)password;
+ (NSData *)  rsaEncryptWithPublicKey:(NSData *)data publicKeyRef:(SecKeyRef)publicKeyRef;
+ (NSData *)  rsaDecryptWithPrivateKey:(NSData *)data privateKeyRef:(SecKeyRef)privateKeyRef;

+ (NSData *)  rsaSignWithPrivateKey:(NSData *)data privateKeyRef:(SecKeyRef)privateKeyRef;
+ (BOOL)      rsaVerifyWithPublicKey:(NSData *)data signature:(NSData *)signature publicKeyRef:(SecKeyRef)publicKeyRef;
```
