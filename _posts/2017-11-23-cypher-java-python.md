---
title: "RSA&AES&SHA256跨平台加解密的实现"
author_profile: ture
toc: true
toc_label: "目录"
categories:
  - 加解密
tags:
  - RSA
  - AES
  - java
  - python
  - sha256
---

## 导读
在做不同系统之间的通信加密时，简单方案是“非对称加密”结合“对称加密”进行。本文基于Java与python之间的通信，Java为客户端（代码可用于Android），python为服务端，基本过程如下：

首先，要生成一对RSA公钥和私钥，由客户端持有公钥，服务端持有私钥，接下来，客户端要发送信息msg到服务端，那么：

客户端：
: * 用sha256对信息msg进行摘要得到该信息的摘要msgDigest
  * 生成随机AES密钥key及IV向量
  * 使用key和IV对msg和msgDigest做AES加密得到密文cypher
  * 对key进行RSA公钥加密得到密文keyCypher
  * 将cypher，keyCypher，IV发送给服务端

服务端：
: * 用RSA私钥解密keyCypher取得AES密钥key
  * 用key和IV对密文cypher解密得到消息msg及摘要msgDigest
  * 对msg进行sha256摘要得到摘要msgDigest2
  * 对比msgDigest2和msgDigest，如果一致则认为可以使用msg

## 生成RSA公私钥对
可以使用`OpenSSL`在命令行生成，以Mac环境为例，在terminal执行:

首先生成私钥
```shell
openssl genrsa -out private_key.pem 2048
```
**⚠️** 2048指定了私钥长度（单位bit），同时，这个长度限制了能够加密的明文长度不能超过2048bit
{: .notice}

生成对应的公钥
```shell
openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der
```
> 上面使用`DER`指定输出的公钥格式为DER，也可以使用`PEM`指定输出格式为PEM，DER是二进制格式，PEM则采用了base64编码。关于不同格式的讨论后续在写文章介绍，也可以参考[serverFault上的介绍](http://serverfault.com/questions/9708/what-is-a-pem-file-and-how-does-it-differ-from-other-openssl-generated-key-file)

```shell
openssl rsa -in private_key.pem -pubout -outform PEM -out public_key.pem
```

## JAVA实现RSA公钥加密

在客户端使用Java实现RSA加密（Android也可用，但读取资源的方式和代码风格自己改一下），
其中用到了bcprov-jdk15on-158.jar库，可以到[bouncycastle](https://www.bouncycastle.org/latest_releases.html)下载。
以下为示例代码：

```java
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.file.Path;

public class RSADemo {
	
	/*
	这里使用的是“Legion of the Bouncy Castle”组织开发的轻量级java加解密包bcprov-jdk15on-158.jar包
	以下先将Provider注册到环境中，否则会提示下面在使用"BC"时，会报错找不到对应的provider  
	*/
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	/*
	实现RSA公钥加密的方法
	*/
	public static String enc(String plainText) throws IOException, GeneralSecurityException  {
		Path pubKeyPath = Paths.get("public_key.der");//请改为你的路径
		byte[] data = Files.readAllBytes(pubKeyPath);
		X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(data);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey key = kf.generatePublic(x509Spec);
		
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding","BC");
		cipher.init(Cipher.ENCRYPT_MODE, key, new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256,
	            PSource.PSpecified.DEFAULT));
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] bytes = cipher.doFinal(plainText.getBytes("UTF-8"));
		byte[] encodedBytes = Base64.getEncoder().encode(bytes);
	    String cipherText = new String(encodedBytes, "UTF-8");
		return cipherText;
	}

	public static void main(String[] args) throws IOException, GeneralSecurityException {
		// TODO Auto-generated method stub
		String plainText = "kdfao9@#&^kdsfa";
		String cipherText = enc(plainText);
		System.out.println("encypted text:\n"+ cipherText);  
	}

}

```

## Java实现AES加解密

这里的对称密钥暂时没有用随机生成，演示用直接用一个常量指定了值，实际应用中请随机生成一个字符串作为key，这个key的长度没有限制，因为下面代码做了归一成16byte的处理。

**⚠️** 由于我们使用的是AES-128，密钥长度必须是128bit，所以下面对密钥key进行了一次sha256转化成256bit，再编码成base64，只取出16位字符（每个字符8bit）
{: .notice}

```java
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES128Demo {
	private static final String characterEncoding = "UTF-8";
	private static final String cipherTransformation = "AES/CBC/PKCS5Padding";
	private static final String aesEncryptionAlgorithm = "AES";
	private static final String key = "e8ffc7e56311673f12b6fc91hlkjhjhujhlk;'hfaa77a5eb";
	private static byte[] ivBytes = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	private static byte[] keyBytes;

	private static AES128Demo instance = null;

	AES128Demo()
	{
	    SecureRandom random = new SecureRandom();
	    AES128Demo.ivBytes = new byte[16];
	    random.nextBytes(AES128Demo.ivBytes); 
	}

	public static AES128Demo getInstance() {
	    if(instance == null){
	        instance = new AES128Demo();
	    }
	    return instance;
	}

	public String encrypt_string(final String plain) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException
	{
	    byte[] encodedBytes = Base64.getEncoder().encode(encrypt(plain.getBytes()));		
	    String cipherText = new String(encodedBytes, characterEncoding);
	    return cipherText;
	}

	public String decrypt_string(final String plain) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException, IOException
	{
	    byte[] encryptedBytes = decrypt(Base64.getDecoder().decode(plain));
	    return new String(encryptedBytes);
	}

	public byte[] encrypt(byte[] mes)
	        throws NoSuchAlgorithmException,
	        NoSuchPaddingException,
	        InvalidKeyException,
	        InvalidAlgorithmParameterException,
	        IllegalBlockSizeException,
	        BadPaddingException, IOException {
	    /*
	    由于我们使用的是AES-128，密钥长度必须是128bit，
	    所以下面对密钥key进行了一次sha256转化成256bit
	    再编码成base64，只取出16位字符（每个字符8bit）
	    */
	    keyBytes = key.getBytes(characterEncoding);
	    MessageDigest md = MessageDigest.getInstance("SHA-256"); 
	    md.update(keyBytes);
	    keyBytes = Arrays.copyOf(md.digest(), 16);//只使用前128 bit作为AES128的密钥
//	    System.out.println("Long KEY: "+keyBytes.length + "-->>" + new String(Base64.getEncoder().encode(keyBytes),"UTF-8"));
//	    AlgorithmParameterSpec ivSpec = new IvParameterSpec(ivBytes);
	    SecretKeySpec newKey = new SecretKeySpec(keyBytes, aesEncryptionAlgorithm);
	    Cipher cipher = null;
	    cipher = Cipher.getInstance(cipherTransformation);
	    SecureRandom random = new SecureRandom();   
	    AES128Demo.ivBytes = new byte[16];               
	    random.nextBytes(AES128Demo.ivBytes);            
	    cipher.init(Cipher.ENCRYPT_MODE, newKey, random);
//	    cipher.init(Cipher.ENCRYPT_MODE, newKey, ivSpec);
	    byte[] destination = new byte[ivBytes.length + mes.length];
	    System.arraycopy(ivBytes, 0, destination, 0, ivBytes.length);
	    System.arraycopy(mes, 0, destination, ivBytes.length, mes.length);
	    return  cipher.doFinal(destination);
	}

	public byte[] decrypt(byte[] bytes)
	        throws NoSuchAlgorithmException,
	        NoSuchPaddingException,
	        InvalidKeyException,
	        InvalidAlgorithmParameterException,
	        IllegalBlockSizeException,
	        BadPaddingException, IOException, ClassNotFoundException {
	    keyBytes = key.getBytes("UTF-8");
	    MessageDigest md = MessageDigest.getInstance("SHA-256");
	    md.update(keyBytes);
	    keyBytes = Arrays.copyOf(md.digest(), 16);
	    //System.out.println("Long KEY: "+keyBytes.length + "-->>" + new String(Base64.getEncoder().encode(keyBytes),"UTF-8"));
	    byte[] ivB = Arrays.copyOfRange(bytes,0,16);
	    byte[] codB = Arrays.copyOfRange(bytes,16,bytes.length);
	    AlgorithmParameterSpec ivSpec = new IvParameterSpec(ivB);
	    SecretKeySpec newKey = new SecretKeySpec(keyBytes, aesEncryptionAlgorithm);
	    Cipher cipher = Cipher.getInstance(cipherTransformation);
	    cipher.init(Cipher.DECRYPT_MODE, newKey, ivSpec);
	    byte[] res = cipher.doFinal(codB); 
	    return  res;

	}
	
	public static void main(String[] args) throws Exception{
		// TODO Auto-generated method stub
		AES128Demo aesCrypt = AES128Demo.getInstance();
		String str = "this is local test你好的开发迪恩";
		String a = aesCrypt.encrypt_string(str);
		System.out.println(a);
//		String b = aesCrypt.decrypt_string(a);
		String b = aesCrypt.decrypt_string("MUBgjPqShkKmhAaj2RMNJBSnQIgdVurT+F4DVwm2OcrF2mClCuL12a+ppUmNFKxSPxlCovc5D4Glr/71oFaKew==");
		System.out.println(b);
	}

}
```

## Python实现RSA私钥解密

python默认支持的密钥格式为PEM。

```python
# -*- coding: utf-8 -*-
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import base64

class RSACipher:
	"""kayPath指向的私钥必须是pem格式的文件"""
	def __init__(self, keyPath):
		key = open(keyPath, 'r').read()
		self.keyPath = keyPath
		self.rsaPriKey = RSA.importKey(key)	

	def decrypt(self, cipherText):
		b64_decoded_message = base64.b64decode(cipherText)
		cipher = PKCS1_OAEP.new(self.rsaPriKey, hashAlgo=SHA256)
		return cipher.decrypt(b64_decoded_message)

"""测试代码"""
rsaCipher = RSACipher('private_key.pem')
encrypted_base64_msg = 'oA5Rg04ujAXjreHyD13+7STioT3nxS6Eb9fx6VHRHB75cq+J2IDcBoDcSoxbcJ351DhKDJ8HwXev9ifdvsHRx+sJx4L1iJ1HhdSMnIskOraMxoy5D50E+RLXEjn7P7jwLFqKAupU/x+x3zdydgRJ1G6r8Psji53Yeij1Y5RRcMgvrJs7RR3n1Wva0nDHX45o3jPnR1vyhQlG2YgF/25izqUkAF4Vo0D4Ei6WWG+mzts+HWNhRrznEKoc5HY2K5rqgkUxM4FH5okQABWa2MjFPabJAQa1cxwBFbVDaK3UPLA+X9CZednLzBVoS+aOHQYJI3wNNhsK9DKC8VZcDeWDkQ=='
print rsaCipher.decrypt(encrypted_base64_msg)
```

## python实现AES加解密


```python
# -*- coding: utf-8 -*-
from Crypto import Random
from Crypto.Cipher import AES
import hashlib
import base64
#####class
class AESCipher:

    def __init__(self, key):
        self.bs = 16 """AES 128的key长度为16字节"""
        self.key = hashlib.sha256(key.encode()).digest()[:16]
        print len(self.key)

    def encrypt(self, message):
        message = self._pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(message)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

"""测试代码"""
phrase = "this is local test来自服务端的问候！"
key = "e8ffc7e56311673f12b6fc91hlkjhjhujhlk;'hfaa77a5eb"
cryp = AESCipher(key)
eTxt = cryp.encrypt(phrase)
# eTxt = 'zSl7uQEfYOxPcsmjAKO6uyG9T70uYi0DL3yf08ktpraO/Mc/A8PvluMaqj0MoPb4QZ1r8VZlCgV6DmJ9eXonSA=='
dTxt = cryp.decrypt(eTxt)
```

