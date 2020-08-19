
GM SM2/3/4 library based on Golang

基于Go语言的国密SM2/SM3/SM4加密算法库

版权所有 苏州同济区块链研究院有限公司(http://www.wutongchain.com/)


Process Results [![Build Status](https://travis-ci.org/tjfoc/gmsm.svg?branch=master)](https://travis-ci.org/tjfoc/gmsm)

Copyright Suzhou Tongji Fintech Research Institute 2017 All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");

you may not use this file except in compliance with the License.
You may obtain a copy of the License at
     http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

See the License for the specific language governing permissions and limitations under the License.


GMSM包含以下主要功能

    SM2: 国密椭圆曲线算法库
        . 支持Generate Key, Sign, Verify基础操作
        . 支持加密和不加密的pem文件格式(加密方法参见RFC5958, 具体实现参加代码)
        . 支持证书的生成，证书的读写(接口兼容rsa和ecdsa的证书)
        . 支持证书链的操作(接口兼容rsa和ecdsa)
        . 支持crypto.Signer接口

    SM3: 国密hash算法库
       . 支持基础的sm3Sum操作
       . 支持hash.Hash接口

    SM4: 国密分组密码算法库
        . 支持Generate Key, Encrypt, Decrypt基础操作
        . 提供Cipher.Block接口
        . 支持加密和不加密的pem文件格式(加密方法为pem block加密, 具体函数为x509.EncryptPEMBlock)

关于GMSM交流： [![Join the chat at https://gitter.im/tjfoc/gmsm](https://badges.gitter.im/tjfoc/gmsm.svg)](https://gitter.im/tjfoc/gmsm?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
或发送邮件到tj@wutongchain.com

 如果你对国密算法开源技术及应用感兴趣，欢迎添加“苏州同济区块链研究院·小助手“微信，回复“国密算法进群”，加入“同济区块链国密算法交流群”。微信二维码如下:
 ![微信二维码](https://github.com/tjfoc/wutongchian-public/blob/master/wutongchain.png)



## 国密gmsm包安装

```bash
go get -u github.com/tjfoc/gmsm
```

## SM3密码杂凑算法 - SM3 cryptographic hash algorithm

遵循的SM3标准号为： GM/T 0004-2012

导入包
```Go
import github.com/tjfoc/gmsm/sm3
```

### 代码示例

```Go
    data := "test"
    h := sm3.New()
    h.Write([]byte(data))
    sum := h.Sum(nil)
    fmt.Printf("digest value is: %x\n",sum)
```
### 方法列表

####  New 
创建哈希计算实例
```Go
func New() hash.Hash 
```

#### Sum 
返回SM3哈希算法摘要值
```Go
func Sum() []byte 
```

## SM4分组密码算法 - SM4 block cipher algorithm

遵循的SM4标准号为:  GM/T 0002-2012

导入包
```Go
import github.com/tjfoc/gmsm/sm4
```

### 代码示例

```Go
    import  "crypto/cipher"
    import  "github.com/tjfoc/gmsm/sm4"

    func main(){
        // 128比特密钥
        key := []byte("1234567890abcdef")
        // 128比特iv
        iv := make([]byte, sm4.BlockSize)
        data := []byte("Tongji Fintech Research Institute")
        ciphertxt,err := sm4Encrypt(key,iv, data)
        if err != nil{
            log.Fatal(err)
        }
        fmt.Printf("加密结果: %x\n", ciphertxt)
    }

    func sm4Encrypt(key, iv, plainText []byte) ([]byte, error) {
        block, err := sm4.NewCipher(key)
        if err != nil {
            return nil, err
        }
        blockSize := block.BlockSize()
        origData := pkcs5Padding(plainText, blockSize)
        blockMode := cipher.NewCBCEncrypter(block, iv)
        cryted := make([]byte, len(origData))
        blockMode.CryptBlocks(cryted, origData)
        return cryted, nil
    }

    func sm4Decrypt(key, iv, cipherText []byte) ([]byte, error) {
        block, err := sm4.NewCipher(key)
    	if err != nil {
        	return nil, err
    	}
    	blockMode := cipher.NewCBCDecrypter(block, iv)
    	origData := make([]byte, len(cipherText))
    	blockMode.CryptBlocks(origData, cipherText)
    	origData = pkcs5UnPadding(origData)
    	return origData, nil
    }
    // pkcs5填充
    func pkcs5Padding(src []byte, blockSize int) []byte {
        padding := blockSize - len(src)%blockSize
    	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    	return append(src, padtext...)
    }

    func pkcs5UnPadding(src []byte) []byte {
        length := len(src)
        if(length==0){
            return nil
        }
    	unpadding := int(src[length-1])
    	return src[:(length - unpadding)]
    }
```

### 方法列表

#### NewCipher
创建SM4密码分组算法模型，参数key长度只支持128比特。
```Go
func NewCipher(key []byte) (cipher.Block, error)
```

## SM2椭圆曲线公钥密码算法 - Public key cryptographic algorithm SM2 based on elliptic curves

遵循的SM2标准号为： GM/T 0003.1-2012、GM/T 0003.2-2012、GM/T 0003.3-2012、GM/T 0003.4-2012、GM/T 0003.5-2012、GM/T 0009-2012、GM/T 0010-2012

导入包
```Go
import github.com/tjfoc/gmsm/sm2
```

### 代码示例

```Go
    priv, err := sm2.GenerateKey() // 生成密钥对
    if err != nil {
    	log.Fatal(err)
    }
    msg := []byte("Tongji Fintech Research Institute")
    pub := &priv.PublicKey
    cipherOpts := &Sm2CipherOpts{
		ASN1:       true, // 使用ASN1 编码
		CipherMode: C1C3C2, // C1C3C2 方式填充
	}
    ciphertxt, err := pub.Encrypt(msg, cipherOpts)
    if err != nil {
    	log.Fatal(err)
    }
    fmt.Printf("加密结果:%x\n",ciphertxt)
    plaintxt,err :=  priv.Decrypt(ciphertxt, cipherOpts)

    signOpts := &Sm2SignerOpts{UserId: testUID, ASN1: false}
    if err != nil {
    	log.Fatal(err)
    }
    if !bytes.Equal(msg,plaintxt){
        log.Fatal("原文不匹配")
    }

    sig ,err := priv.Sign(rand.Reader, msg, signOpts)
    if err != nil {
    	log.Fatal(err)
    }
    isok := pub.Verify(msg, sig, signOpts)
    fmt.Printf("Verified: %v\n", isok)
```

### 方法列表

#### GenerateKey
生成随机秘钥。
```Go
func GenerateKey() (*PrivateKey, error) 
```

#### Sign
用私钥签名数据，成功返回以两个大数表示的签名结果，否则返回错误。
```Go
func (priv *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) []byte
```

#### Verify
用公钥验证数据签名, 验证成功返回True，否则返回False。
```Go
func (pub *PublicKey) Verify(msg []byte, sign []byte, opts crypto.SignerOpts) bool 
```

#### Encrypt
用公钥加密数据,成功返回密文错误，否则返回错误。
```Go
func (pub *PublicKey) Encrypt(data []byte, opts *Sm2CipherOpts) ([]byte, error)
```

#### Decrypt
用私钥解密数据，成功返回原始明文数据，否则返回错误。
```Go
func (priv *PrivateKey) Decrypt(data []byte, opts *Sm2CipherOpts) ([]byte, error)
```
