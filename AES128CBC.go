package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

/**
 * @Author: Lee
 * @Date: 2021/4/14 10:29
 * @Desc: AES-128-CBC，数据采用PKCS#7填充
 */

func main()  {

	plaintext := []byte("demo")//需要加密的内容
	//key iv 字节长度一定要16
	key := []byte("demoKey123456789")[:aes.BlockSize]
	iv := []byte("demoIV1234567890")[:aes.BlockSize]

	//加密
	ciphertext,err := AesEncrypt(plaintext,key,iv)
	if err != nil{
		panic(err)
	}
	//密文一般base64之后传输
	fmt.Println(base64.StdEncoding.EncodeToString(ciphertext))

	//解密
	plaintext,err = AesDecrypt(ciphertext,key,iv)
	if err != nil{
		panic(err)
	}
	fmt.Println(string(plaintext))
}


// AesDecrypt 解密函数
func AesDecrypt(ciphertext []byte, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, iv[:blockSize])
	origData := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(origData, ciphertext)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}
//AesEncrypt 加密函数
func AesEncrypt(plaintext []byte, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	plaintext = PKCS7Padding(plaintext, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(plaintext))
	blockMode.CryptBlocks(crypted, plaintext)
	return crypted, nil
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}