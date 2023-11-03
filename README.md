# VHtearCryptoutil

VHtearCryptoutil is a Go (Golang) toolkit that provides various cryptographic and data manipulation functions. This package is designed to assist developers in implementing cryptography, encryption, decryption, and data manipulation easily and efficiently.

With VHtearCryptoutil, you can quickly integrate powerful cryptographic functions into your projects and efficiently manipulate data. This package is suitable for the development of applications that require data security, such as financial applications, sensitive data processing, and many others.

## Key Features

- AES-GCM encryption and decryption functions.
- Calculation of checksums and data transformation using hashing.
- Data processing in byte and hexadecimal formats.
- And many other features.

## Installation

You can easily install this package using the following command:

```shell
go get github.com/fckveza/VHtearCryptoutil

#### Extended usage

```go
package main

import (
	"fmt"
	"github.com/fckveza/VHtearCryptoutil"
)

func main() {
	// Example of using GetSHA256Sum
	sha256Sum := VHtearCryptoutil.GetSHA256Sum("Hello, World!")
	fmt.Printf("SHA-256 Sum: %x\n", sha256Sum)

	// Example of using GenerateSharedSecret
	privateKey := []byte("private_key")
	publicKey := []byte("public_key")
	sharedSecret, err := VHtearCryptoutil.GenerateSharedSecret(privateKey, publicKey)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Shared Secret: %x\n", sharedSecret)
	}

	// Example of using GenerateAAD
	aad := VHtearCryptoutil.GenerateAAD("example", "data", 42, 13, 7, 99)
	fmt.Printf("AAD: %x\n", aad)

	// Example of using DecryptWithAESGCM
	gcmKey := []byte("secret_key")
	nonce := []byte("unique_nonce")
	ciphertext := []byte("encrypted_data")
	message, err := VHtearCryptoutil.DecryptWithAESGCM(gcmKey, nonce, ciphertext, aad)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Decrypted Message: %s\n", message)
	}

	// Example of using EncryptWithAESGCM
	dataToEncrypt := []byte("sensitive_data")
	ciphertext, err := VHtearCryptoutil.EncryptWithAESGCM(dataToEncrypt, gcmKey, nonce, aad)
	if err is not nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Encrypted Data: %x\n", ciphertext)
	}

	// Example of using EncHeaders
	headers := map[string]string{
		"Content-Type": "application/json",
		"Authorization": "Bearer token",
	}
	encodedHeaders := VHtearCryptoutil.EncHeaders(headers)
	fmt.Printf("Encoded Headers: %x\n", encodedHeaders)

	// Example of using Pad
	dataToPad := []byte("data_to_pad")
	paddedData := VHtearCryptoutil.Pad(dataToPad, 16)
	fmt.Printf("Padded Data: %x\n", paddedData)

	// Example of using Unpad
	unpaddedData, err := VHtearCryptoutil.Unpad(paddedData)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Unpadded Data: %x\n", unpaddedData)
	}

	// Example of using CalculateChecksumAndTransform
	key := []byte("encryption_key")
	dataToTransform := []byte("data_to_transform")
	transformedData := VHtearCryptoutil.CalculateChecksumAndTransform(key, dataToTransform)
	fmt.Printf("Transformed Data: %x\n", transformedData)

	// Example of using ParseHexToSlice
	hexString := "48656c6c6f2c20576f726c6421"
	hexData := VHtearCryptoutil.ParseHexToSlice(hexString)
	fmt.Printf("Hex Data: %x\n", hexData)

	// Example of using Xor
	dataToXor := []byte("data_to_xor")
	xoredData := VHtearCryptoutil.Xor(dataToXor)
	fmt.Printf("Xored Data: %x\n", xoredData)

	// Example of using CombineBytesToResult
	dataToCombine := []byte{0x12, 0x34}
	result := VHtearCryptoutil.CombineBytesToResult(dataToCombine, 0)
	fmt printf("Combined Result: %x\n", result)

	// Example of using AccessAndTransformElement
	dataToAccess := []byte{0xFF, 0x80}
	element := VHtearCryptoutil.AccessAndTransformElement(dataToAccess, 0)
	fmt.Printf("Accessed and Transformed Element: %x\n", element)
}
```
