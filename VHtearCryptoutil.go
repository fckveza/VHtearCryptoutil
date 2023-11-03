package VHtearCryptoutil

//Made with the happiness of VHtear

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/OneOfOne/xxhash"
	"golang.org/x/crypto/curve25519"
)

func GetSHA256Sum(args ...interface{}) []byte {
	instance := sha256.New()
	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			instance.Write([]byte(v))
		case []byte:
			instance.Write(v)
		default:
			fmt.Printf("Unsupported type: %T\n", v)
		}
	}
	return instance.Sum(nil)
}

func GenerateSharedSecret(privateKey, publicKey []byte) ([]byte, error) {
	sharedSecret, err := curve25519.X25519(privateKey, publicKey)
	if err != nil {
		fmt.Println("Error calculating shared secret:", err)
		return nil, err
	}

	return sharedSecret, nil
}

func GenerateAAD(a string, b string, c int, d int, e int, f int) []byte {
	var aad bytes.Buffer

	aad.WriteString(a)
	aad.WriteString(b)
	aad.Write(GetIntBytesV2(c))
	aad.Write(GetIntBytesV2(d))
	aad.Write(GetIntBytesV2(e))
	aad.Write(GetIntBytesV2(f))

	return aad.Bytes()
}

func DecryptWithAESGCM(gcmKey, sign, message, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(gcmKey)
	if err != nil {
		fmt.Println("NewCipher", err)
	}
	var gcm cipher.AEAD
	if len(sign) == 16 {
		gcm, err = cipher.NewGCMWithNonceSize(block, 16)
		if err != nil {
			return nil, err
		}
	} else {
		gcm, err = cipher.NewGCM(block)
		if err != nil {
			fmt.Println("NewGCM", err)
		}
	}
	decrypted, err := gcm.Open(nil, sign, message, aad)
	if err != nil {
		fmt.Println("aesgcm.Open", err)
	}
	return decrypted, nil
}

func EncryptWithAESGCM(data, gcmKey, nonce, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(gcmKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, data, aad)

	return ciphertext, nil
}
func mFhrnmxnNF(t int, e *[]byte) error {
	i := 65536
	if t < -32768 || t >= i {
		return fmt.Errorf("%d is incorrect for i16", t)
	}
	*e = append(*e, byte(255&t>>8), byte(255&t))
	return nil
}

func wYEpEYldst(t string, e *[]byte) {
	for i := 0; i < len(t); i++ {
		*e = append(*e, t[i])
	}
}

func EncHeaders(headers map[string]string) []byte {
	data := make([]byte, 0)
	numKeys := len(headers)
	mFhrnmxnNF(numKeys, &data)

	for key, value := range headers {
		keyLen := len(key)
		mFhrnmxnNF(keyLen, &data)
		wYEpEYldst(key, &data)
		valueLen := len(value)
		mFhrnmxnNF(valueLen, &data)
		wYEpEYldst(value, &data)
	}
	dataLen := len(data)
	data = append([]byte{byte(dataLen & 255)}, data...)
	data = append([]byte{byte(dataLen >> 8 & 255)}, data...)
	return data
}

func Pad(buf []byte, size int) []byte {
	if size < 1 || size > 255 {
		panic(fmt.Sprintf("pkcs7pad: inappropriate block size %d", size))
	}
	i := size - (len(buf) % size)
	return append(buf, bytes.Repeat([]byte{byte(i)}, i)...)
}

func Pad256(buf []byte, size int) []byte {
	dataLen := len(buf)
	padLen := size % dataLen
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(buf, padding...)
}

func Unpad(buf []byte) ([]byte, error) {
	if len(buf) == 0 {
		return nil, errors.New("pkcs7pad: bad padding")
	}
	padLen := buf[len(buf)-1]
	toCheck := 255
	good := 1
	if toCheck > len(buf) {
		toCheck = len(buf)
	}
	for i := 0; i < toCheck; i++ {
		b := buf[len(buf)-1-i]

		outOfRange := subtle.ConstantTimeLessOrEq(int(padLen), i)
		equal := subtle.ConstantTimeByteEq(padLen, b)
		good &= subtle.ConstantTimeSelect(outOfRange, 1, equal)
	}

	good &= subtle.ConstantTimeLessOrEq(1, int(padLen))
	good &= subtle.ConstantTimeLessOrEq(int(padLen), len(buf))

	if good != 1 {
		return nil, errors.New("pkcs7pad: bad padding")
	}
	return buf[:len(buf)-int(padLen)], nil
}

func CalculateChecksumAndTransform(key []byte, data []byte) []byte {
	r := make([]byte, 16)
	for o := 0; o < 16; o++ {
		r[o] = 92 ^ key[o]
	}

	n := xxhash.New32()
	s := xxhash.New32()

	n.Write(r)

	for o := 0; o < 16; o++ {
		r[o] ^= 106
	}

	s.Write(r)
	s.Write(data)
	a := s.Sum32()
	aHex := fmt.Sprintf("%08x", a)

	n.Write(ParseHexToSlice(aHex))
	c := n.Sum32()
	cHex := fmt.Sprintf("%08x", c)
	d := ParseHexToSlice(cHex)
	return d
}

func ParseHexToSlice(t string) []byte {
	e := make([]byte, 0)
	i := 0
	n := len(t)

	for i < n {
		_i, err := hex.DecodeString(t[i : i+2])
		if err != nil {
			_i, _ = hex.DecodeString("10")
		}
		e = append(e, _i...)
		i += 2
	}
	return e
}

func EncEncKey(key *rsa.PublicKey, encryptKey []byte) string {
	encrypted, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, key, encryptKey, nil)
	if err != nil {
		fmt.Println("Error encrypting data:", err)
	}
	encodedKey := "0005" + base64.StdEncoding.EncodeToString(encrypted)
	return encodedKey
}

func Xor(buf []byte) []byte {
	bufLength := len(buf) / 2
	buf2 := make([]byte, bufLength)

	for i := 0; i < bufLength; i++ {
		buf2[i] = buf[i] ^ buf[bufLength+i]
	}

	return buf2
}

func CombineBytesToResult(d []byte, i int) []byte {
	result := (int(d[i])&255)<<8 | int(d[i+1])&255
	return []byte{byte(result >> 8), byte(result & 0xFF)}
}

func AccessAndTransformElement(d []byte, i int) byte {
	if i >= 0 && i < len(d) {
		t := d[i]
		if t > 127 {
			t = byte(0 - (t - 1 ^ 255))
		}
		return t
	}
	return 0
}
