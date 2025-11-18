package crypto_utils

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
)

func Genrsakp() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func Gendhkp() (*ecdh.PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand.Reader)
}

func Compshsec(mypvk *ecdh.PrivateKey, thpubk *ecdh.PublicKey) ([]byte, error) {
	return mypvk.ECDH(thpubk)
}

func Dervaesk(shsec []byte) []byte {
	kb := sha256.Sum256(shsec)
	return kb[:]
}

func Encrsa(d []byte, pubk *rsa.PublicKey) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, pubk, d)
}

func Decrsa(d []byte, pvk *rsa.PrivateKey) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, pvk, d)
}

func pkcs5Pad(d []byte, bs int) []byte {
	padding := bs - len(d)%bs
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(d, padtext...)
}

func pkcs5Unpad(d []byte) ([]byte, error) {
	length := len(d)
	if length == 0 {
		return nil, errors.New("unpadding error: data is empty")
	}
	unpadding := int(d[length-1])
	if unpadding > length {
		return nil, fmt.Errorf("unpadding error: invalid padding size %d", unpadding)
	}
	return d[:(length - unpadding)], nil
}

func Encaes(d []byte, sk []byte) ([]byte, error) {
	block, err := aes.NewCipher(sk)
	if err != nil {
		return nil, err
	}
	paddedData := pkcs5Pad(d, block.BlockSize())
	encrypted := make([]byte, len(paddedData))

	for bs, be := 0, block.BlockSize(); bs < len(paddedData); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Encrypt(encrypted[bs:be], paddedData[bs:be])
	}
	return encrypted, nil
}

func Decaes(d []byte, sk []byte) ([]byte, error) {
	block, err := aes.NewCipher(sk)
	if err != nil {
		return nil, err
	}
	if len(d)%block.BlockSize() != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	decrypted := make([]byte, len(d))
	for bs, be := 0, block.BlockSize(); bs < len(d); bs, be = bs+block.BlockSize(), be+block.BlockSize() {
		block.Decrypt(decrypted[bs:be], d[bs:be])
	}
	return pkcs5Unpad(decrypted)
}

func Sgn(d []byte, pvk *rsa.PrivateKey) ([]byte, error) {
	h := sha256.Sum256(d)
	return rsa.SignPKCS1v15(rand.Reader, pvk, crypto.SHA256, h[:])
}

func Verifysgn(d, s []byte, pubk *rsa.PublicKey) error {
	h := sha256.Sum256(d)
	return rsa.VerifyPKCS1v15(pubk, crypto.SHA256, h[:], s)
}

func Pubktostr(pubk *rsa.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pubk)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pubBytes), nil
}

func Strtopubk(ks string) (*rsa.PublicKey, error) {
	kb, err := base64.StdEncoding.DecodeString(ks)
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(kb)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not a valid rsa public key")
	}
	return rsaPub, nil
}

func Ser(obj interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(obj); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Deser(b []byte, obj interface{}) error {
	buf := bytes.NewBuffer(b)
	dec := gob.NewDecoder(buf)
	return dec.Decode(obj)
}
