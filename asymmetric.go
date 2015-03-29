package pgp

import (
	"bytes"
	"errors"
	"io"
	"os"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

func NewPublicKey(buffer io.Reader) (*openpgp.Entity, error) {
	return newKey(buffer, openpgp.PublicKeyType)
}

func LoadPublicKey(filename string) (*openpgp.Entity, error) {
	return loadKeyFromFile(filename, openpgp.PublicKeyType)
}

func NewPrivateKey(buffer io.Reader, passphrase []byte) (*openpgp.Entity, error) {
	if key, err := newKey(buffer, openpgp.PrivateKeyType); err == nil {
		return decryptKey(key, passphrase)
	} else {
		return nil, err
	}
}

func LoadPrivateKey(filename string, passphrase []byte) (*openpgp.Entity, error) {
	if key, err := loadKeyFromFile(filename, openpgp.PrivateKeyType); err == nil {
		return decryptKey(key, passphrase)
	} else {
		return nil, err
	}
}

func AsymmetricEncrypt(plaintext []byte, publicKey, privateKey *openpgp.Entity) ([]byte, error) {
	buffer := new(bytes.Buffer)
	err := asymmetricallyEncryptToBuffer(buffer, plaintext, publicKey, privateKey)
	if err == nil {
		return buffer.Bytes(), nil
	} else {
		return nil, err
	}
}

func AsymmetricEncryptWithArmor(plaintext []byte, publicKey, privateKey *openpgp.Entity) (string, error) {
	buffer := new(bytes.Buffer)
	w, err := armor.Encode(buffer, "PGP MESSAGE", nil)
	if err != nil {
		return "", err
	}
	err = asymmetricallyEncryptToBuffer(w, plaintext, publicKey, privateKey)
	w.Close()

	if err == nil {
		return buffer.String(), nil
	} else {
		return "", err
	}
}

func newKey(buffer io.Reader, expectedType string) (*openpgp.Entity, error) {
	block, err := armor.Decode(buffer)
	if err != nil {
		return nil, err
	}
	if block.Type != expectedType {
		return nil, errors.New("key is not a " + expectedType)
	}
	reader := packet.NewReader(block.Body)
	return openpgp.ReadEntity(reader)
}

func decryptKey(key *openpgp.Entity, passphrase []byte) (*openpgp.Entity, error) {
	if len(passphrase) > 0 && key != nil {
		err := key.PrivateKey.Decrypt(passphrase)
		if err != nil {
			return nil, err
		}
	}
	return key, nil
}

func loadKeyFromFile(filename string, expectedType string) (*openpgp.Entity, error) {
	if file, err := os.Open(filename); err == nil {
		defer file.Close()
		return newKey(file, expectedType)
	} else {
		return nil, err
	}
}

func asymmetricallyEncryptToBuffer(buffer io.Writer, plaintext []byte, publicKey *openpgp.Entity, privateKey *openpgp.Entity) error {
	writer, err := openpgp.Encrypt(buffer, []*openpgp.Entity{publicKey}, privateKey, nil, nil)
	if err != nil {
		return err
	}
	_, err = writer.Write(plaintext)
	writer.Close()
	return err
}
