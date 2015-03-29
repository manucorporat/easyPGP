package pgp

import (
	"bytes"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func SymmetricallyEncrypt(plaintext, passphrase []byte) ([]byte, error) {
	buffer := new(bytes.Buffer)
	err := symmetricallyEncryptToBuffer(buffer, plaintext, passphrase)
	if err == nil {
		return buffer.Bytes(), nil
	} else {
		return nil, err
	}
}

func SymmetricallyEncryptWithArmor(plaintext, passphrase []byte) (string, error) {
	buffer := new(bytes.Buffer)
	w, err := armor.Encode(buffer, "PGP MESSAGE", nil)
	if err != nil {
		w.Close()
		return "", err
	}
	if err = symmetricallyEncryptToBuffer(w, plaintext, passphrase); err == nil {
		w.Close()
		return buffer.String(), nil
	} else {
		return "", err
	}
}

func symmetricallyEncryptToBuffer(buffer io.Writer, plaintext, passphrase []byte) error {
	writer, err := openpgp.SymmetricallyEncrypt(buffer, passphrase, nil, nil)
	defer writer.Close()
	if err != nil {
		return err
	}
	_, err = writer.Write(plaintext)
	return err
}
