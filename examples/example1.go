package main

import (
	"fmt"
	"log"

	"github.com/manucorporat/easyPGP"
)

func main() {
	publicKey, err := pgp.LoadPublicKey("publicKey.gpg")
	PanicIf(err)

	plaintext := []byte("hola que tal estas?")
	encrypted, err := pgp.AsymmetricEncryptWithArmor(plaintext, publicKey, nil)
	PanicIf(err)

	fmt.Println(encrypted)
}

func PanicIf(err error) {
	if err != nil {
		log.Panicln(err)
	}
}
