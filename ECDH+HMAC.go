package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func main() {
	//---------------------------------MQTT-------------------------------------

	//--------------------------------------------------------------------------
	fmt.Printf("--ECC Parameters--\n")
	fmt.Printf(" Name: %s\n", elliptic.P256().Params().Name)
	fmt.Printf(" N: %x\n", elliptic.P256().Params().N)
	fmt.Printf(" P: %x\n", elliptic.P256().Params().P)
	fmt.Printf(" Gx: %x\n", elliptic.P256().Params().Gx)
	fmt.Printf(" Gy: %x\n", elliptic.P256().Params().Gy)

	fmt.Printf(" Bitsize: %x\n\n", elliptic.P256().Params().BitSize)
	//---------------------------------WORK-ECDH-------------------------------------
	priva, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privb, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	puba := priva.PublicKey
	pubb := privb.PublicKey

	a, _ := puba.Curve.ScalarMult(puba.X, puba.Y, privb.D.Bytes())
	b, _ := pubb.Curve.ScalarMult(pubb.X, pubb.Y, priva.D.Bytes())

	shared1 := sha256.Sum256(a.Bytes())
	shared2 := sha256.Sum256(b.Bytes())

	//--------------------------------HMAC-------------------------------------------

	data := "data"
	slice := shared1[:]
	slice2 := shared2[:]

	// Create a new HMAC by defining the hash type and the key (as byte array)
	h := hmac.New(sha256.New, []byte(slice))
	g := hmac.New(sha256.New, []byte(slice2))

	// Write Data to it
	h.Write([]byte(data))
	g.Write([]byte(data))

	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))
	sha2 := hex.EncodeToString(g.Sum(nil))

	//-------------------------------ALICE-------------------------------------------

	fmt.Printf("\nKunci Pribadi (Alice)\t: %x", priva.D)
	fmt.Printf("\nKunci Publik (Alice)\t: (%x,%x)", puba.X, puba.Y)
	fmt.Printf("\nKunci Rahasia (Alice)\t: %x\n", shared1)
	fmt.Printf("Hasil Hash (Alice)\t: %x", sha)

	//----------------------------------BOB-----------------------------------------------

	fmt.Printf("\n\nKunci Pribadi (Bob)\t: %x", privb.D)
	fmt.Printf("\nKunci Publik (Bob)\t: (%x,%x)", pubb.X, pubb.Y)
	fmt.Printf("\nKunci Rahasia (Bob)\t: %x", shared2)
	fmt.Printf("\nHasil Hash (Bob)\t: %x", sha2)

	//-------------------------Verifikasi-------------------------------------------------

	if !((sha) == (sha2)) {
		fmt.Printf("\n\nVerifikasi Gagal\n")
	} else {
		fmt.Printf("\n\nVerifikasi Berhasil\n")
	}

}
