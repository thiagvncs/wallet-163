package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/ripemd160"
)

// Função para gerar a chave pública a partir da chave privada
func generatePublic(privateKey string) string {
	privKeyBytes, _ := hex.DecodeString(privateKey)
	privKey, _ := crypto.ToECDSA(privKeyBytes)
	publicKey := privKey.PublicKey
	pubKeyBytes := crypto.CompressPubkey(&publicKey)
	return hex.EncodeToString(pubKeyBytes)
}

// Função para gerar o endereço Bitcoin a partir da chave pública
func generateBitcoinAddress(publicKey string) string {
	pubKeyBytes, _ := hex.DecodeString(publicKey)
	shaHash := sha256.New()
	shaHash.Write(pubKeyBytes)
	sha256Result := shaHash.Sum(nil)

	ripemdHash := ripemd160.New()
	ripemdHash.Write(sha256Result)
	ripemd160Result := ripemdHash.Sum(nil)

	address := append([]byte{0x00}, ripemd160Result...)
	checksum := sha256.Sum256(address)
	checksum = sha256.Sum256(checksum[:])

	addressWithChecksum := append(address, checksum[:4]...)
	return base58.Encode(addressWithChecksum)
}

// Função para gerar o WIF (Wallet Import Format) a partir da chave privada
func generateWIF(privateKey string) string {
	privKeyBytes, _ := hex.DecodeString(privateKey)
	prefix := append([]byte{0x80}, privKeyBytes...)
	hash1 := sha256.Sum256(prefix)
	hash2 := sha256.Sum256(hash1[:])
	checksum := hash2[:4]
	payload := append(prefix, checksum...)

	return base58.Encode(payload)
}

func checkPrivatKeyFromWallet(wallet, privateKey string) bool {
	publicKey := generatePublic(privateKey)
	address := generateBitcoinAddress(publicKey)
	return wallet == address
}

func createRandomString(length int) string {
	rangeStr := "0123456789abcdef"
	result := make([]byte, length)

	for i := 0; i < length; i++ {
		result[i] = rangeStr[rand.Intn(len(rangeStr))]
	}

	return string(result)
}

func replaceXtoRandomNumber(privateKey, randRange string) string {
	newPrivateKey := ""
	index := 0
	for i := 0; i < len(privateKey); i++ {
		if privateKey[i] == 'x' {
			newPrivateKey += string(randRange[index])
			index++
		} else {
			newPrivateKey += string(privateKey[i])
		}
	}
	return newPrivateKey
}

func worker(wallet, privatKey string, result chan string, count *int) {
	for {
		countX := strings.Count(privatKey, "x")
		randRange := createRandomString(countX)
		newPrivateKey := replaceXtoRandomNumber(privatKey, randRange)
		walletCheck := checkPrivatKeyFromWallet(wallet, newPrivateKey)

		*count++

		if walletCheck {
			result <- newPrivateKey
			return
		}
	}
}

func main() {

	//wallet 66
	// wallet := "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"
	// privatKey := "000000000000000000000000000000000000000000000002832ed74f2b5xxxxx"

	wallet := "1Hoyt6UBzwL5vvUSTLMQC2mwvvE5PpeSC"
	privatKey := "403b3d4xcxfx6x9xfx3xaxcx5x0x4xbxbx7x2x6x8x7x8xax4x0x8x3x3x3x7x3x"

	totalKeys := 0
	startTime := time.Now()

	// Número de goroutines para rodar em paralelo
	numWorkers := 12
	result := make(chan string)

	// Contador de chaves verificadas
	count := 0

	// Inicia as goroutines (trabalhadores)
	for i := 0; i < numWorkers; i++ {
		go worker(wallet, privatKey, result, &count)
	}

	// Loop para exibir as chaves verificadas por segundo
	go func() {
		for {
			elapsedTime := time.Since(startTime).Seconds()
			keysPerSecond := float64(count) / elapsedTime
			fmt.Printf("\rChaves verificadas: %d | Chaves/s: %.2f", count, keysPerSecond)
			time.Sleep(1 * time.Second)
		}
	}()

	// Espera pelo resultado
	foundPrivateKey := <-result
	elapsedTime := time.Since(startTime).Seconds()

	// Exibe os resultados
	totalKeys = 1 // Já encontramos uma chave válida

	fmt.Println("\nAchei a chave privada")
	fmt.Println("Total de chaves verificadas:", totalKeys)
	fmt.Println("Tempo decorrido:", elapsedTime, "segundos")
	fmt.Println("Chave Privada:", foundPrivateKey)
	fmt.Println("Chave Publica:", generatePublic(foundPrivateKey))
	fmt.Println("Endereço Bitcoin:", wallet)
	fmt.Println("WIF:", generateWIF(foundPrivateKey))
}
