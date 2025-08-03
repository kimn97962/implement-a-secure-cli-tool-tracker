package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh/terminal"
)

// Config holds configuration for the CLI tool tracker
type Config struct {
	Password string
	Salt     string
}

// Tracker holds a list of trackers
type Tracker struct {
	ID   string
	Name string
}

// Trackers is a slice of Tracker
type Trackers []Tracker

// loadConfig loads configuration from a file
func loadConfig(path string) (*Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var config Config
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// saveConfig saves configuration to a file
func saveConfig(path string, config *Config) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(config)
	if err != nil {
		return err
	}

	return nil
}

// encrypt encrypts data using AES
func encrypt(data []byte, password string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(password))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decrypt decrypts data using AES
func decrypt(data []byte, password string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(password))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// hashPassword hashes a password using bcrypt
func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// verifyPassword verifies a password using bcrypt
func verifyPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func main() {
	configPath := flag.String("config", "./config.json", "path to config file")
	add := flag.Bool("add", false, "add a new tracker")
	delete := flag.Bool("delete", false, "delete a tracker")
	list := flag.Bool("list", false, "list all trackers")
.flag.Parse()

	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	if *add {
		fmt.Print("Enter tracker name: ")
		var name string
		fmt.Scanln(&name)

		fmt.Print("Enter password: ")
		password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Fatal(err)
		}

		hash, err := hashPassword(string(password))
		if err != nil {
			log.Fatal(err)
		}

		tracker := Tracker{
			ID:   uuid.New().String(),
			Name: name,
		}

		trackers := Trackers{tracker}
		data, err := json.Marshal(trackers)
		if err != nil {
			log.Fatal(err)
		}

		encrypted, err := encrypt(data, config.Password)
		if err != nil {
			log.Fatal(err)
		}

		err = os.WriteFile("trackers.txt", encrypted, 0600)
		if err != nil {
			log.Fatal(err)
		}
	} else if *delete {
		fmt.Print("Enter tracker ID: ")
		var id string
		fmt.Scanln(&id)

		file, err := os.ReadFile("trackers.txt")
		if err != nil {
			log.Fatal(err)
		}

		decrypted, err := decrypt(file, config.Password)
		if err != nil {
			log.Fatal(err)
		}

		var trackers Trackers
		err = json.Unmarshal(decrypted, &trackers)
		if err != nil {
			log.Fatal(err)
		}

		for i, tracker := range trackers {
			if tracker.ID == id {
				trackers = append(trackers[:i], trackers[i+1:]...)
				break
			}
		}

		data, err := json.Marshal(trackers)
		if err != nil {
			log.Fatal(err)
		}

		encrypted, err := encrypt(data, config.Password)
		if err != nil {
			log.Fatal(err)
		}

		err = os.WriteFile("trackers.txt", encrypted, 0600)
		if err != nil {
			log.Fatal(err)
		}
	} else if *list {
		file, err := os.ReadFile("trackers.txt")
		if err != nil {
			log.Fatal(err)
		}

		decrypted, err := decrypt(file, config.Password)
		if err != nil {
			log.Fatal(err)
		}

		var trackers Trackers
		err = json.Unmarshal(decrypted, &trackers)
		if err != nil {
			log.Fatal(err)
		}

		for _, tracker := range trackers {
			fmt.Println(tracker.Name)
		}
	} else {
		fmt.Println("Invalid command")
	}
}