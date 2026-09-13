package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type Password struct {
	Name         string    `json:"name"`
	Value        string    `json:"value"`
	Category     string    `json:"category"`
	CreatedAt    time.Time `json:"created_at"`
	LastModified time.Time `json:"last_modified"`
}

func NewPassword(name, value, category string) Password {
	return Password{
		Name:         name,
		Value:        value,
		Category:     category,
		CreatedAt:    time.Now(),
		LastModified: time.Now(),
	}
}

type PasswordManager struct {
	passwords     map[string]Password `json:"passwords"`
	masterKey     []byte              `json:"-"`
	filePath      string              `json:"-"`
	isInitialized bool                `json:"-"`
}

func NewPasswordManager(filePath string) *PasswordManager {
	return &PasswordManager{
		passwords:     make(map[string]Password),
		filePath:      filePath,
		isInitialized: false,
	}
}

func (pm *PasswordManager) SetMasterPassword(masterPassword string) error {
	if len(masterPassword) < 8 {
		return fmt.Errorf("password is too weak")
	}

	masterKey := make([]byte, 32)
	copy(masterKey, masterPassword)
	pm.masterKey = masterKey
	pm.isInitialized = true
	return nil
}

func (pm *PasswordManager) SavePassword(name, value, category string) error {
	if !pm.isInitialized {
		return fmt.Errorf("password manager is not initialized")
	}

	if _, present := pm.passwords[name]; present {
		return fmt.Errorf("password already exist")
	}

	pm.passwords[name] = NewPassword(name, value, category)
	return nil
}

func (pm *PasswordManager) UpdatePassword(name, newValue string) error {
	if !pm.isInitialized {
		return fmt.Errorf("password manager is not initialized")
	}

	if pass, present := pm.passwords[name]; present {
		err := pm.CheckPasswordStrength(newValue)
		if err != nil {
			return err
		}

		pass.Value = newValue
		pass.LastModified = time.Now()
		pm.passwords[name] = pass
	} else {
		return fmt.Errorf("password not found")
	}

	return nil
}

func (pm *PasswordManager) DeletePassword(name string) error {
	if !pm.isInitialized {
		return fmt.Errorf("password manager is not initialized")
	}

	if _, present := pm.passwords[name]; present {
		delete(pm.passwords, name)
	} else {
		return fmt.Errorf("password not found")
	}

	return nil
}

func (pm *PasswordManager) GetPassword(name string) (Password, error) {
	if !pm.isInitialized {
		return Password{}, fmt.Errorf("password manager not initialized")
	}

	if pass, present := pm.passwords[name]; present {
		return pass, nil
	}

	return Password{}, fmt.Errorf("password not found")
}

func (pm *PasswordManager) ListPasswords() []Password {
	passwords := make([]Password, 0, len(pm.passwords))
	for _, pass := range pm.passwords {
		passwords = append(passwords, pass)
	}

	return passwords
}

func (pm *PasswordManager) GetPasswordsByCategory(category string) []Password {
	var passwords []Password
	for _, pass := range pm.passwords {
		if pass.Category == category {
			passwords = append(passwords, pass)
		}
	}
	return passwords
}

func (pm *PasswordManager) ListCategories() []string {
	categories := make(map[string]bool)
	for _, pass := range pm.passwords {
		categories[pass.Category] = true
	}

	res := make([]string, 0, len(categories))
	for cat := range categories {
		res = append(res, cat)
	}
	return res
}

func (pm *PasswordManager) GetPasswordStats() map[string]interface{} {
	res := make(map[string]interface{})
	res["total"] = len(pm.passwords)

	if len(pm.passwords) == 0 {
		return res
	}

	categories := make(map[string]int)
	var newest time.Time
	var oldest = time.Now()
	for _, pass := range pm.passwords {
		if pass.CreatedAt.After(newest) {
			newest = pass.CreatedAt
		}
		if pass.CreatedAt.Before(oldest) {
			oldest = pass.CreatedAt
		}
		categories[pass.Category] += 1
	}
	res["categories"] = categories
	res["oldest"] = oldest
	res["newest"] = newest
	return res
}

func (pm *PasswordManager) FindDuplicatePasswords() map[string][]string {
	duplicates := make(map[string][]string)
	for _, pass := range pm.passwords {
		duplicates[pass.Value] = append(duplicates[pass.Value], pass.Name)
	}

	for key := range duplicates {
		if len(duplicates[key]) == 1 {
			delete(duplicates, key)
		}
	}

	return duplicates
}

func (pm *PasswordManager) GeneratePassword(length int) (string, error) {
	if length < 8 {
		return "", fmt.Errorf("password is too weak")
	}

	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+!@#$%^&*"

	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}

	for i := range key {
		key[i] = charset[key[i]%byte(len(charset))]
	}

	return string(key), nil
}

func (pm *PasswordManager) SaveToFile() error {
	if !pm.isInitialized {
		return fmt.Errorf("password manager not initialized")
	}

	data, err := json.Marshal(pm.passwords)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return err
	}

	encryptedData := gcm.Seal(nil, nonce, data, nil)

	file, err := os.Create(pm.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(nonce)
	if err != nil {
		return err
	}
	_, err = file.Write(encryptedData)
	if err != nil {
		return err
	}
	return nil
}

func (pm *PasswordManager) LoadFromFile() error {
	if !pm.isInitialized {
		return fmt.Errorf("password manager not initialized")
	}

	file, err := os.Open(pm.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	block, err := aes.NewCipher(pm.masterKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(file, nonce)
	if err != nil {
		return err
	}

	encryptedData, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	data, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &pm.passwords)
	if err != nil {
		return err
	}

	return nil
}

func (pm *PasswordManager) CheckPasswordStrength(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password is too weak")
	}

	symbols := "!@#$%^&*"
	hasLowerCase, hasUpperCase, hasDigit, hasSymbol := false, false, false, false
	for _, r := range password {
		if r >= 'a' && r <= 'z' {
			hasLowerCase = true
			continue
		}
		if r >= 'A' && r <= 'Z' {
			hasUpperCase = true
			continue
		}
		if r >= '0' && r <= '9' {
			hasDigit = true
			continue
		}
		if strings.ContainsRune(symbols, r) {
			hasSymbol = true
		}
	}

	if !(hasLowerCase && hasUpperCase && hasDigit && hasSymbol) {
		return fmt.Errorf("password is too weak")
	}

	return nil
}

func main() {
}
