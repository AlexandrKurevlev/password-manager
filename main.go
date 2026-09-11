package main

import (
	"fmt"
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
	passwords := make([]Password, len(pm.passwords))
	for _, pass := range pm.passwords {
		passwords = append(passwords, pass)
	}

	return passwords
}

func main() {
}
