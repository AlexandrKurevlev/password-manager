package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"
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

const (
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorReset  = "\033[0m"
)

func clearScreen() {
	fmt.Println("\033[H\033[2J")
}

func showSuccess(message string) {
	fmt.Println(colorGreen + message + colorReset)
}

func showError(message string) {
	fmt.Println(colorRed + message + colorReset)
}

func showInfo(message string) {
	fmt.Println(colorYellow + message + colorReset)
}

func waitForEnter() {
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
}

func ReadUserInput(prompt string) (string, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

func readPassword() (string, error) {
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println()
	return string(pass), nil
}

func ShowMainMenu() {
	clearScreen()
	fmt.Println("==========================================")
	fmt.Println("           Password Manager")
	fmt.Println("==========================================")
	fmt.Println("1. Generate new password")
	fmt.Println("2. Add new password")
	fmt.Println("3. Get password")
	fmt.Println("4. List all passwords")
	fmt.Println("5. Update password")
	fmt.Println("6. Delete password")
	fmt.Println("7. List categories")
	fmt.Println("8. Show password statistics")
	fmt.Println("9. Find duplicate passwords")
	fmt.Println("0. Exit")
	fmt.Println("==========================================")
}

func PrintPasswordList(passwords []Password) {
	fmt.Println("=== Password list ===")
	fmt.Printf("%-20s %-20s %-20s %-20s\n", "Name", "Category", "Created", "Last Modified")
	for _, pass := range passwords {
		fmt.Printf("%-20s %-20s %-20s %-20s\n", pass.Name, pass.Category, pass.CreatedAt.Format("2006-01-02"), pass.LastModified.Format("2006-01-02"))
	}
}

func ShowPasswordDetails(password Password) {
	fmt.Println("=== Password details ===")
	fmt.Println("Service:", password.Name)
	fmt.Println("Category:", password.Category)
	fmt.Println("Password:", password.Value)
	fmt.Println("Created:", password.CreatedAt.Format("2006-01-02 03:04:05"))
	fmt.Println("Last Modified:", password.LastModified.Format("2006-01-02 03:04:05"))
}

func HandlePasswordGeneration(pm *PasswordManager) {
	clearScreen()
	fmt.Println("=== Password Generation ===")
	input, err := ReadUserInput("Enter password length (min 8): ")
	if err != nil {
		showError(err.Error())
		return
	}

	length, err := strconv.Atoi(input)
	if err != nil {
		showError(err.Error())
		return
	}

	pass, err := pm.GeneratePassword(length)
	if err != nil {
		showError(err.Error())
		return
	}
	showSuccess("Password generated successfully")
	fmt.Println("Generated password:", pass)

	fmt.Println("Press Enter to continue...")
	waitForEnter()
}

func HandlePasswordAdd(pm *PasswordManager) {
	clearScreen()
	fmt.Println("=== Add New Password ===")
	serviceName, err := ReadUserInput("Enter service name: ")
	if err != nil {
		showError(err.Error())
		return
	}

	fmt.Print("Enter password (or press Enter to generate):")
	pass, err := readPassword()
	if err != nil {
		showError(err.Error())
		return
	}
	if len(pass) == 0 {
		pass, err = pm.GeneratePassword(14)
		if err != nil {
			showError(err.Error())
			return
		}
		showInfo("Generated password: " + pass)
	}

	category, err := ReadUserInput("Enter category: ")
	if err != nil {
		showError(err.Error())
		return
	}

	err = pm.SavePassword(serviceName, pass, category)
	if err != nil {
		showError(err.Error())
		return
	}
	showSuccess("Password saved successfully")

	fmt.Println("Press Enter to continue...")
	waitForEnter()
}

func HandlePasswordUpdate(pm *PasswordManager) {
	clearScreen()
	fmt.Println("=== Update Password ===")
	serviceName, err := ReadUserInput("Enter service name: ")
	if err != nil {
		showError(err.Error())
		return
	}

	_, err = pm.GetPassword(serviceName)
	if err != nil {
		showError(err.Error())
		return
	}

	fmt.Print("Enter new password (or press Enter to generate):")
	pass, err := readPassword()
	if err != nil {
		showError(err.Error())
		return
	}
	if len(pass) == 0 {
		pass, err = pm.GeneratePassword(14)
		if err != nil {
			showError(err.Error())
			return
		}
		showInfo("Generated password: " + pass)
	}

	err = pm.UpdatePassword(serviceName, pass)
	if err != nil {
		showError(err.Error())
		return
	}
	showSuccess("Password saved successfully")
	fmt.Println("Press Enter to continue...")
	waitForEnter()
}

func HandlePasswordSearch(pm *PasswordManager) {
	clearScreen()
	fmt.Println("=== Search Password ===")
	serviceName, err := ReadUserInput("Enter service name: ")
	if err != nil {
		showError(err.Error())
		return
	}

	pass, err := pm.GetPassword(serviceName)
	if err != nil {
		showError(err.Error())
		return
	}

	showSuccess("Password found")

	ShowPasswordDetails(pass)
	fmt.Println("Press Enter to continue...")
	waitForEnter()
}

func HandleExitAndSave(pm *PasswordManager) error {
	clearScreen()
	fmt.Println("=== Saving and Exiting ===")
	fmt.Println("Saving changes...")
	err := pm.SaveToFile()
	if err != nil {
		return fmt.Errorf("error saving data: %q", err)
	}

	showSuccess("Changes saved successfully!")
	showSuccess("Goodbye!")

	return nil
}

func main() {
	pm := NewPasswordManager("passwords.txt")
	fmt.Println("=== Password Manager Initialization ===")
	fmt.Print("Enter master password: ")
	pass, err := readPassword()
	if err != nil {
		showError(err.Error())
		return
	}

	err = pm.SetMasterPassword(pass)
	if err != nil {
		showError(err.Error())
		return
	}

	showSuccess("Password manager initialized successfully")

	err = pm.LoadFromFile()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		showError(err.Error())
		return
	}

	fmt.Println("Press Enter to continue...")
	waitForEnter()

	for {
		ShowMainMenu()
		choice, err := ReadUserInput("Enter your choice: ")
		if err != nil {
			showError(err.Error())
			return
		}
		choice = strings.TrimSpace(choice)
		command, err := strconv.Atoi(choice)
		if err != nil {
			showError(err.Error())
			return
		}

		switch command {
		case 1:
			genPass, err := pm.GeneratePassword(14)
			if err != nil {
				showError(err.Error())
				return
			}
			showSuccess("Generated password: " + genPass)
		case 2:
			HandlePasswordAdd(pm)
		case 3:
			HandlePasswordSearch(pm)
		case 4:
			PrintPasswordList(pm.ListPasswords())
		case 5:
			HandlePasswordUpdate(pm)
		case 6:
			serviceName, err := ReadUserInput("Enter service name: ")
			if err != nil {
				showError(err.Error())
				return
			}
			err = pm.DeletePassword(serviceName)
			if err != nil {
				showError(err.Error())
				return
			}
			showSuccess("Password deleted successfully")
		case 7:
			for _, cat := range pm.ListCategories() {
				fmt.Println(cat)
			}
		case 8:
			stats := pm.GetPasswordStats()
			fmt.Println("Total:", stats["total"])
			if stats["total"].(int) != 0 {
				fmt.Println("Oldest password:", stats["oldest"])
				fmt.Println("Newest password:", stats["newest"])
				fmt.Println("Stats by categories")
				for cat, catCount := range stats["categories"].(map[string]int) {
					fmt.Println(cat, "=>", catCount)
				}
			}
		case 9:
			duplicates := pm.FindDuplicatePasswords()
			for cat, _ := range duplicates {
				fmt.Println("Cat:")
				for _, p := range duplicates[cat] {
					fmt.Println("\t", p)
				}
			}
		case 0:
			err = HandleExitAndSave(pm)
			if err != nil {
				showError(err.Error())
				return
			}
			return
		}
	}
}
