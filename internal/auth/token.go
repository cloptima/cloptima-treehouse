// Package auth stores the daemon's access token: keychain first,
// credentials-file fallback, env var override. The token is minted by the web
// app during `treehouse login` (see oauth.go, which drives that flow through the
// browser); this package holds what comes back.
package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/zalando/go-keyring"
)

const (
	EnvAccessToken        = "TREEHOUSE_ACCESS_TOKEN"
	EnvCredentialsPath    = "TREEHOUSE_CREDENTIALS_PATH"
	CredentialsDirName    = ".treehouse"
	CredentialsFileName   = "credentials.json"
	SourceKeychain        = "keychain"
	SourceCredentialsFile = "credentials_file"
	keyringService        = "treehouse-daemon"
	keyringUser           = "access-token"
)

// ErrNoAccessToken means no credential is stored -- distinct from a keychain
// that exists but could not be read (locked, or access denied to this
// binary). Callers that treat both as "not logged in" send the user back
// through a login flow that cannot fix the second case.
var ErrNoAccessToken = errors.New("no credentials found; set " + EnvAccessToken + " or run treehouse login")

type credentialsFile struct {
	AccessToken string `json:"access_token"`
}

func AccessToken() (string, error) {
	if token := strings.TrimSpace(os.Getenv(EnvAccessToken)); token != "" {
		return token, nil
	}

	token, _, err := StoredAccessTokenWithSource()
	if err == nil && strings.TrimSpace(token) != "" {
		return token, nil
	}
	if err != nil {
		return "", err
	}
	return "", ErrNoAccessToken
}

func StoredAccessTokenWithSource() (string, string, error) {
	token, err := keyring.Get(keyringService, keyringUser)
	if err == nil && strings.TrimSpace(token) != "" {
		return token, SourceKeychain, nil
	}

	fileToken, fileErr := fileAccessToken()
	if fileErr != nil {
		return "", "", fileErr
	}
	if strings.TrimSpace(fileToken) != "" {
		if err != nil && !errors.Is(err, keyring.ErrNotFound) {
			log.Printf("warning: falling back to credentials file after keychain read failed: %v", err)
		}
		return fileToken, SourceCredentialsFile, nil
	}

	if err != nil && errors.Is(err, keyring.ErrNotFound) {
		return "", "", nil
	}
	if err != nil {
		return "", "", fmt.Errorf("read keychain token: %w", err)
	}
	return "", "", nil
}

func SaveAccessTokenWithSource(token string) (string, error) {
	trimmed := strings.TrimSpace(token)
	if trimmed == "" {
		return "", errors.New("token cannot be empty")
	}
	if err := keyring.Set(keyringService, keyringUser, trimmed); err != nil {
		if fileErr := saveFileAccessToken(trimmed); fileErr != nil {
			return "", fmt.Errorf("store token in keychain: %w; store token in credentials file: %w", err, fileErr)
		}
		log.Printf("warning: stored token in credentials file after keychain write failed: %v", err)
		return SourceCredentialsFile, nil
	}
	return SourceKeychain, nil
}

func DeleteAccessToken() error {
	err := keyring.Delete(keyringService, keyringUser)
	fileErr := deleteFileAccessToken()
	if err != nil && !errors.Is(err, keyring.ErrNotFound) && fileErr != nil {
		return fmt.Errorf("delete keychain token: %w; delete credentials file token: %w", err, fileErr)
	}
	if err != nil && !errors.Is(err, keyring.ErrNotFound) && fileErr == nil {
		log.Printf("warning: could not delete keychain token: %v", err)
		return nil
	}
	if fileErr != nil {
		return fmt.Errorf("delete credentials file token: %w", fileErr)
	}
	return nil
}

func defaultCredentialsPath() (string, error) {
	if path := strings.TrimSpace(os.Getenv(EnvCredentialsPath)); path != "" {
		return path, nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", nil
	}
	return filepath.Join(home, CredentialsDirName, CredentialsFileName), nil
}

func fileAccessToken() (string, error) {
	path, err := defaultCredentialsPath()
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", nil
	}

	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("stat credentials file: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("credentials file %s must not be readable by group or others", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read credentials file: %w", err)
	}
	var creds credentialsFile
	if err := json.Unmarshal(data, &creds); err != nil {
		return "", fmt.Errorf("parse credentials file: %w", err)
	}
	return strings.TrimSpace(creds.AccessToken), nil
}

func saveFileAccessToken(token string) error {
	path, err := defaultCredentialsPath()
	if err != nil {
		return err
	}
	if path == "" {
		return errors.New("credentials file path is unavailable; set HOME or TREEHOUSE_CREDENTIALS_PATH")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create credentials directory: %w", err)
	}
	data, err := json.MarshalIndent(credentialsFile{AccessToken: token}, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize credentials file: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write credentials file: %w", err)
	}
	return nil
}

func deleteFileAccessToken() error {
	path, err := defaultCredentialsPath()
	if err != nil {
		return err
	}
	if path == "" {
		return nil
	}
	err = os.Remove(path)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
