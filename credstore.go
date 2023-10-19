package gocredstore

import (
	"errors"
	"runtime"

	"github.com/affix/gocredstore/pkg/darwin"
	"github.com/affix/gocredstore/pkg/linux"
	"github.com/affix/gocredstore/pkg/wincred"
)

type credstore interface {
	Write(itemName string, itemValue []byte) error
	Read(itemName string) ([]byte, error)
	Delete(itemName string) error
}

// CredWrite stores an item in the credential store with the given itemName and itemValue.
// It returns an error if the item cannot be stored.
func CredWrite(itemName string, itemValue []byte, appName string) error {
	store := credstore(nil)
	switch runtime.GOOS {
	case "windows":
		store = &wincred.WindowsCredStore{
			Name: appName,
		}
		itemValue = wincred.CredBlob(itemValue)
	case "darwin":
		store = &darwin.DarwinCredStore{
			Name: appName,
		}
	case "linux":
		store = &linux.LinuxCredStore{
			Name: appName,
		}
	default:
		return errors.New("unsupported operating system")
	}

	return store.Write(itemName, itemValue)
}

// CredRead retrieves an item from the credential store with the given itemName.
// It returns an error if the item cannot be found.
func CredRead(itemName string, appName string) ([]byte, error) {
	store := credstore(nil)
	switch runtime.GOOS {
	case "windows":
		store = &wincred.WindowsCredStore{
			Name: appName,
		}
	case "darwin":
		store = &darwin.DarwinCredStore{
			Name: appName,
		}
	case "linux":
		store = &linux.LinuxCredStore{
			Name: appName,
		}
	default:
		return nil, errors.New("unsupported operating system")
	}

	return store.Read(itemName)
}

// CredDelete removes an item from the credential store with the given itemName.
// It returns an error if the item cannot be found or deleted.
func CredDelete(itemName string, appName string) error {
	store := credstore(nil)
	switch runtime.GOOS {
	case "windows":
		store = &wincred.WindowsCredStore{
			Name: appName,
		}
	case "darwin":
		store = &darwin.DarwinCredStore{
			Name: appName,
		}
	case "linux":
		store = &linux.LinuxCredStore{
			Name: appName,
		}
	default:
		return errors.New("unsupported operating system")
	}

	return store.Delete(itemName)
}
