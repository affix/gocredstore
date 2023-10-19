package gocredstore

import (
	"errors"
	"runtime"

	"github.com/affix/gocredstore/pkg/darwin"
	"github.com/affix/gocredstore/pkg/linux"
	"github.com/affix/gocredstore/pkg/windows"
)

type credstore interface {
	Write(itemName string, itemValue []byte) error
	Read(itemName string) ([]byte, error)
	Delete(itemName string) error
}

func CredWrite(itemName string, itemValue []byte) error {
	store := credstore(nil)
	switch runtime.GOOS {
	case "windows":
		store = &windows.WindowsCredStore{}
		itemValue = windows.CredBlob(itemValue)
	case "darwin":
		store = &darwin.DarwinCredStore{}
	case "linux":
		store = &linux.LinuxCredStore{}
	default:
		return errors.New("unsupported operating system")
	}

	return store.Write(itemName, itemValue)
}

func CredRead(itemName string) ([]byte, error) {
	store := credstore(nil)
	switch runtime.GOOS {
	case "windows":
		store = &windows.WindowsCredStore{}
	case "darwin":
		store = &darwin.DarwinCredStore{}
	case "linux":
		store = &linux.LinuxCredStore{}
	default:
		return nil, errors.New("unsupported operating system")
	}

	return store.Read(itemName)
}

func CredDelete(itemName string) error {
	store := credstore(nil)
	switch runtime.GOOS {
	case "windows":
		store = &windows.WindowsCredStore{}
	case "darwin":
		store = &darwin.DarwinCredStore{}
	case "linux":
		store = &linux.LinuxCredStore{}
	default:
		return errors.New("unsupported operating system")
	}

	return store.Delete(itemName)
}
