//go:build darwin
// +build darwin

package darwin

import (
	"github.com/keybase/go-keychain"
)

type DarwinCredStore struct{}

func (d *DarwinCredStore) Write(itemName string, itemValue []byte) error {
	item := keychain.NewGenericPassword(itemName, "gocredstore", "", itemValue, "")
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)
	err := keychain.AddItem(item)
	if err != nil {
		return err
	}
	return nil
}

func (d *DarwinCredStore) Delete(itemName string) error {
	return keychain.DeleteGenericPasswordItem(itemName)
}

func (d *DarwinCredStore) Read(itemName string) ([]byte, error) {
	item, err := keychain.GetGenericPassword(itemName, "gocredstore", "", "")
	if err != nil {
		return nil, err
	}
	return item.Data, nil
}
