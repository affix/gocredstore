//go:build linux
// +build linux

package linux

import (
	"github.com/godbus/dbus/v5"
	keyring "github.com/ppacher/go-dbus-keyring"
)

type LinuxCredStore struct{}

func (l *LinuxCredStore) Write(itemName string, itemValue []byte) error {
	bus, _ := dbus.SessionBus()

	secretService, _ := keyring.GetSecretService(bus)
	col, err := secretService.GetCollection("login")
	if err != nil {
		col, _ = secretService.CreateCollection("login", "default")
	}

	col.CreateItem("default", itemName, map[string]string{}, itemValue, "text/plain", true)
	return nil
}

func (l *LinuxCredStore) Read(itemName string) ([]byte, error) {
	bus, _ := dbus.SessionBus()

	secretService, _ := keyring.GetSecretService(bus)
	col, err := secretService.GetCollection("login")
	if err != nil {
		return nil, err
	}

	item, _ := col.GetItem(itemName)
	_, _ = item.Unlock()
	secret, _ := item.GetSecret()

	return secret.Value, nil
}

func (l *LinuxCredStore) Delete(itemName string) error {
	bus, _ := dbus.SessionBus()

	secretService, _ := keyring.GetSecretService(bus)
	col, err := secretService.GetCollection("login")
	if err != nil {
		return err
	}

	item, _ := col.GetItem(itemName)
	_, _ = item.Unlock()
	_ = item.Delete()

	return nil
}
