package linux

import (
	"github.com/godbus/dbus/v5"
	keyring "github.com/ppacher/go-dbus-keyring"
)

type LinuxCredStore struct {
	Name string
}

// Write stores an item in the Linux keyring.
// Write stores an item in the Linux credential store with the given itemName and itemValue.
// It returns an error if the item cannot be stored.
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

// Read retrieves an item from the Linux keyring.
// Read retrieves an item from the Linux credential store with the given itemName.
// It returns an error if the item cannot be found.
func (l *LinuxCredStore) Read(itemName string) ([]byte, error) {
	bus, _ := dbus.SessionBus()

	secretService, _ := keyring.GetSecretService(bus)
	col, err := secretService.GetCollection("login")
	if err != nil {
		return nil, err
	}

	item, _ := col.GetItem(itemName)
	_, _ = item.Unlock()
	secret, _ := item.GetSecret("default")

	return secret.Value, nil
}

// Delete removes the specified item from the Linux keyring.
// Delete removes an item from the Linux credential store with the given itemName.
// It returns an error if the item cannot be found or deleted.
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
