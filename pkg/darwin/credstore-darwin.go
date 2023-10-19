package darwin

import (
	"github.com/keybase/go-keychain"
)

type DarwinCredStore struct {
	Name string
}

// Write stores an item in the Darwin keychain.
// Write stores an item in the Darwin credential store with the given itemName and itemValue.
// It returns an error if the item cannot be stored.
func (d *DarwinCredStore) Write(itemName string, itemValue []byte) error {
	item := buildItem(itemName)
	item.SetSynchronizable(keychain.SynchronizableNo)
	item.SetAccessible(keychain.AccessibleWhenUnlocked)
	err := keychain.AddItem(item)
	if err != nil {
		return err
	}
	return nil
}

// Read retrieves an item from the Darwin keychain.
// Read retrieves an item from the Darwin credential store with the given itemName.
// It returns an error if the item cannot be found.
func (d *DarwinCredStore) Delete(itemName string) error {
	item := buildItem(itemName)
	return keychain.DeleteItem(item)
}

// Delete removes the specified item from the Darwin keychain.
// Delete removes an item from the Darwin credential store with the given itemName.
// It returns an error if the item cannot be found or deleted.
func (d *DarwinCredStore) Read(itemName string) ([]byte, error) {
	query := d.buildItem(itemName)
	query.SetMatchLimit(keychain.MatchLimitOne)
	query.SetReturnData(true)
	results, err := keychain.QueryItem(query)
	if err != nil {
		return nil, err
	}
	password := string(results[0].Data)

	return password, err
}

func (d *DarwinCredStore) buildItem(itemName string) keychain.Item {
	item := keychain.NewItem()
	item.SetSecClass(keychain.SecClassGenericPassword)
	item.SetService(d.name)
	item.SetAccount(itemName)
	item.SetLabel(itemName)
	return item
}
