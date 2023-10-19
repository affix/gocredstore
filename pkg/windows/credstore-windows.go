package windows

import (
	"syscall"
	"unsafe"
)

type WindowsCredStore struct{}

type CredBlob []byte

// CREDENTIAL is a Windows API structure that contains credential data.
// See https://docs.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw
type CREDENTIAL struct {
	Flags              uint32
	Type               uint32
	TargetName         string
	Comment            string
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     []byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           string
}

// Credential types
const (
	CRED_TYPE_GENERIC          = 1
	CRED_PERSIST_LOCAL_MACHINE = 2
	CRED_PERSIST_ENTERPRISE    = 3
)

// Read retrieves a credential from the Windows Credential Manager.
func (w *WindowsCredential) Read(targetName string, typ uint32) ([]byte, error) {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")

	var cred *CREDENTIAL
	var credPtr uintptr
	var err error

	credPtr, err = syscall.UTF16PtrFromString(targetName)
	if err != nil {
		return nil, err
	}

	// Call Windows API
	ret, _, err := advapi32.NewProc("CredReadW").Call(credPtr, typ, 0, uintptr(unsafe.Pointer(&cred)))
	if ret == 0 {
		return nil, err
	}

	credBlob := make([]byte, cred.CredentialBlobSize)
	copy(credBlob, cred.CredentialBlob)

	return credBlob, nil
}

// Write stores a credential in the Windows Credential Manager.
func (w *WindowsCredential) Write(targetName string, credBlob []byte, typ uint32) error {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	var cred *CREDENTIAL
	var credPtr uintptr
	var err error

	credPtr, err = syscall.UTF16PtrFromString(targetName)
	if err != nil {
		return err
	}

	// Call Windows API
	ret, _, err := advapi32.NewProc("CredWriteW").Call(credPtr, typ, 0, uintptr(unsafe.Pointer(&cred)))
	if ret == 0 {
		return err
	}

	return nil
}

// Delete removes a credential from the Windows Credential Manager.
func (w *WindowsCredential) Delete(targetName string, typ uint32) error {
	var cred *CREDENTIAL
	var credPtr uintptr
	var err error

	credPtr, err = syscall.UTF16PtrFromString(targetName)
	if err != nil {
		return err
	}

	// Call Windows API
	ret, _, err := advapi32.NewProc("CredDeleteW").Call(credPtr, typ, 0)
	if ret == 0 {
		return err
	}

	return nil
}
