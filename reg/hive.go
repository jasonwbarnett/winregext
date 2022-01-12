//go:build windows
// +build windows

package reg

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

//sys lookupPrivilegeDisplayName(systemName string, name *uint16, buffer *uint16, size *uint32, languageId *uint32) (err error) = advapi32.LookupPrivilegeDisplayNameW

var (
	// modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	// modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procRegLoadKeyW   = modadvapi32.NewProc("RegLoadKeyW")
	procRegUnLoadKeyW = modadvapi32.NewProc("RegUnLoadKeyW")
	// procAdjustTokenPrivileges = modadvapi32.NewProc("AdjustTokenPrivileges")
)

// https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadkeyw

// LSTATUS RegLoadKeyW(
//   [in]           HKEY    hKey,
//   [in, optional] LPCWSTR lpSubKey,
//   [in]           LPCWSTR lpFile
// );

func LoadKey(k registry.Key, subkey string, file string) (regerrno error) {
	sk, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return err
	}

	f, err := syscall.UTF16PtrFromString(file)
	if err != nil {
		return err
	}

	ret, _, _ := procRegLoadKeyW.Call(uintptr(syscall.Handle(k)),
		uintptr(unsafe.Pointer(sk)),
		uintptr(unsafe.Pointer(f)))

	if ret != 0 {
		regerrno = syscall.Errno(ret)
	}
	return
}

// https://docs.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regunloadkeyw

// LSTATUS RegUnLoadKeyW(
//   [in]           HKEY    hKey,
//   [in, optional] LPCWSTR lpSubKey
// );

func UnloadKey(k registry.Key, subkey string) (regerrno error) {
	sk, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return err
	}

	ret, _, _ := procRegUnLoadKeyW.Call(uintptr(syscall.Handle(k)),
		uintptr(unsafe.Pointer(sk)))

	if ret != 0 {
		regerrno = syscall.Errno(ret)
	}
	return
}
