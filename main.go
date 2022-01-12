package main

import (
	"crypto/sha1"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/jasonwbarnett/winregext/reg"
	"golang.org/x/sys/windows/registry"
)

func main() {
	err := reg.RunWithPrivileges([]string{reg.SeBackupPrivilege, reg.SeRestorePrivilege}, unmountHives)
	if err != nil {
		log.Fatal(err)
	}

	err = reg.RunWithPrivileges([]string{reg.SeBackupPrivilege, reg.SeRestorePrivilege}, mountHives)
	if err != nil {
		log.Fatal(err)
	}
}

func mountHives() error {
	hives, err := filepath.Glob(`c:\Users\*\NTUSER.DAT`)
	if err != nil {
		log.Fatalf("unable to glob NTUSER.DAT, error: %+v\n", err)
		return err
	}

	for _, f := range hives {
		parts := strings.Split(f, `\`)
		name := fmt.Sprintf("hive_%s", generateSha1(parts[2]))
		err := reg.LoadKey(registry.LOCAL_MACHINE, name, f)
		if err != nil {
			if err.Error() == "The process cannot access the file because it is being used by another process." {
				log.Printf("The file (%s) is already in use, skipping.\n", f)
			} else {
				log.Fatalf("error loading %s, error: %+v\n", f, err)
				return err
			}
		}
	}

	return nil
}

func generateSha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}

func unmountHives() error {
	keys, err := LocalMachineSubKeys()
	if err != nil {
		log.Fatalf("Unable to grab local machine sub keys, error: %+v\n", err)
		return err
	}

	for _, k := range keys {
		if strings.HasPrefix(k, "hive_") {
			log.Printf("Unloading hive %s\n", k)
			err := reg.UnloadKey(registry.LOCAL_MACHINE, k)
			if err != nil {
				log.Fatalf("error: %+v\n", err)
				return err
			}
		}
	}

	return nil
}

func LocalMachineSubKeys() (keys []string, err error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		log.Fatal(err)
	}
	defer k.Close()

	keys, err = k.ReadSubKeyNames(-1)
	return
}
