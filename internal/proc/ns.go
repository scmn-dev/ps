package proc

import (
	"fmt"
	"os"
)

type IDMap struct {
	ContainerID int
	HostID      int
	Size        int
}

func ParsePIDNamespace(pid string) (string, error) {
	pidNS, err := os.Readlink(fmt.Sprintf("/proc/%s/ns/pid", pid))
	if err != nil {
		return "", err
	}

	return pidNS, nil
}
