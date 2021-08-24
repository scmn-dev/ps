package proc

import (
	"bufio"
	"fmt"
	"io"
	"os"

	"github.com/pkg/errors"
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

func ParseUserNamespace(pid string) (string, error) {
	userNS, err := os.Readlink(fmt.Sprintf("/proc/%s/ns/user", pid))
	if err != nil {
		return "", err
	}

	return userNS, nil
}

func ReadMappings(path string) ([]IDMap, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.Wrapf(err, "cannot open %s", path)
	}

	defer file.Close()

	mappings := []IDMap{}

	buf := bufio.NewReader(file)
	for {
		line, _, err := buf.ReadLine()
		if err != nil {
			if err == io.EOF {
				return mappings, nil
			}

			return nil, errors.Wrapf(err, "cannot read line from %s", path)
		}

		if line == nil {
			return mappings, nil
		}

		containerID, hostID, size := 0, 0, 0
		if _, err := fmt.Sscanf(string(line), "%d %d %d", &containerID, &hostID, &size); err != nil {
			return nil, errors.Wrapf(err, "cannot parse %s", string(line))
		}

		mappings = append(mappings, IDMap{ContainerID: containerID, HostID: hostID, Size: size})
	}
}
