package proc

import (
	"bytes"
	"fmt"
	"io/ioutil"
)

func ParseCmdLine(pid string) ([]string, error) {
	data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%s/cmdline", pid))
	if err != nil {
		return nil, err
	}

	cmdLine := []string{}
	for _, rawCmd := range bytes.Split(data, []byte{0}) {
		cmdLine = append(cmdLine, string(rawCmd))
	}

	return cmdLine, nil
}
