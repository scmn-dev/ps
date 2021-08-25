package main

import (
	"fmt"
	"strconv"
	"io/ioutil"

	"github.com/gepis/ps/internal/dev"
	"github.com/gepis/ps/internal/process"
	"github.com/pkg/errors"
)

type IDMap struct {
	ContainerID int
	HostID int
	Size int
}

type JoinNamespaceOpts struct {
	UIDMap []IDMap
	GIDMap []IDMap
	FillMappings bool
}

type psContext struct {
	containersProcesses []*process.Process
	hostProcesses []*process.Process
	ttys *[]dev.TTY
	opts *JoinNamespaceOpts
}

type processFunc func(*process.Process, *psContext) (string, error)

type aixFormatDescriptor struct {
	code string
	normal string
	header string
	onHost bool
	procFn processFunc
}

func findID(idStr string, mapping []IDMap, lookupFunc func(uid string) (string, error), overflowFile string) (string, error) {
	if len(mapping) == 0 {
		return idStr, nil
	}

	id, err := strconv.ParseInt(idStr, 10, 0)
	if err != nil {
		return "", errors.Wrapf(err, "cannot parse %s", idStr)
	}

	for _, m := range mapping {
		if int(id) >= m.ContainerID && int(id) < m.ContainerID+m.Size {
			user := fmt.Sprintf("%d", m.HostID+(int(id)-m.ContainerID))

			return lookupFunc(user)
		}
	}

	// User not found, read the overflow
	overflow, err := ioutil.ReadFile(overflowFile)
	if err != nil {
		return "", errors.Wrapf(err, "cannot read %s", overflowFile)
	}

	return string(overflow), nil
}
