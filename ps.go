package main

import (
	"github.com/gepis/ps/internal/dev"
	"github.com/gepis/ps/internal/process"
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
