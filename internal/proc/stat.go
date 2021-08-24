package proc

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
)

type Stat struct {
	Pid string
	Comm string
	State string
	Ppid string
	Pgrp string
	Session string
	TtyNr string
	Tpgid string
	Flags string
	Minflt string
	Cminflt string
	Majflt string
	Cmajflt string
	Utime string
	Stime string
	Cutime string
	Cstime string
	Priority string
	Nice string
	NumThreads string
	Itrealvalue string
	Starttime string
	Vsize string
}

var readStat = func(path string) (string, error) {
	rawData, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}

	return string(rawData), nil
}

// ParseStat parses the /proc/$pid/stat file and returns a Stat.
func ParseStat(pid string) (*Stat, error) {
	data, err := readStat(fmt.Sprintf("/proc/%s/stat", pid))
	if err != nil {
		return nil, err
	}

	firstParen := strings.IndexByte(data, '(')
	lastParen := strings.LastIndexByte(data, ')')
	if firstParen == -1 || lastParen == -1 {
		return nil, errors.New("invalid format in stat")
	}

	pidstr := data[0 : firstParen-1]
	comm := data[firstParen+1 : lastParen]
	rest := strings.Fields(data[lastParen+1:])
	fields := append([]string{pidstr, comm}, rest...)

	fieldAt := func(i int) string {
		return fields[i-1]
	}
}
