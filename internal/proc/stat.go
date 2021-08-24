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

	return &Stat{
		Pid:         fieldAt(1),
		Comm:        fieldAt(2),
		State:       fieldAt(3),
		Ppid:        fieldAt(4),
		Pgrp:        fieldAt(5),
		Session:     fieldAt(6),
		TtyNr:       fieldAt(7),
		Tpgid:       fieldAt(8),
		Flags:       fieldAt(9),
		Minflt:      fieldAt(10),
		Cminflt:     fieldAt(11),
		Majflt:      fieldAt(12),
		Cmajflt:     fieldAt(13),
		Utime:       fieldAt(14),
		Stime:       fieldAt(15),
		Cutime:      fieldAt(16),
		Cstime:      fieldAt(17),
		Priority:    fieldAt(18),
		Nice:        fieldAt(19),
		NumThreads:  fieldAt(20),
		Itrealvalue: fieldAt(21),
		Starttime:   fieldAt(22),
		Vsize:       fieldAt(23),
	}, nil
}
