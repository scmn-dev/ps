package dev

import (
	"os"
	"strings"
	"syscall"
)

type TTY struct {
	Minor uint64
	Major uint64
	Path string
}

func TTYs() (*[]TTY, error) {
	devDir, err := os.Open("/dev/")
	if err != nil {
		return nil, err
	}

	defer devDir.Close()

	devices := []string{}
	devTTYs, err := devDir.Readdirnames(0)
	if err != nil {
		return nil, err
	}

	for _, d := range devTTYs {
		if !strings.HasPrefix(d, "tty") {
			continue
		}
		devices = append(devices, "/dev/"+d)
	}

	devPTSDir, err := os.Open("/dev/pts/")
	if err != nil {
		return nil, err
	}

	defer devPTSDir.Close()

	devPTSs, err := devPTSDir.Readdirnames(0)
	if err != nil {
		return nil, err
	}

	for _, d := range devPTSs {
		devices = append(devices, "/dev/pts/"+d)
	}

	ttys := []TTY{}
	for _, dev := range devices {
		fi, err := os.Stat(dev)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}

			return nil, err
		}

		s := fi.Sys().(*syscall.Stat_t)
		t := TTY{
			// Rdev is type uint32 on mips arch so we have to cast to uint64
			Minor: minDevNum(uint64(s.Rdev)),
			Major: majDevNum(uint64(s.Rdev)),
			Path:  dev,
		}

		ttys = append(ttys, t)
	}

	return &ttys, nil
}

func majDevNum(rdev uint64) uint64 {
	return (rdev >> 8) & 0xfff
}

// minDevNum returns the minor device number of rdev (see stat_t.Rdev).
func minDevNum(rdev uint64) uint64 {
	return (rdev & 0xff) | ((rdev >> 12) & 0xfff00)
}
