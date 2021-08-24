package proc

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Status struct {
	Name string
	Umask string
	State string
	Tgid string
	Ngid string
	Pid string
	PPid string
	TracerPid string
	Uids []string
	Gids []string
	FdSize string
	Groups []string
	NStgid string
	NSpid []string
	NSpgid string
	NSsid string
	VMPeak string
	VMSize string
	VMLCK string
	VMPin string
	VMHWM string
	VMRSS string
	RssAnon string
	RssFile string
	RssShmem string
	VMData string
	VMStk string
	VMExe string
	VMLib string
	VMPTE string
	VMPMD string
	VMSwap string
	HugetlbPages string
	Threads string
	SigQ string
	SigPnd string
	ShdPnd string
	SigBlk string
	SigIgn string
	SigCgt string
	CapInh string
	CapPrm string
	CapEff string
	CapBnd string
	CapAmb string
	NoNewPrivs string
	Seccomp string
	CpusAllowed string
	CpusAllowedList string
	MemsAllowed string
	MemsAllowedList string
	VoluntaryCtxtSwitches string
	NonvoluntaryCtxtSwitches string
}

func readStatusUserNS(pid string) ([]string, error) {
	path := fmt.Sprintf("/proc/%s/status", pid)
	args := []string{"nsenter", "-U", "-t", pid, "cat", path}

	c := exec.Command(args[0], args[1:]...)
	output, err := c.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("error executing %q: %v", strings.Join(args, " "), err)
	}

	return strings.Split(string(output), "\n"), nil
}
