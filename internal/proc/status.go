package proc

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/pkg/errors"
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

func readStatusDefault(pid string) ([]string, error) {
	path := fmt.Sprintf("/proc/%s/status", pid)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	lines := []string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	return lines, nil
}

func ParseStatus(pid string, joinUserNS bool) (*Status, error) {
	var lines []string
	var err error

	if joinUserNS {
		lines, err = readStatusUserNS(pid)
	} else {
		lines, err = readStatusDefault(pid)
	}

	if err != nil {
		return nil, err
	}

	return parseStatus(pid, lines)
}

func parseStatus(pid string, lines []string) (*Status, error) {
	s := Status{}
	errUnexpectedInput := fmt.Errorf("unexpected input from /proc/%s/status", pid)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
			case "Name:":
				s.Name = fields[1]
			case "Umask:":
				s.Umask = fields[1]
			case "State:":
				s.State = fields[1]
			case "Tgid:":
				s.Tgid = fields[1]
			case "Ngid:":
				s.Ngid = fields[1]
			case "Pid:":
				s.Pid = fields[1]
			case "PPid:":
				s.PPid = fields[1]
			case "TracerPid:":
				s.TracerPid = fields[1]
			case "Uid:":
				if len(fields) != 5 {
					return nil, errors.Wrap(errUnexpectedInput, line)
				}

				s.Uids = []string{fields[1], fields[2], fields[3], fields[4]}
			case "Gid:":
				if len(fields) != 5 {
					return nil, errors.Wrap(errUnexpectedInput, line)
				}

				s.Gids = []string{fields[1], fields[2], fields[3], fields[4]}
			case "FDSize:":
				s.FdSize = fields[1]
			case "Groups:":
				s.Groups = fields[1:]
			case "NStgid:":
				s.NStgid = fields[1]
			case "NSpid:":
				s.NSpid = fields[1:]
			case "NSpgid:":
				s.NSpgid = fields[1]
			case "NSsid:":
				s.NSsid = fields[1]
			case "VmPeak:":
				s.VMPeak = fields[1]
			case "VmSize:":
				s.VMSize = fields[1]
			case "VmLck:":
				s.VMLCK = fields[1]
			case "VmPin:":
				s.VMPin = fields[1]
			case "VmHWM:":
				s.VMHWM = fields[1]
			case "VmRSS:":
				s.VMRSS = fields[1]
			case "RssAnon:":
				s.RssAnon = fields[1]
			case "RssFile:":
				s.RssFile = fields[1]
			case "RssShmem:":
				s.RssShmem = fields[1]
			case "VmData:":
				s.VMData = fields[1]
			case "VmStk:":
				s.VMStk = fields[1]
			case "VmExe:":
				s.VMExe = fields[1]
			case "VmLib:":
				s.VMLib = fields[1]
			case "VmPTE:":
				s.VMPTE = fields[1]
			case "VmPMD:":
				s.VMPMD = fields[1]
			case "VmSwap:":
				s.VMSwap = fields[1]
			case "HugetlbPages:":
				s.HugetlbPages = fields[1]
			case "Threads:":
				s.Threads = fields[1]
			case "SigQ:":
				s.SigQ = fields[1]
			case "SigPnd:":
				s.SigPnd = fields[1]
			case "ShdPnd:":
				s.ShdPnd = fields[1]
			case "SigBlk:":
				s.SigBlk = fields[1]
			case "SigIgn:":
				s.SigIgn = fields[1]
			case "SigCgt:":
				s.SigCgt = fields[1]
			case "CapInh:":
				s.CapInh = fields[1]
			case "CapPrm:":
				s.CapPrm = fields[1]
			case "CapEff:":
				s.CapEff = fields[1]
			case "CapBnd:":
				s.CapBnd = fields[1]
			case "CapAmb:":
				s.CapAmb = fields[1]
			case "NoNewPrivs:":
				s.NoNewPrivs = fields[1]
			case "Seccomp:":
				s.Seccomp = fields[1]
			case "Cpus_allowed:":
				s.CpusAllowed = fields[1]
			case "Cpus_allowed_list:":
				s.CpusAllowedList = fields[1]
			case "Mems_allowed:":
				s.MemsAllowed = fields[1]
			case "Mems_allowed_list:":
				s.MemsAllowedList = fields[1]
			case "voluntary_ctxt_switches:":
				s.VoluntaryCtxtSwitches = fields[1]
			case "nonvoluntary_ctxt_switches:":
				s.NonvoluntaryCtxtSwitches = fields[1]
		}
	}

	return &s, nil
}
