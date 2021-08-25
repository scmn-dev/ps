package main

import (
	"fmt"
	"os"
	"sort"
	"sync"
	"strings"
	"strconv"
	"runtime"
	"io/ioutil"

	capkg "github.com/gepis/ps/internal/cap"
	"github.com/gepis/ps/internal/dev"
	"github.com/gepis/ps/internal/process"
	"github.com/gepis/ps/internal/proc"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
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

func translateDescriptors(descriptors []string) ([]aixFormatDescriptor, error) {
	if len(descriptors) == 0 {
		descriptors = DefaultDescriptors
	}

	formatDescriptors := []aixFormatDescriptor{}
	for _, d := range descriptors {
		d = strings.TrimSpace(d)
		found := false
		for _, aix := range aixFormatDescriptors {
			if d == aix.code || d == aix.normal {
				formatDescriptors = append(formatDescriptors, aix)
				found = true
			}
		}

		if !found {
			return nil, errors.Wrapf(ErrUnknownDescriptor, "'%s'", d)
		}
	}

	return formatDescriptors, nil
}

var (
	// DefaultDescriptors is the `ps -ef` compatible default format.
	DefaultDescriptors = []string{"user", "pid", "ppid", "pcpu", "etime", "tty", "time", "args"}

	// ErrUnknownDescriptor is returned when an unknown descriptor is parsed.
	ErrUnknownDescriptor = errors.New("unknown descriptor")

	aixFormatDescriptors = []aixFormatDescriptor{
		{
			code:   "%C",
			normal: "pcpu",
			header: "%CPU",
			procFn: processPCPU,
		},
		{
			code:   "%G",
			normal: "group",
			header: "GROUP",
			procFn: processGROUP,
		},
		{
			code:   "%P",
			normal: "ppid",
			header: "PPID",
			procFn: processPPID,
		},
		{
			code:   "%U",
			normal: "user",
			header: "USER",
			procFn: processUSER,
		},
		{
			code:   "%a",
			normal: "args",
			header: "COMMAND",
			procFn: processARGS,
		},
		{
			code:   "%c",
			normal: "comm",
			header: "COMMAND",
			procFn: processCOMM,
		},
		{
			code:   "%g",
			normal: "rgroup",
			header: "RGROUP",
			procFn: processRGROUP,
		},
		{
			code:   "%n",
			normal: "nice",
			header: "NI",
			procFn: processNICE,
		},
		{
			code:   "%p",
			normal: "pid",
			header: "PID",
			procFn: processPID,
		},
		{
			code:   "%r",
			normal: "pgid",
			header: "PGID",
			procFn: processPGID,
		},
		{
			code:   "%t",
			normal: "etime",
			header: "ELAPSED",
			procFn: processETIME,
		},
		{
			code:   "%u",
			normal: "ruser",
			header: "RUSER",
			procFn: processRUSER,
		},
		{
			code:   "%x",
			normal: "time",
			header: "TIME",
			procFn: processTIME,
		},
		{
			code:   "%y",
			normal: "tty",
			header: "TTY",
			procFn: processTTY,
		},
		{
			code:   "%z",
			normal: "vsz",
			header: "VSZ",
			procFn: processVSZ,
		},
		{
			normal: "capamb",
			header: "AMBIENT CAPS",
			procFn: processCAPAMB,
		},
		{
			normal: "capinh",
			header: "INHERITED CAPS",
			procFn: processCAPINH,
		},
		{
			normal: "capprm",
			header: "PERMITTED CAPS",
			procFn: processCAPPRM,
		},
		{
			normal: "capeff",
			header: "EFFECTIVE CAPS",
			procFn: processCAPEFF,
		},
		{
			normal: "capbnd",
			header: "BOUNDING CAPS",
			procFn: processCAPBND,
		},
		{
			normal: "seccomp",
			header: "SECCOMP",
			procFn: processSECCOMP,
		},
		{
			normal: "label",
			header: "LABEL",
			procFn: processLABEL,
		},
		{
			normal: "hpid",
			header: "HPID",
			onHost: true,
			procFn: processHPID,
		},
		{
			normal: "huser",
			header: "HUSER",
			onHost: true,
			procFn: processHUSER,
		},
		{
			normal: "hgroup",
			header: "HGROUP",
			onHost: true,
			procFn: processHGROUP,
		},
		{
			normal: "rss",
			header: "RSS",
			procFn: processRSS,
		},
		{
			normal: "state",
			header: "STATE",
			procFn: processState,
		},
		{
			normal: "stime",
			header: "STIME",
			procFn: processStartTime,
		},
	}
)

func ListDescriptors() (list []string) {
	for _, d := range aixFormatDescriptors {
		list = append(list, d.normal)
	}

	sort.Strings(list)
	return
}

func readMappings(path string) ([]IDMap, error) {
	mappings, err := proc.ReadMappings(path)
	if err != nil {
		return nil, err
	}

	var res []IDMap
	for _, i := range mappings {
		m := IDMap{ContainerID: i.ContainerID, HostID: i.HostID, Size: i.Size}
		res = append(res, m)
	}

	return res, nil
}

func contextFromOptions(options *JoinNamespaceOpts) (*psContext, error) {
	ctx := new(psContext)
	ctx.opts = options
	if ctx.opts != nil && ctx.opts.FillMappings {
		uidMappings, err := readMappings("/proc/self/uid_map")
		if err != nil {
			return nil, err
		}

		gidMappings, err := readMappings("/proc/self/gid_map")
		if err != nil {
			return nil, err
		}

		ctx.opts.UIDMap = uidMappings
		ctx.opts.GIDMap = gidMappings

		ctx.opts.FillMappings = false
	}
	return ctx, nil
}

func JoinNamespaceAndProcessInfoWithOptions(pid string, descriptors []string, options *JoinNamespaceOpts) ([][]string, error) {
	var (
		data    [][]string
		dataErr error
		wg      sync.WaitGroup
	)

	aixDescriptors, err := translateDescriptors(descriptors)
	if err != nil {
		return nil, err
	}

	ctx, err := contextFromOptions(options)
	if err != nil {
		return nil, err
	}

	// extract data from host processes only on-demand / when at least one
	// of the specified descriptors requires host data
	for _, d := range aixDescriptors {
		if d.onHost {
			ctx.hostProcesses, err = hostProcesses(pid)
			if err != nil {
				return nil, err
			}
			break
		}
	}

	wg.Add(1)

	go func() {
		defer wg.Done()
		runtime.LockOSThread()

		// extract user namespaces prior to joining the mount namespace
		currentUserNs, err := proc.ParseUserNamespace("self")
		if err != nil {
			dataErr = errors.Wrapf(err, "error determining user namespace")
			return
		}

		pidUserNs, err := proc.ParseUserNamespace(pid)
		if err != nil {
			dataErr = errors.Wrapf(err, "error determining user namespace of PID %s", pid)
		}

		// join the mount namespace of pid
		fd, err := os.Open(fmt.Sprintf("/proc/%s/ns/mnt", pid))
		if err != nil {
			dataErr = err
			return
		}
	
		defer fd.Close()

		// create a new mountns on the current thread
		if err = unix.Unshare(unix.CLONE_NEWNS); err != nil {
			dataErr = err
			return
		}

		if err := unix.Setns(int(fd.Fd()), unix.CLONE_NEWNS); err != nil {
			dataErr = err
			return
		}

		// extract all pids mentioned in pid's mount namespace
		pids, err := proc.GetPIDs()
		if err != nil {
			dataErr = err
			return
		}

		// join the user NS if the pid's user NS is different
		// to the caller's user NS.
		joinUserNS := currentUserNs != pidUserNs

		ctx.containersProcesses, err = process.FromPIDs(pids, joinUserNS)
		if err != nil {
			dataErr = err
			return
		}

		data, dataErr = processDescriptors(aixDescriptors, ctx)
	}()

	wg.Wait()

	return data, dataErr
}

func JoinNamespaceAndProcessInfo(pid string, descriptors []string) ([][]string, error) {
	return JoinNamespaceAndProcessInfoWithOptions(pid, descriptors, &JoinNamespaceOpts{})
}

func JoinNamespaceAndProcessInfoByPidsWithOptions(pids []string, descriptors []string, options *JoinNamespaceOpts) ([][]string, error) {
	nsMap := make(map[string]bool)
	pidList := []string{}
	for _, pid := range pids {
		ns, err := proc.ParsePIDNamespace(pid)
		if err != nil {
			if os.IsNotExist(errors.Cause(err)) {
				continue
			}

			return nil, errors.Wrapf(err, "error extracting PID namespace")
		}

		if _, exists := nsMap[ns]; !exists {
			nsMap[ns] = true
			pidList = append(pidList, pid)
		}
	}

	data := [][]string{}
	for i, pid := range pidList {
		pidData, err := JoinNamespaceAndProcessInfoWithOptions(pid, descriptors, options)
		if os.IsNotExist(errors.Cause(err)) {
			continue
		}

		if err != nil {
			return nil, err
		}

		if i == 0 {
			data = append(data, pidData[0])
		}

		data = append(data, pidData[1:]...)
	}

	return data, nil
}

func JoinNamespaceAndProcessInfoByPids(pids []string, descriptors []string) ([][]string, error) {
	return JoinNamespaceAndProcessInfoByPidsWithOptions(pids, descriptors, &JoinNamespaceOpts{})
}

func ProcessInfo(descriptors []string) ([][]string, error) {
	pids, err := proc.GetPIDs()
	if err != nil {
		return nil, err
	}

	return ProcessInfoByPids(pids, descriptors)
}

func ProcessInfoByPids(pids []string, descriptors []string) ([][]string, error) {
	aixDescriptors, err := translateDescriptors(descriptors)
	if err != nil {
		return nil, err
	}

	ctx, err := contextFromOptions(nil)
	if err != nil {
		return nil, err
	}

	ctx.containersProcesses, err = process.FromPIDs(pids, false)
	if err != nil {
		return nil, err
	}

	return processDescriptors(aixDescriptors, ctx)
}

// hostProcesses returns all processes running in the current namespace.
func hostProcesses(pid string) ([]*process.Process, error) {
	// get processes
	pids, err := proc.GetPIDsFromCgroup(pid)
	if err != nil {
		return nil, err
	}

	processes, err := process.FromPIDs(pids, false)
	if err != nil {
		return nil, err
	}

	// set the additional host data
	for _, p := range processes {
		if err := p.SetHostData(); err != nil {
			return nil, err
		}
	}

	return processes, nil
}

func processDescriptors(formatDescriptors []aixFormatDescriptor, ctx *psContext) ([][]string, error) {
	data := [][]string{}
	// create header
	header := []string{}
	for _, desc := range formatDescriptors {
		header = append(header, desc.header)
	}
	data = append(data, header)

	// dispatch all descriptor functions on each process
	for _, proc := range ctx.containersProcesses {
		pData := []string{}
		for _, desc := range formatDescriptors {
			dataStr, err := desc.procFn(proc, ctx)
			if err != nil {
				return nil, err
			}
			pData = append(pData, dataStr)
		}
		data = append(data, pData)
	}

	return data, nil
}

func findHostProcess(p *process.Process, ctx *psContext) *process.Process {
	for _, hp := range ctx.hostProcesses {
		if len(hp.Status.NSpid) < 2 {
			continue
		}

		if p.Pid == hp.Status.NSpid[1] && p.PidNS == hp.PidNS {
			return hp
		}
	}

	return nil
}

func processGROUP(p *process.Process, ctx *psContext) (string, error) {
	return process.LookupGID(p.Status.Gids[1])
}

func processUSER(p *process.Process, ctx *psContext) (string, error) {
	return process.LookupUID(p.Status.Uids[1])
}

// processRUSER returns the effective user name of the process.  This will be
// the textual user ID, if it can be optained, or a decimal representation
// otherwise.
func processRUSER(p *process.Process, ctx *psContext) (string, error) {
	return process.LookupUID(p.Status.Uids[0])
}

// processName returns the name of process p in the format "[$name]".
func processName(p *process.Process, ctx *psContext) (string, error) {
	return fmt.Sprintf("[%s]", p.Status.Name), nil
}

// processARGS returns the command of p with all its arguments.
func processARGS(p *process.Process, ctx *psContext) (string, error) {
	if p.CmdLine[0] == "" {
		return processName(p, ctx)
	}

	return strings.Join(p.CmdLine, " "), nil
}

// processCOMM returns the command name (i.e., executable name) of process p.
func processCOMM(p *process.Process, ctx *psContext) (string, error) {
	return p.Stat.Comm, nil
}

// processNICE returns the nice value of process p.
func processNICE(p *process.Process, ctx *psContext) (string, error) {
	return p.Stat.Nice, nil
}

// processPID returns the process ID of process p.
func processPID(p *process.Process, ctx *psContext) (string, error) {
	return p.Pid, nil
}

// processPGID returns the process group ID of process p.
func processPGID(p *process.Process, ctx *psContext) (string, error) {
	return p.Stat.Pgrp, nil
}

// processPCPU returns how many percent of the CPU time process p uses as
func processPCPU(p *process.Process, ctx *psContext) (string, error) {
	elapsed, err := p.ElapsedTime()
	if err != nil {
		return "", err
	}

	cpu, err := p.CPUTime()
	if err != nil {
		return "", err
	}

	pcpu := 100 * cpu.Seconds() / elapsed.Seconds()

	return strconv.FormatFloat(pcpu, 'f', 3, 64), nil
}

// processETIME returns the elapsed time since the process was started.
func processETIME(p *process.Process, ctx *psContext) (string, error) {
	elapsed, err := p.ElapsedTime()
	if err != nil {
		return "", nil
	}

	return fmt.Sprintf("%v", elapsed), nil
}

// processTIME returns the cumulative CPU time of process p.
func processTIME(p *process.Process, ctx *psContext) (string, error) {
	cpu, err := p.CPUTime()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%v", cpu), nil
}

// processStartTime returns the start time of process p.
func processStartTime(p *process.Process, ctx *psContext) (string, error) {
	sTime, err := p.StartTime()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%v", sTime), nil
}

// processTTY returns the controlling tty (terminal) of process p.
func processTTY(p *process.Process, ctx *psContext) (string, error) {
	ttyNr, err := strconv.ParseUint(p.Stat.TtyNr, 10, 64)
	if err != nil {
		return "", nil
	}

	tty, err := dev.FindTTY(ttyNr, ctx.ttys)
	if err != nil {
		return "", nil
	}

	ttyS := "?"
	if tty != nil {
		ttyS = strings.TrimPrefix(tty.Path, "/dev/")
	}

	return ttyS, nil
}

func processVSZ(p *process.Process, ctx *psContext) (string, error) {
	vmsize, err := strconv.Atoi(p.Stat.Vsize)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d", vmsize/1024), nil
}

func parseCAP(cap string) (string, error) {
	mask, err := strconv.ParseUint(cap, 16, 64)
	if err != nil {
		return "", err
	}

	if mask == capkg.FullCAPs {
		return "full", nil
	}

	caps := capkg.TranslateMask(mask)
	if len(caps) == 0 {
		return "none", nil
	}

	sort.Strings(caps)
	return strings.Join(caps, ","), nil
}

func processCAPAMB(p *process.Process, ctx *psContext) (string, error) {
	return parseCAP(p.Status.CapAmb)
}

func processCAPINH(p *process.Process, ctx *psContext) (string, error) {
	return parseCAP(p.Status.CapInh)
}

func processCAPPRM(p *process.Process, ctx *psContext) (string, error) {
	return parseCAP(p.Status.CapPrm)
}

func processCAPEFF(p *process.Process, ctx *psContext) (string, error) {
	return parseCAP(p.Status.CapEff)
}

func processCAPBND(p *process.Process, ctx *psContext) (string, error) {
	return parseCAP(p.Status.CapBnd)
}

func processSECCOMP(p *process.Process, ctx *psContext) (string, error) {
	switch p.Status.Seccomp {
		case "0":
			return "disabled", nil
		case "1":
			return "strict", nil
		case "2":
			return "filter", nil
		default:
			return "?", nil
	}
}

func processLABEL(p *process.Process, ctx *psContext) (string, error) {
	return p.Label, nil
}

func processHPID(p *process.Process, ctx *psContext) (string, error) {
	if hp := findHostProcess(p, ctx); hp != nil {
		return hp.Pid, nil
	}

	return "?", nil
}

// processHUSER returns the effective user ID of the corresponding host process
// of the (container) or "?" if no corresponding process could be found.
func processHUSER(p *process.Process, ctx *psContext) (string, error) {
	if hp := findHostProcess(p, ctx); hp != nil {
		if ctx.opts != nil && len(ctx.opts.UIDMap) > 0 {
			return findID(hp.Status.Uids[1], ctx.opts.UIDMap, process.LookupUID, "/proc/sys/fs/overflowuid")
		}

		return hp.Huser, nil
	}

	return "?", nil
}

func processHGROUP(p *process.Process, ctx *psContext) (string, error) {
	if hp := findHostProcess(p, ctx); hp != nil {
		if ctx.opts != nil && len(ctx.opts.GIDMap) > 0 {
			return findID(hp.Status.Gids[1], ctx.opts.GIDMap, process.LookupGID, "/proc/sys/fs/overflowgid")
		}

		return hp.Hgroup, nil
	}

	return "?", nil
}

func processRSS(p *process.Process, ctx *psContext) (string, error) {
	if p.Status.VMRSS == "" {
		return "0", nil
	}

	return p.Status.VMRSS, nil
}

func processState(p *process.Process, ctx *psContext) (string, error) {
	return p.Status.State, nil
}

func processRGROUP(p *process.Process, ctx *psContext) (string, error) {
	return process.LookupGID(p.Status.Gids[0])
}

// processPPID returns the parent process ID of process p.
func processPPID(p *process.Process, ctx *psContext) (string, error) {
	return p.Status.PPid, nil
}
