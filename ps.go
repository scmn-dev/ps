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

	"github.com/gepis/ps/internal/cap"
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
