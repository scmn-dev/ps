package process

import (
	"os"
	"strconv"
	"time"

	"github.com/gepis/ps/internal/host"
	"github.com/gepis/ps/internal/proc"

	"github.com/opencontainers/runc/libcontainer/user"
	"github.com/pkg/errors"
)

type Process struct {
	Pid string
	Stat proc.Stat
	Status proc.Status
	CmdLine []string
	Label string
	PidNS string
	Huser string
	Hgroup string
}

func LookupGID(gid string) (string, error) {
	gidNum, err := strconv.Atoi(gid)
	if err != nil {
		return "", errors.Wrap(err, "error parsing group ID")
	}

	g, err := user.LookupGid(gidNum)
	if err != nil {
		return gid, nil
	}

	return g.Name, nil
}

func LookupUID(uid string) (string, error) {
	uidNum, err := strconv.Atoi(uid)
	if err != nil {
		return "", errors.Wrap(err, "error parsing user ID")
	}

	u, err := user.LookupUid(uidNum)
	if err != nil {
		return uid, nil
	}

	return u.Name, nil
}

// New returns a new Process with the specified pid and parses the relevant
// data from /proc and /dev.
func New(pid string, joinUserNS bool) (*Process, error) {
	p := Process{Pid: pid}

	if err := p.parseStat(); err != nil {
		return nil, err
	}

	if err := p.parseStatus(joinUserNS); err != nil {
		return nil, err
	}

	if err := p.parseCmdLine(); err != nil {
		return nil, err
	}

	if err := p.parsePIDNamespace(); err != nil {
		// Ignore permission errors as those occur for some pids when
		// the caller has limited permissions.
		if !os.IsPermission(err) {
			return nil, err
		}
	}

	if err := p.parseLabel(); err != nil {
		return nil, err
	}

	return &p, nil
}

// FromPIDs creates a new Process for each pid.
func FromPIDs(pids []string, joinUserNS bool) ([]*Process, error) {
	processes := []*Process{}
	for _, pid := range pids {
		p, err := New(pid, joinUserNS)
		if err != nil {
			if os.IsNotExist(errors.Cause(err)) {
				// proc parsing is racy
				// Let's ignore "does not exist" errors
				continue
			}

			return nil, err
		}

		processes = append(processes, p)
	}

	return processes, nil
}

// parseStat parses /proc/$pid/stat.
func (p *Process) parseStat() error {
	s, err := proc.ParseStat(p.Pid)
	if err != nil {
		return err
	}

	p.Stat = *s
	return nil
}

// parseStatus parses /proc/$pid/status.
func (p *Process) parseStatus(joinUserNS bool) error {
	s, err := proc.ParseStatus(p.Pid, joinUserNS)
	if err != nil {
		return err
	}

	p.Status = *s
	return nil
}

// parseCmdLine parses /proc/$pid/cmdline.
func (p *Process) parseCmdLine() error {
	s, err := proc.ParseCmdLine(p.Pid)
	if err != nil {
		return err
	}

	p.CmdLine = s
	return nil
}

// parsePIDNamespace sets the PID namespace.
func (p *Process) parsePIDNamespace() error {
	pidNS, err := proc.ParsePIDNamespace(p.Pid)
	if err != nil {
		return err
	}

	p.PidNS = pidNS
	return nil
}

// parseLabel parses the security label.
func (p *Process) parseLabel() error {
	label, err := proc.ParseAttrCurrent(p.Pid)
	if err != nil {
		return err
	}

	p.Label = label
	return nil
}

// SetHostData sets all host-related data fields.
func (p *Process) SetHostData() error {
	var err error

	p.Huser, err = LookupUID(p.Status.Uids[1])
	if err != nil {
		return err
	}

	p.Hgroup, err = LookupGID(p.Status.Gids[1])
	if err != nil {
		return err
	}

	return nil
}

// ElapsedTime returns the time.Duration since process p was created.
func (p *Process) ElapsedTime() (time.Duration, error) {
	startTime, err := p.StartTime()
	if err != nil {
		return 0, err
	}

	return time.Since(startTime), nil
}

// StarTime returns the time.Time when process p was started.
func (p *Process) StartTime() (time.Time, error) {
	sinceBoot, err := strconv.ParseInt(p.Stat.Starttime, 10, 64)
	if err != nil {
		return time.Time{}, err
	}

	clockTicks, err := host.ClockTicks()
	if err != nil {
		return time.Time{}, err
	}

	bootTime, err := host.BootTime()
	if err != nil {
		return time.Time{}, err
	}

	sinceBoot = sinceBoot / clockTicks
	return time.Unix(sinceBoot+bootTime, 0), nil
}

// CPUTime returns the cumlative CPU time of process p as a time.Duration.
func (p *Process) CPUTime() (time.Duration, error) {
	user, err := strconv.ParseInt(p.Stat.Utime, 10, 64)
	if err != nil {
		return 0, err
	}

	system, err := strconv.ParseInt(p.Stat.Stime, 10, 64)
	if err != nil {
		return 0, err
	}

	clockTicks, err := host.ClockTicks()
	if err != nil {
		return 0, err
	}

	secs := (user + system) / clockTicks
	cpu := time.Unix(secs, 0)
	return cpu.Sub(time.Unix(0, 0)), nil
}
