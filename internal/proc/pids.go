package proc

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/scmn-dev/ps/internal/cgroups"
)

// GetPIDs extracts and returns all PIDs from /proc.
func GetPIDs() ([]string, error) {
	procDir, err := os.Open("/proc/")
	if err != nil {
		return nil, err
	}

	defer procDir.Close()

	// extract string slice of all directories in procDir
	pidDirs, err := procDir.Readdirnames(0)
	if err != nil {
		return nil, err
	}

	pids := []string{}
	for _, pidDir := range pidDirs {
		_, err := strconv.Atoi(pidDir)
		if err != nil {
			// skip non-numerical entries (e.g., `/proc/softirqs`)
			continue
		}

		pids = append(pids, pidDir)
	}

	return pids, nil
}

// GetPIDsFromCgroup returns a strings slice of all pids listesd in pid's pids
// cgroup.  It automatically detects if we're running in unified mode or not.
func GetPIDsFromCgroup(pid string) ([]string, error) {
	unified, err := cgroups.IsCgroup2UnifiedMode()
	if err != nil {
		return nil, err
	}

	if unified {
		return getPIDsFromCgroupV2(pid)
	}

	return getPIDsFromCgroupV1(pid)
}

// getPIDsFromCgroupV1 returns a strings slice of all pids listesd in pid's pids
// cgroup.
func getPIDsFromCgroupV1(pid string) ([]string, error) {
	// First, find the corresponding path to the PID cgroup.
	f, err := os.Open(fmt.Sprintf("/proc/%s/cgroup", pid))
	if err != nil {
		return nil, err
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)
	cgroupPath := ""
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) != 3 {
			continue
		}

		if fields[1] == "pids" {
			cgroupPath = fmt.Sprintf("/sys/fs/cgroup/pids/%s/cgroup.procs", fields[2])
		}
	}

	if cgroupPath == "" {
		return nil, fmt.Errorf("couldn't find v1 pids group for PID %s", pid)
	}

	// Second, extract the PIDs inside the cgroup.
	f, err = os.Open(cgroupPath)
	if err != nil {
		return nil, err
	}

	defer f.Close()

	pids := []string{}
	scanner = bufio.NewScanner(f)
	for scanner.Scan() {
		pids = append(pids, scanner.Text())
	}

	return pids, nil
}

// getPIDsFromCgroupV2 returns a strings slice of all pids listesd in pid's pids
// cgroup.
func getPIDsFromCgroupV2(pid string) ([]string, error) {
	// First, find the corresponding path to the PID cgroup.
	f, err := os.Open(fmt.Sprintf("/proc/%s/cgroup", pid))
	if err != nil {
		return nil, err
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)
	cgroupSlice := ""
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) != 3 {
			continue
		}

		cgroupSlice = fields[2]
		break
	}

	if cgroupSlice == "" {
		return nil, fmt.Errorf("couldn't find v2 pids group for PID %s", pid)
	}

	// Second, extract the PIDs inside the cgroup.
	f, err = os.Open(filepath.Join(cgroups.CgroupRoot, cgroupSlice, "cgroup.procs"))
	if err != nil {
		return nil, err
	}

	defer f.Close()

	pids := []string{}
	scanner = bufio.NewScanner(f)
	for scanner.Scan() {
		pids = append(pids, scanner.Text())
	}

	return pids, nil
}
