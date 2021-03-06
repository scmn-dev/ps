package cgroups

import (
	"sync"
	"syscall"
)

const (
	CgroupRoot        = "/sys/fs/cgroup"
	cgroup2SuperMagic = 0x63677270
)

var (
	isUnifiedOnce sync.Once
	isUnified     bool
	isUnifiedErr  error
)

// IsCgroup2UnifiedMode returns whether we are running in cgroup or cgroupv2 mode.
func IsCgroup2UnifiedMode() (bool, error) {
	isUnifiedOnce.Do(func() {
		var st syscall.Statfs_t
		if err := syscall.Statfs(CgroupRoot, &st); err != nil {
			isUnified, isUnifiedErr = false, err
		} else {
			isUnified, isUnifiedErr = st.Type == cgroup2SuperMagic, nil
		}
	})

	return isUnified, isUnifiedErr
}
