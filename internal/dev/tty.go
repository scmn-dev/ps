package dev

type TTY struct {
	Minor uint64
	Major uint64
	Path string
}

func majDevNum(rdev uint64) uint64 {
	return (rdev >> 8) & 0xfff
}

// minDevNum returns the minor device number of rdev (see stat_t.Rdev).
func minDevNum(rdev uint64) uint64 {
	return (rdev & 0xff) | ((rdev >> 12) & 0xfff00)
}
