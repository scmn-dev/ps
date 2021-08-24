package capabilities

var (
	capabilities = map[uint]string{
		0:  "CHOWN",
		1:  "DAC_OVERRIDE",
		2:  "DAC_READ_SEARCH",
		3:  "FOWNER",
		4:  "FSETID",
		5:  "KILL",
		6:  "SETGID",
		7:  "SETUID",
		8:  "SETPCAP",
		9:  "LINUX_IMMUTABLE",
		10: "NET_BIND_SERVICE",
		11: "NET_BROADCAST",
		12: "NET_ADMIN",
		13: "NET_RAW",
		14: "IPC_LOCK",
		15: "IPC_OWNER",
		16: "SYS_MODULE",
		17: "SYS_RAWIO",
		18: "SYS_CHROOT",
		19: "SYS_PTRACE",
		20: "SYS_PACCT",
		21: "SYS_ADMIN",
		22: "SYS_BOOT",
		23: "SYS_NICE",
		24: "SYS_RESOURCE",
		25: "SYS_TIME",
		26: "SYS_TTY_CONFIG",
		27: "MKNOD",
		28: "LEASE",
		29: "AUDIT_WRITE",
		30: "AUDIT_CONTROL",
		31: "SETFCAP",
		32: "MAC_OVERRIDE",
		33: "MAC_ADMIN",
		34: "SYSLOG",
		35: "WAKE_ALARM",
		36: "BLOCK_SUSPEND",
		37: "AUDIT_READ",
	}

	FullCAPs = uint64(0x3FFFFFFFFF)
)

func TranslateMask(mask uint64) []string {
	caps := []string{}
	for i := uint(0); i < 64; i++ {
		if (mask>>i)&0x1 == 1 {
			c, known := capabilities[i]
			if !known {
				c = "unknown"
			}

			caps = append(caps, c)
		}
	}

	return caps
}
