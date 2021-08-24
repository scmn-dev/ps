// +build !cgo

package host

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"unsafe"
)

var (
	clockTicks *int64
	bootTime   *int64
)

func getNativeEndianness() binary.ByteOrder {
	var i int32 = 0x00000001
	u := unsafe.Pointer(&i)
	if *((*byte)(u)) == 0x01 {
		return binary.LittleEndian
	}

	return binary.BigEndian
}

const (
	atClktck = 17
)

func getFromAuxv(what uint, whatName string) (uint, error) {
	dataLen := int(unsafe.Sizeof(int(0)))
	p, err := ioutil.ReadFile("/proc/self/auxv")
	if err != nil {
		return 0, err
	}

	native := getNativeEndianness()
	for i := 0; i < len(p); {
		var k, v uint

		switch dataLen {
		case 4:
			k = uint(native.Uint32(p[i : i+dataLen]))
			v = uint(native.Uint32(p[i+dataLen : i+dataLen*2]))
		case 8:
			k = uint(native.Uint64(p[i : i+dataLen]))
			v = uint(native.Uint64(p[i+dataLen : i+dataLen*2]))
		}

		i += dataLen * 2
		if k == what {
			return v, nil
		}
	}

	return 0, fmt.Errorf("cannot find %s in auxv", whatName)
}

// ClockTicks returns sysconf(SC_CLK_TCK).
func ClockTicks() (int64, error) {
	if clockTicks == nil {
		ret, err := getFromAuxv(atClktck, "AT_CLKTCK")
		if err != nil {
			return -1, err
		}

		ticks := int64(ret)
		clockTicks = &ticks
	}

	return *clockTicks, nil
}
