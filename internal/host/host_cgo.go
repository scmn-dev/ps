package host

/*
#include <unistd.h>
*/
import "C"

var (
	clockTicks *int64
	bootTime   *int64
)

func ClockTicks() (int64, error) {
	if clockTicks == nil {
		ticks := int64(C.sysconf(C._SC_CLK_TCK))
		clockTicks = &ticks
	}

	return *clockTicks, nil
}
