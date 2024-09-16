package tool

import (
	"strconv"
	"time"
)

func GetCurrentMillisecondsAsString() string {
	now := time.Now()
	milliseconds := now.UnixNano() / 1e6
	return strconv.FormatInt(milliseconds, 10)
}
