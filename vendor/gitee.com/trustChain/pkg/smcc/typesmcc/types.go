package typesmcc

import "time"

type ConfigSMCC struct {
	Endpoints   []string
	DialTimeout time.Duration
}
