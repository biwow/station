package smcc

import (
	"gitee.com/trustChain/pkg/smcc/etcd"
	"gitee.com/trustChain/pkg/smcc/typesmcc"
)

type SMCC interface {
	RegisterService(serviceName, serviceAddr string) error
	GetService(key string) ([]string, error)
	SetConfig(key, value string) error
	GetConfig(key string) (string, error)
}

func NewSMCC(provider string, cfg typesmcc.ConfigSMCC) (SMCC, error) {
	switch provider {
	case "etcd":
		return etcd.NewSMCCEtcd(cfg)
	default:

		return etcd.NewSMCCEtcd(cfg)
	}
}
