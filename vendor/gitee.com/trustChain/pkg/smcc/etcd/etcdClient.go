package etcd

import (
	"context"
	"errors"
	"gitee.com/trustChain/pkg/logger"
	"gitee.com/trustChain/pkg/smcc/typesmcc"
	clientv3 "go.etcd.io/etcd/client/v3"
)

type SMCCEtcd struct {
	client *clientv3.Client
}

// NewSMCCEtcd 创建etcd链接
func NewSMCCEtcd(cfg typesmcc.ConfigSMCC) (*SMCCEtcd, error) {
	conf := clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: cfg.DialTimeout,
	}
	if client, err := clientv3.New(conf); err == nil {
		return &SMCCEtcd{
			client: client,
		}, nil
	} else {
		logger.Error("SMCCEtcd", "step", "NewSMCCEtcd", "err", err)
		return nil, err
	}
}

// RegisterService 服务注册
func (c *SMCCEtcd) RegisterService(serviceName, serviceAddr string) error {
	// 创建一个新的lease
	resp, err := c.client.Grant(context.TODO(), 5) // 5秒后过期
	if err != nil {
		return err
	}
	leaseID := resp.ID
	// 写入服务注册信息
	_, err = c.client.Put(context.Background(), serviceName, serviceAddr, clientv3.WithLease(leaseID))
	if err != nil {
		return err
	}
	// 续租
	ch, err := c.client.KeepAlive(context.TODO(), leaseID)
	if err != nil {
		return err
	}
	// 及时从KeepAlive返回的通道中取走值,防止队列充满
	go func() {
		for {
			_ = <-ch
		}
	}()

	return nil
}

// GetService 服务发现
func (c *SMCCEtcd) GetService(key string) ([]string, error) {
	resp, err := c.client.Get(context.Background(), key)
	if err != nil {
		return nil, err
	}
	addrs := extractAddrs(resp)
	return addrs, nil
}

func (c *SMCCEtcd) SetConfig(key, value string) error {
	_, err := c.client.Put(context.Background(), key, value)
	return err
}

func (c *SMCCEtcd) GetConfig(key string) (string, error) {
	resp, err := c.client.Get(context.Background(), key)
	if err != nil {
		return "", err
	}
	if resp.Kvs == nil {
		return "", errors.New("key is null")
	}
	return string(resp.Kvs[0].Value), nil
}

// extractAddrs 提取地址
func extractAddrs(resp *clientv3.GetResponse) []string {
	addrs := make([]string, 0)
	if resp == nil || resp.Kvs == nil {
		return addrs
	}
	for i := range resp.Kvs {
		if v := resp.Kvs[i].Value; v != nil {
			addrs = append(addrs, string(v))
		}
	}
	return addrs
}
