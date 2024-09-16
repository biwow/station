package rediscache

import (
	"gitee.com/trustChain/pkg/cache/typecache"
	"gitee.com/trustChain/pkg/logger"
	"github.com/go-redis/redis"
	"time"
)

type CacheRedis struct {
	db *redis.Client // 数据库句柄
}

func NewCacheRedis(cfg typecache.ConfigCache) (*CacheRedis, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	_, err := client.Ping().Result()
	if err != nil {
		return nil, err
	}
	return &CacheRedis{db: client}, nil
}

// Set 写入数据
func (r *CacheRedis) Set(key, value string, expiration time.Duration) error {
	r.db.Set(key, value, time.Second*expiration)
	return nil
}

// Get 读数据
func (r *CacheRedis) Get(key string) (string, error) {
	defer func() {
		if err := recover(); err != nil {
			logger.Error("Redis Get", "step", "defer", "err", err)
		}
	}()
	value, err := r.db.Get(key).Result()
	if err != nil || value == "" {
		return "", err
	}
	return value, nil
}

// Del 删除数据
func (r *CacheRedis) Del(key string) error {
	r.db.Del(key)
	return nil
}

func (r *CacheRedis) List(prefix string, pageNum, pageSize int) (int, []string, error) {
	var cursor uint64
	var keys []string
	var res []string
	start := (pageNum - 1) * pageSize

	for {
		var batchKeys []string
		var err error
		batchKeys, cursor, err = r.db.Scan(cursor, prefix+"*", int64(pageSize)).Result()
		if err != nil {
			return 0, nil, err
		}
		keys = append(keys, batchKeys...)
		if cursor == 0 || len(keys) >= start+pageSize {
			break
		}
	}

	for _, key := range keys[start : start+pageSize] {
		value, err := r.Get(key)
		if err != nil {
			return 0, nil, err
		}
		res = append(res, value)
	}

	return len(keys), res, nil
}
