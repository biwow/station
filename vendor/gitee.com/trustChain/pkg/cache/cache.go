package cache

import (
	leveldbcache "gitee.com/trustChain/pkg/cache/leveldb"
	memorycache "gitee.com/trustChain/pkg/cache/memory"
	rediscache "gitee.com/trustChain/pkg/cache/redis"
	"gitee.com/trustChain/pkg/cache/typecache"
	"time"
)

type Cache interface {
	Set(key, value string, expiration time.Duration) error
	Get(key string) (string, error)
	Del(key string) error
	List(prefix string, pageNum, pageSize int) (int, []string, error)
}

func NewCache(provider string, cfg typecache.ConfigCache) (Cache, error) {
	switch provider {
	case "redis":
		return rediscache.NewCacheRedis(cfg)
	case "level":
		return leveldbcache.NewCacheLevelDB(cfg)
	case "memory":
		return memorycache.NewCacheMemory(cfg)
	default:

		return rediscache.NewCacheRedis(cfg)
	}
}
