package memorycache

import (
	"errors"
	"gitee.com/trustChain/pkg/cache/typecache"
	"sync"
	"time"
)

// 结构体
type CacheMemoryDB struct {
	lock sync.Mutex
	db   map[string]string
}

// NewCacheMemory 初始化数据库
func NewCacheMemory(cfg typecache.ConfigCache) (*CacheMemoryDB, error) {
	return &CacheMemoryDB{
		db: make(map[string]string),
	}, nil
}

// Set 写方法
func (db *CacheMemoryDB) Set(key, value string, expiration time.Duration) error {
	db.lock.Lock()
	db.db[key] = value
	db.lock.Unlock()

	return nil
}

// Get 读方法
func (db *CacheMemoryDB) Get(key string) (string, error) {
	db.lock.Lock()
	defer db.lock.Unlock()

	if value, ok := db.db[key]; ok {
		return value, nil
	}
	return "", errors.New("key non existent")
}

// Del 删除制定键值
func (db *CacheMemoryDB) Del(key string) error {
	db.lock.Lock()
	delete(db.db, key)
	db.lock.Unlock()

	return nil
}

func (db *CacheMemoryDB) List(prefix string, pageNum, pageSize int) (int, []string, error) {
	//TODO implement me
	panic("implement me")
}
