package leveldbcache

import (
	"gitee.com/trustChain/pkg/cache/typecache"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/syndtr/goleveldb/leveldb/filter"
	"github.com/syndtr/goleveldb/leveldb/iterator"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
	"time"
)

type CacheLevelDB struct {
	db *leveldb.DB
}

func NewCacheLevelDB(cfg typecache.ConfigCache) (*CacheLevelDB, error) {
	// 打开数据库并定义相关参数
	db, err := leveldb.OpenFile(cfg.DBPath, &opt.Options{
		Compression:         opt.SnappyCompression,
		WriteBuffer:         32 * opt.MiB,
		CompactionTableSize: 2 * opt.MiB,               // 定义数据文件最大存储
		Filter:              filter.NewBloomFilter(10), // bloom过滤器
	})
	if _, corrupted := err.(*errors.ErrCorrupted); corrupted {
		db, err = leveldb.RecoverFile(cfg.DBPath, nil)
	}
	if err != nil {
		return nil, err
	}

	// 结构体赋值并返回
	return &CacheLevelDB{db: db}, nil
}

// Set 数据库写操作
func (db *CacheLevelDB) Set(key, value string, expiration time.Duration) error {
	err := db.db.Put([]byte(key), []byte(value), nil)
	return err
}

// Get 数据库读操作
func (db *CacheLevelDB) Get(key string) (string, error) {
	data, err := db.db.Get([]byte(key), nil)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// Del 数据库删除操作
func (db *CacheLevelDB) Del(key string) error {
	err := db.db.Delete([]byte(key), nil)
	return err
}

func (db *CacheLevelDB) List(prefix string, pageNum, pageSize int) (int, []string, error) {
	r := util.BytesPrefix([]byte(prefix))
	iter := db.NewIterator(r, nil)

	var keys []string
	var res []string
	count := 0
	start := (pageNum - 1) * pageSize
	for iter.Next() {
		if count >= start && count < start+pageSize {
			keys = append(keys, string(iter.Key()))
		}
		count++
	}

	iter.Release()
	if err := iter.Error(); err != nil {
		return 0, nil, err
	}
	for _, key := range keys {
		value, err := db.Get(key)
		if err != nil {
			return 0, nil, err
		}
		res = append(res, value)
	}

	return count, res, nil
}

// NewIterator 数据库迭代器
func (db *CacheLevelDB) NewIterator(slice *util.Range, ro *opt.ReadOptions) iterator.Iterator {
	return db.db.NewIterator(slice, ro)
}

// Close 关闭数据库
func (db *CacheLevelDB) Close() error {
	if err := db.db.Close(); err != nil {
		return err
	}
	return nil
}
