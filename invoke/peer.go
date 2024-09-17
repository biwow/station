package invoke

import (
	"gitee.com/trustChain/pkg/cache"
	"gitee.com/trustChain/pkg/cache/typecache"
	"gitee.com/trustChain/pkg/logger"
	"github.com/biwow/station/global"
)

func Init() {
	global.Cache = LevelDBInstance()
}
func Show(name string) string {
	return name
}

func LevelDBInstance() cache.Cache {
	cfg := typecache.ConfigCache{
		DBPath: "./data",
	}
	cacheInstance, err := cache.NewCache("level", cfg)
	if err != nil {
		logger.Painc("LevelDBInstance:", "step", "NewCache", "err", err)
	}
	logger.Info("Instance", "Cache", "connection successful!")
	return cacheInstance
}
