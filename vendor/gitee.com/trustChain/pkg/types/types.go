package types

import (
	"gitee.com/trustChain/pkg/cache"
	"gitee.com/trustChain/pkg/smcc"
	"gorm.io/gorm"
)

type PluginNeedInstance struct {
	Mysql       *gorm.DB
	Cache       cache.Cache
	SMCC        smcc.SMCC
	SecretKey   string // jwt签名验签使用
	AccessToken string // 在插件市场申请的AT，用于插件申请
}
