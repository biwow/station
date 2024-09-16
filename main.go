package station

import (
	"gitee.com/trustChain/pkg/types"
	"github.com/biwow/station/global"
	"github.com/biwow/station/router"
	"github.com/gin-gonic/gin"
)

type Plugin struct{}

func (*Plugin) PluginName() string {
	return "station"
}

func (*Plugin) PluginVersion() string {
	return "v0.8.2"
}

func (*Plugin) Register(group *gin.RouterGroup) {
	router.GroupApp.InitRouter(group)
}

func (*Plugin) AutoMigrate() error {
	return nil
}

func CreatePluginAndDB(instance types.PluginNeedInstance) *Plugin {
	global.Cache = instance.Cache
	return &Plugin{}
}
