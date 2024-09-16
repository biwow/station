package router

import (
	"github.com/biwow/station/api"
	"github.com/gin-gonic/gin"
)

type Group struct {
	Router
}

var GroupApp = new(Group)

type Router struct{}

func (s *Router) InitRouter(Router *gin.RouterGroup) {
	{
		// 先做接口，在接入react页面
		HostRouter := Router.Group("")
		{
			HostRouter.POST("host", api.CreateHostHandler)
			HostRouter.PUT("host", api.UpdateHostHandler)
			HostRouter.GET("host", api.ViewHostHandler)
		}
		PeerRouter := Router.Group("")
		{
			PeerRouter.POST("peer", api.CreatePeerHandler)
			PeerRouter.PUT("peer", api.UpdatePeerHandler)
			PeerRouter.DELETE("peer", api.DeletePeerHandler)
			PeerRouter.GET("peers", api.ListPeerHandler)
			PeerRouter.GET("peer", api.ViewPeerHandler)
			// 启动监听
			PeerRouter.POST("peer/listen", api.PeerListenStartHandler)
			// 关闭监听
			PeerRouter.PUT("peer/listen", api.PeerListenStopHandler)
			// 启动拨号
			PeerRouter.POST("peer/dial", api.PeerDialStartHandler)
			// 关闭拨号
			PeerRouter.PUT("peer/dial", api.PeerDialStopHandler)
			// 发布信息
			PeerRouter.POST("peer/message", api.SendPeerMessageHandler)
			PeerRouter.GET("peer/messages", api.ListPeerMessageHandler)
		}
		RemotePeerRouter := Router.Group("")
		{
			RemotePeerRouter.POST("remotePeer", api.CreateRemotePeerHandler)
			RemotePeerRouter.PUT("remotePeer", api.UpdateRemotePeerHandler)
			RemotePeerRouter.DELETE("remotePeer", api.DeleteRemotePeerHandler)
			RemotePeerRouter.GET("remotePeers", api.ListRemotePeerHandler)
			RemotePeerRouter.GET("remotePeer", api.ViewRemotePeerHandler)
		}
	}
}
