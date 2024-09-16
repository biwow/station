package peer

import (
	"gitee.com/trustChain/blockchain/tools/key/ethkey"
	"github.com/biwow/station/core/pubsub"
)

type Peer interface {
	Start()
	Stop() error
	GetAddr() string
	GetPublicKey() string
	GetCP() string
	GetPeerId() string
	GetPeerPriKey() *ethkey.PrivateKey
	GetEventBus() *pubsub.SubList
}
