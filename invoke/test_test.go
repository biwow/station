package invoke

import (
	"testing"
)

func TestListPeer(t *testing.T) {
	res := ListPeer()
	t.Log(res)
}
func TestCreateRemotePeer(t *testing.T) {
	res := CreatePeer("qiqi", "192.168.1.33", "11111", "tcp", "tlv")
	t.Log(res)
}

func TestPeerDialStart(t *testing.T) {
	res := PeerDialStart("0x5dbc378c5406ee224b44aa5f22d3e67b545e4184", "0x465bc9bf50957bc6e7de8347d902cfeb99c00629")
	t.Log(res)
}
