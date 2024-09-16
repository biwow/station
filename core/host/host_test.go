package host

import (
	"testing"
)

func TestName(t *testing.T) {
	host, err := NewHost()
	if err != nil {
		t.Error(err)
	}
	t.Log(host)
	t.Log(host.ID())
	t.Log(host.MasterKey())
	t.Log(host.Peers())
}
