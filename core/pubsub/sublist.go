package pubsub

import (
	"fmt"
	"sync"
)

// 需求整理
// 1、发送和接收的消息都要持久化
// 2、使用goroutine实现发布订阅
// 3、每个节点有都需要一个pub和trustconns个数个sub
// 4、trustconn关闭后对应chain也要关闭
// 5、pub可以指定某一个或多个remote peer id

type SubList struct {
	CH map[string]Broadcast
	sync.RWMutex
}
type Broadcast chan []byte

func NewSubList() *SubList {
	s := &SubList{}
	s.CH = make(map[string]Broadcast) //所有channel
	return s
}

// Subscribe 订阅
func (s *SubList) Subscribe(remotePeerId string) {
	s.Lock()
	s.CH[remotePeerId] = make(Broadcast)
	s.Unlock()
	//go s.ListeningBroadcast(remotePeerId)
}

// Unsubscribe 取消订阅
func (s *SubList) Unsubscribe(remotePeerId string) {
	s.Lock()
	close(s.CH[remotePeerId])
	delete(s.CH, remotePeerId)
	s.Unlock()
}

// PublishMessage 发布消息
func (s *SubList) PublishMessage(remotePeerIds []string, message []byte) {
	s.RLock()
	for _, v := range remotePeerIds {
		s.CH[v] <- message
	}
	s.RUnlock()
}

// ListeningBroadcast 监听信息
func (s *SubList) ListeningBroadcast(remotePeerId string) {
	for {
		message := <-s.CH[remotePeerId]
		fmt.Println(remotePeerId, " 收到 ", string(message))
	}
}
