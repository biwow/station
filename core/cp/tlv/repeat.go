package tlv

import (
	"strings"
	"sync"
)

type QueueMap struct {
	lock  sync.Mutex
	rek   int
	queue map[int]string
}

var (
	qlen     int = 100
	qmOnce   sync.Once
	queueMap *QueueMap
)

// NewQM new
func NewQM() *QueueMap {
	qmOnce.Do(func() {
		queueMap = &QueueMap{
			lock:  sync.Mutex{},
			rek:   1,
			queue: make(map[int]string, qlen),
		}
	})
	return queueMap
}

// CheckIn 重复消息检测
func (qm *QueueMap) CheckIn(msgHash string) bool {
	qm.lock.Lock()
	defer qm.lock.Unlock()
	for _, v := range qm.queue {
		if strings.EqualFold(v, msgHash) {
			return true
		}
	}
	return false
}

// Push 消息暂存
func (qm *QueueMap) Push(msgHash string) {
	qm.lock.Lock()
	defer qm.lock.Unlock()
	qm.queue[qm.rek] = msgHash
	if qm.rek >= qlen {
		qm.rek = 1
	} else {
		qm.rek++
	}
}
