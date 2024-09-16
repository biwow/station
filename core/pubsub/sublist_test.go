package pubsub

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func TestName(t *testing.T) {
	sl := NewSubList()
	sl.Subscribe("A")
	sl.Subscribe("B")
	sl.Subscribe("C")

	go listen("A", sl.CH["A"])
	go listen("B", sl.CH["B"])
	go listen("C", sl.CH["C"])

	for {
		time.Sleep(time.Second * 1)
		rand.Seed(time.Now().UnixNano())
		strings := []string{"A", "B", "C"}
		randomIndex := rand.Intn(len(strings))
		randomString := strings[randomIndex]
		var arr []string
		arr = append(arr, randomString)
		sl.PublishMessage(arr, []byte("sss"))
	}

}

func listen(key string, bc Broadcast) {
	for {
		s := <-bc
		fmt.Println(key + ":" + string(s))
	}

}
