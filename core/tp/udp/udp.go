package udp

import (
	"fmt"
	"gitee.com/trustChain/pkg/logger"
	"github.com/biwow/station/core/peer"
	"github.com/biwow/station/models"
	"log"
	"net"
)

type TPUdp struct {
}

func (t *TPUdp) ListenPeer(peer peer.Peer) {
	udpAddr, err := net.ResolveUDPAddr("udp", peer.PeerAddr)
	if err != nil {
		logger.Error("UDP ListenPeer", "step", "ResolveUDPAddr", "err", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		logger.Error("UDP ListenPeer", "step", "ListenUDP", "err", err)
		return
	}
	go handleConnection(conn)
}

func (t *TPUdp) DialPeer(remotePeer models.RemotePeer) {
	//TODO implement me
	panic("implement me")
}

func (t *TPUdp) Stop() error {
	//TODO implement me
	panic("implement me")
}

func handleConnection(conn *net.UDPConn) {
	// defer语句会在函数执行完毕（包括函数正常返回、发生错误或执行到函数末尾）时执行
	defer conn.Close()

	// 启动读协程
	go readFromConnection(conn)

	// 启动写协程
	go writeToConnection(conn)
}

func readFromConnection(conn *net.UDPConn) {
	buffer := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Println("Error reading from UDP connection:", err)
			return
		}
		receivedMessage := string(buffer[:n])
		fmt.Println("Received from", addr, ":", receivedMessage)
	}
}

func writeToConnection(conn *net.UDPConn) {
	for {
		_, err := conn.WriteToUDP([]byte("Hello from UDP server!"), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8888})
		if err != nil {
			log.Println("Error writing to UDP connection:", err)
			return
		}
	}
}
