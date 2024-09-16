package main

import (
	"fmt"
	"net"
)

func main() {
	// 连接到本地的 UDP 服务端，端口 8080
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:33333")
	if err != nil {
		fmt.Println("Error resolving address:", err)
		return
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		fmt.Println("Error dialing:", err)
		return
	}
	defer conn.Close()

	message := "Hello, Server!"
	_, err = conn.Write([]byte(message))
	if err != nil {
		fmt.Println("Error writing:", err)
		return
	}

	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		fmt.Println("Error reading:", err)
		return
	}

	receivedMessage := string(buf[:n])
	fmt.Println("Received from server:", receivedMessage)
}
