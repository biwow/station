package main

import (
	"fmt"
	"net"
)

func main() {
	// 监听本地的 UDP 端口 8080
	addr, err := net.ResolveUDPAddr("udp", ":33333")
	if err != nil {
		fmt.Println("Error resolving address:", err)
		return
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		fmt.Println("Error listening:", err)
		return
	}
	fmt.Println("Success listening:", addr.Port)
	defer conn.Close()

	buf := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Error reading:", err)
			continue
		}
		message := string(buf[:n])
		fmt.Printf("Received from %v: %s\n", addr, message)

		// 回复消息
		_, err = conn.WriteToUDP([]byte("Message received!"), addr)
		if err != nil {
			fmt.Println("Error writing:", err)
			continue
		}
	}
}
