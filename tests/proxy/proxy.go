package main

import (
	"io"
	"log"
	"net"
	"sync"
)

func tcpProxy(localAddr string, remoteAddr string) {
	listener, err := net.Listen("tcp", localAddr)
	if err != nil {
		log.Fatalf("Error listening on TCP: %v", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Error accepting TCP connection:", err)
			continue
		}
		go handleTCPConn(conn, remoteAddr)
	}
}

func handleTCPConn(conn net.Conn, remoteAddr string) {
	defer conn.Close()

	remoteConn, err := net.Dial("tcp", remoteAddr)
	if err != nil {
		log.Println("Error dialing remote TCP address:", err)
		return
	}
	defer remoteConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := io.Copy(remoteConn, conn)
		if err != nil {
			log.Println("Error copying data from local to remote in TCP:", err)
		}
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(conn, remoteConn)
		if err != nil {
			log.Println("Error copying data from remote to local in TCP:", err)
		}
	}()

	wg.Wait()
}

func udpProxy(localAddr string, remoteAddr string) {
	localUDPAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		log.Fatalf("Error resolving local UDP address: %v", err)
	}

	remoteUDPAddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		log.Fatalf("Error resolving remote UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", localUDPAddr)
	if err != nil {
		log.Fatalf("Error listening on UDP: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 1024)
	for {
		n, _, err := conn.ReadFromUDP(buf) // 修正：将 addr 改为 _ ，表示忽略该返回值
		if err != nil {
			log.Println("Error reading from UDP:", err)
			continue
		}

		_, err = conn.WriteToUDP(buf[:n], remoteUDPAddr)
		if err != nil {
			log.Println("Error writing to remote UDP:", err)
			continue
		}
	}
}

func main() {
	localAddr := "127.0.0.1:8080"
	remoteTCPAddr := "your_remote_tcp_address:port"
	remoteUDPAddr := "your_remote_udp_address:port"

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		tcpProxy(localAddr, remoteTCPAddr)
	}()

	go func() {
		defer wg.Done()
		udpProxy(localAddr, remoteUDPAddr)
	}()

	wg.Wait()
}
