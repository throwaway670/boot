package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
)

var pkd = &sync.Map{}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	log.Printf("client connected from %s", conn.RemoteAddr())

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		log.Printf("tpe received: %s", line)

		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 1 {
			fmt.Fprintln(conn, "err: invalid command")
			continue
		}
		cmd := parts[0]

		switch cmd {
		case "REGISTER":
			if len(parts) == 3 {
				name, key := parts[1], parts[2]
				pkd.Store(name, key)
				fmt.Fprintf(conn, "ok: registered %s\n", name)
			} else {
				fmt.Fprintln(conn, "err: invalid register")
			}
		case "GET_KEY":
			if len(parts) == 2 {
				name := parts[1]
				key, ok := pkd.Load(name)
				if ok {
					fmt.Fprintln(conn, key)
				} else {
					fmt.Fprintf(conn, "err: key not found for %s\n", name)
				}
			} else {
				fmt.Fprintln(conn, "err: invalid get_key")
			}
		default:
			fmt.Fprintln(conn, "err: unknown command")
		}
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		log.Printf("error reading from client %s: %v", conn.RemoteAddr(), err)
	}
	log.Printf("client disconnected from %s", conn.RemoteAddr())
}

func main() {
	port := 8080
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
	defer listener.Close()
	log.Printf("tpe server started on port %d", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}
