package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/rsa"
	"encoding/gob"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"chat/crypto_utils"
	"chat/shared"
)

const REKEY_AFTER_MESSAGES = 3

type peer struct {
	nm     string
	prprt  int
	rsakp  *rsa.PrivateKey
	tpeh   string
	tpeprt int

	kr      map[string]*rsa.PublicKey
	krMutex sync.RWMutex

	sks      map[string][]byte
	sksMutex sync.RWMutex

	recvts      map[string]map[int64]bool
	recvtsMutex sync.Mutex

	msgCounts      map[string]int
	msgCountsMutex sync.Mutex
}

func newPeer(n string, pp int, th string, tp int) (*peer, error) {
	rsakp, err := crypto_utils.Genrsakp()
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa key pair: %w", err)
	}
	fmt.Printf("peer %s init\n", n)
	return &peer{
		nm:        n,
		prprt:     pp,
		rsakp:     rsakp,
		tpeh:      th,
		tpeprt:    tp,
		kr:        make(map[string]*rsa.PublicKey),
		sks:       make(map[string][]byte),
		recvts:    make(map[string]map[int64]bool),
		msgCounts: make(map[string]int),
	}, nil
}

func (p *peer) start() error {
	go p.startsrv()
	if err := p.regtpe(); err != nil {
		return fmt.Errorf("could not register with tpe: %w", err)
	}
	p.hndlusrin()
	return nil
}

func (p *peer) startsrv() {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", p.prprt))
	if err != nil {
		log.Fatalf("server error for %s: %v", p.nm, err)
	}
	defer listener.Close()
	fmt.Printf("peer %s listening on port %d\n", p.nm, p.prprt)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept conn: %v", err)
			continue
		}
		go p.hndlconn(conn)
	}
}

func (p *peer) regtpe() error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", p.tpeh, p.tpeprt))
	if err != nil {
		return err
	}
	defer conn.Close()

	pks, err := crypto_utils.Pubktostr(&p.rsakp.PublicKey)
	if err != nil {
		return err
	}

	fmt.Fprintf(conn, "REGISTER %s %s\n", p.nm, pks)
	rsp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	fmt.Printf("tpe reg response: %s", strings.ToLower(rsp))
	if !strings.HasPrefix(rsp, "ok") {
		return fmt.Errorf("tpe reg failed: %s", rsp)
	}
	return nil
}

func (p *peer) getpk(pnm string) (*rsa.PublicKey, error) {
	p.krMutex.RLock()
	pubk, ok := p.kr[pnm]
	p.krMutex.RUnlock()
	if ok {
		return pubk, nil
	}

	fmt.Printf("getting key for %s from tpe...\n", pnm)
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", p.tpeh, p.tpeprt))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	fmt.Fprintf(conn, "GET_KEY %s\n", pnm)
	rsp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return nil, err
	}
	rsp = strings.TrimSpace(rsp)
	if strings.HasPrefix(rsp, "err") {
		return nil, fmt.Errorf("could not get key for %s: %s", pnm, rsp)
	}

	pubk, err = crypto_utils.Strtopubk(rsp)
	if err != nil {
		return nil, err
	}

	p.krMutex.Lock()
	p.kr[pnm] = pubk
	p.krMutex.Unlock()
	fmt.Printf("key for %s stored in local keyring.\n", pnm)
	return pubk, nil
}

func (p *peer) getSessionKey(rcpnm string) ([]byte, bool) {
	p.sksMutex.RLock()
	defer p.sksMutex.RUnlock()
	sk, ok := p.sks[rcpnm]
	return sk, ok
}

func getrcpaddr(n string) (string, error) {
	switch strings.ToLower(n) {
	case "alice":
		return "192.168.1.101:9001", nil //ali
	case "bob":
		return "192.168.1.102:9002", nil // bab
	case "charlie":
		return "192.168.1.103:9003", nil // charlick
	case "david":
		return "192.168.1.104:9004", nil // davie
	default:
		return "", fmt.Errorf("unknown peer: " + n)
	}
}

func (p *peer) dohs(rcpnm string) error {
	fmt.Printf("\n--- initiating handshake with %s ---\n", rcpnm)
	rcppk, err := p.getpk(rcpnm)
	if err != nil {
		return err
	}
	rcpaddr, err := getrcpaddr(rcpnm)
	if err != nil {
		return err
	}
	conn, err := net.Dial("tcp", rcpaddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	encoder := gob.NewEncoder(conn)
	decoder := gob.NewDecoder(conn)
	dhkp, err := crypto_utils.Gendhkp()
	if err != nil {
		return err
	}
	dhpkb := dhkp.PublicKey().Bytes()

	fmt.Printf("   [+] encrypting ephemeral key with %s's public key...\n", rcpnm)
	encryptedDhpk, err := crypto_utils.Encrsa(dhpkb, rcppk)
	if err != nil {
		return fmt.Errorf("could not encrypt dh key: %w", err)
	}
	fmt.Println("   [+] signing ephemeral key with local private key...")
	sgn, err := crypto_utils.Sgn(dhpkb, p.rsakp)
	if err != nil {
		return fmt.Errorf("could not sign dh key: %w", err)
	}
	fmt.Println("   [+] sending handshake message...")
	msg := shared.HandshakeMessage{EncryptedDhpk: encryptedDhpk, Sgn: sgn}
	if err := encoder.Encode("HANDSHAKE"); err != nil {
		return err
	}
	if err := encoder.Encode(p.nm); err != nil {
		return err
	}
	if err := encoder.Encode(msg); err != nil {
		return err
	}
	fmt.Println("   [+] waiting for handshake response...")
	var rspMsg shared.HandshakeMessage
	if err := decoder.Decode(&rspMsg); err != nil {
		return fmt.Errorf("failed to read handshake response: %w", err)
	}
	fmt.Println("   [+] received handshake response.")
	fmt.Println("   [+] decrypting response key with local private key...")
	rcpDhpkb, err := crypto_utils.Decrsa(rspMsg.EncryptedDhpk, p.rsakp)
	if err != nil {
		return fmt.Errorf("failed to decrypt response dh key: %w", err)
	}
	fmt.Println("   [+] verifying signature on response key...")
	if err := crypto_utils.Verifysgn(rcpDhpkb, rspMsg.Sgn, rcppk); err != nil {
		return fmt.Errorf("handshake response signature verify fail: %w", err)
	}
	fmt.Println("       [+] signature verified.")
	curve := ecdh.P256()
	rcpdhpk, err := curve.NewPublicKey(rcpDhpkb)
	if err != nil {
		return fmt.Errorf("invalid recipient dh public key: %w", err)
	}
	fmt.Println("   [+] deriving shared aes key...")
	shsec, err := crypto_utils.Compshsec(dhkp, rcpdhpk)
	if err != nil {
		return err
	}
	ak := crypto_utils.Dervaesk(shsec)
	p.sksMutex.Lock()
	p.sks[rcpnm] = ak
	p.sksMutex.Unlock()
	fmt.Printf("--- handshake with %s complete. secure channel established. ---\n", rcpnm)
	return nil
}

func (p *peer) hndlinchs(sndrnm string, decoder *gob.Decoder, encoder *gob.Encoder) error {
	fmt.Printf("\n--- responding to handshake from %s ---\n", sndrnm)
	sndrpk, err := p.getpk(sndrnm)
	if err != nil {
		return err
	}
	var reqMsg shared.HandshakeMessage
	if err := decoder.Decode(&reqMsg); err != nil {
		return err
	}
	fmt.Println("   [+] received handshake request.")
	fmt.Println("   [+] decrypting ephemeral key with local private key...")
	sndrDhpkb, err := crypto_utils.Decrsa(reqMsg.EncryptedDhpk, p.rsakp)
	if err != nil {
		return fmt.Errorf("failed to decrypt request dh key: %w", err)
	}
	fmt.Printf("   [+] verifying signature from %s...\n", sndrnm)
	if err := crypto_utils.Verifysgn(sndrDhpkb, reqMsg.Sgn, sndrpk); err != nil {
		return fmt.Errorf("handshake request signature verify fail: %w", err)
	}
	fmt.Println("       [+] signature verified.")
	curve := ecdh.P256()
	sndrdhpk, err := curve.NewPublicKey(sndrDhpkb)
	if err != nil {
		return fmt.Errorf("invalid sender dh public key: %w", err)
	}
	fmt.Println("   [+] deriving shared aes key...")
	mydhkp, err := crypto_utils.Gendhkp()
	if err != nil {
		return err
	}
	shsec, err := crypto_utils.Compshsec(mydhkp, sndrdhpk)
	if err != nil {
		return err
	}
	ak := crypto_utils.Dervaesk(shsec)
	p.sksMutex.Lock()
	p.sks[sndrnm] = ak
	p.sksMutex.Unlock()
	fmt.Printf("--- shared key with %s established. ---\n", sndrnm)
	fmt.Println("   [+] preparing and sending handshake response...")
	mydhpkb := mydhkp.PublicKey().Bytes()
	encryptedMyDhpk, err := crypto_utils.Encrsa(mydhpkb, sndrpk)
	if err != nil {
		return err
	}
	mySgn, err := crypto_utils.Sgn(mydhpkb, p.rsakp)
	if err != nil {
		return err
	}
	rspMsg := shared.HandshakeMessage{EncryptedDhpk: encryptedMyDhpk, Sgn: mySgn}
	return encoder.Encode(rspMsg)
}

func (p *peer) sendmsg(rcpnm string, cnt string) error {
	p.msgCountsMutex.Lock()
	p.msgCounts[rcpnm]++
	count := p.msgCounts[rcpnm]
	p.msgCountsMutex.Unlock()

	if cnt != "__CLOSE_NOTIFY__" {
		fmt.Printf("\n--- preparing message for %s (count: %d) ---\n", rcpnm, count)
	}

	if count >= REKEY_AFTER_MESSAGES {
		fmt.Printf("[!] message limit of %d reached with %s. re-keying required.\n", REKEY_AFTER_MESSAGES, rcpnm)
		p.msgCountsMutex.Lock()
		p.msgCounts[rcpnm] = 0
		p.msgCountsMutex.Unlock()
		if err := p.dohs(rcpnm); err != nil {
			return fmt.Errorf("re-keying handshake failed: %w", err)
		}
	}

	sk, ok := p.getSessionKey(rcpnm)
	if !ok {
		if err := p.dohs(rcpnm); err != nil {
			return fmt.Errorf("initial handshake failed: %w", err)
		}
		sk, _ = p.getSessionKey(rcpnm)
	}

	rcpaddr, err := getrcpaddr(rcpnm)
	if err != nil {
		return err
	}
	conn, err := net.Dial("tcp", rcpaddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	encoder := gob.NewEncoder(conn)
	pld := shared.Message{Cnt: cnt, Ts: time.Now().UnixMilli()}
	spld, err := crypto_utils.Ser(pld)
	if err != nil {
		return err
	}

	if cnt != "__CLOSE_NOTIFY__" {
		fmt.Println("   [+] signing message with local private key...")
	}
	sgn, err := crypto_utils.Sgn(spld, p.rsakp)
	if err != nil {
		return err
	}

	if cnt != "__CLOSE_NOTIFY__" {
		fmt.Println("   [+] encrypting message with shared session key...")
	}
	epld, err := crypto_utils.Encaes(spld, sk)
	if err != nil {
		return err
	}

	_ = encoder.Encode("MESSAGE")
	_ = encoder.Encode(p.nm)
	_ = encoder.Encode(epld)
	_ = encoder.Encode(sgn)

	if cnt != "__CLOSE_NOTIFY__" {
		fmt.Println("   [+] secure message sent.")
		fmt.Println("--- end message preparation ---")
	}
	return nil
}

func (p *peer) hndlincmsg(sndrnm string, decoder *gob.Decoder) error {
	sk, ok := p.getSessionKey(sndrnm)
	if !ok {
		return fmt.Errorf("msg from %s but no session key", sndrnm)
	}

	var epld, sgn []byte
	if err := decoder.Decode(&epld); err != nil {
		return err
	}
	if err := decoder.Decode(&sgn); err != nil {
		return err
	}

	dpld, err := crypto_utils.Decaes(epld, sk)
	if err != nil {
		log.Printf("aes decryption failed from %s: %v", sndrnm, err)
		return nil
	}

	sndrpk, err := p.getpk(sndrnm)
	if err != nil {
		return err
	}

	if err := crypto_utils.Verifysgn(dpld, sgn, sndrpk); err != nil {
		log.Printf("warning: invalid signature from %s", sndrnm)
		return nil
	}

	var msg shared.Message
	if err := crypto_utils.Deser(dpld, &msg); err != nil {
		return err
	}

	if msg.Cnt == "__CLOSE_NOTIFY__" {
		fmt.Printf("\n--- user %s has disconnected gracefully. ---\n> ", sndrnm)
		p.sksMutex.Lock()
		delete(p.sks, sndrnm)
		p.sksMutex.Unlock()
		return nil
	}

	fmt.Printf("\n--- new message from %s ---\n", sndrnm)
	fmt.Println("   [+] decrypting message with session key...")
	fmt.Println("       [+] decryption successful.")
	fmt.Println("   [+] verifying digital signature...")
	fmt.Println("       [+] signature verified.")
	fmt.Println("   [+] verifying timestamp for replay protection...")

	p.recvtsMutex.Lock()
	if _, ok := p.recvts[sndrnm]; !ok {
		p.recvts[sndrnm] = make(map[int64]bool)
	}
	if p.recvts[sndrnm][msg.Ts] {
		p.recvtsMutex.Unlock()
		fmt.Println("       [!] warning: replay attack detected (duplicate timestamp)")
		return nil
	}
	p.recvts[sndrnm][msg.Ts] = true
	p.recvtsMutex.Unlock()
	fmt.Println("       [+] timestamp valid.")

	fmt.Printf("\n<%s> %s\n> ", sndrnm, msg.Cnt)
	return nil
}

func (p *peer) hndlconn(conn net.Conn) {
	defer conn.Close()
	decoder := gob.NewDecoder(conn)

	var cmd string
	if err := decoder.Decode(&cmd); err != nil {
		return
	}

	var sndrnm string
	if err := decoder.Decode(&sndrnm); err != nil {
		return
	}

	switch cmd {
	case "HANDSHAKE":
		encoder := gob.NewEncoder(conn)
		if err := p.hndlinchs(sndrnm, decoder, encoder); err != nil {
			log.Printf("failed handshake with %s: %v", sndrnm, err)
		}
	case "MESSAGE":
		if err := p.hndlincmsg(sndrnm, decoder); err != nil {
			log.Printf("failed handling message from %s: %v", sndrnm, err)
		}
	}
}

func (p *peer) hndlusrin() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("commands: send <to> <msg> | broadcast <msg> | exit")

	allPeers := []string{"alice", "bob", "charlie", "david"}

	for {
		fmt.Print("> ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			continue
		}

		if strings.EqualFold(input, "exit") {
			fmt.Println("sending signed 'close notify' messages to all peers...")
			for _, rcpnm := range allPeers {
				if !strings.EqualFold(rcpnm, p.nm) && p.sks[rcpnm] != nil {
					go p.sendmsg(rcpnm, "__CLOSE_NOTIFY__")
				}
			}
			time.Sleep(500 * time.Millisecond)
			fmt.Println("shutting down.")
			os.Exit(0)
			return
		}

		parts := strings.SplitN(input, " ", 2)
		cmd := parts[0]

		if strings.EqualFold(cmd, "broadcast") && len(parts) == 2 {
			msgcnt := parts[1]
			fmt.Printf("broadcasting: %s\n", msgcnt)

			for _, rcpnm := range allPeers {
				if !strings.EqualFold(rcpnm, p.nm) {
					go func(recipient, message string) {
						if err := p.sendmsg(recipient, message); err != nil {
							log.Printf("broadcast fail to %s: %v", recipient, err)
						}
					}(rcpnm, msgcnt)
				}
			}
			continue
		}

		parts = strings.SplitN(input, " ", 3)
		if len(parts) == 3 && strings.EqualFold(parts[0], "send") {
			rcpnm := parts[1]
			msgcnt := parts[2]
			if strings.EqualFold(rcpnm, p.nm) {
				fmt.Println("err: cannot send to self")
				continue
			}
			go func() {
				if err := p.sendmsg(rcpnm, msgcnt); err != nil {
					log.Printf("send fail to %s: %v\n", rcpnm, err)
				}
			}()
		} else {
			fmt.Println("err: invalid command")
		}
	}
}

func main() {
	if len(os.Args) != 5 {
		fmt.Println("usage: go run peer/main.go <name> <port> <tpehost> <tpeport>")
		return
	}
	n := os.Args[1]
	pp, err := strconv.Atoi(os.Args[2])
	if err != nil {
		log.Fatalf("invalid port: %v", err)
	}
	th := os.Args[3]
	tp, err := strconv.Atoi(os.Args[4])
	if err != nil {
		log.Fatalf("invalid tpe port: %v", err)
	}

	p, err := newPeer(n, pp, th, tp)
	if err != nil {
		log.Fatalf("could not create peer: %v", err)
	}

	if err := p.start(); err != nil {
		log.Fatalf("peer exited with error: %v", err)
	}
}
