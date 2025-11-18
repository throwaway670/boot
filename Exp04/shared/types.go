package shared

type Message struct {
	Cnt string
	Ts  int64
}

type HandshakeMessage struct {
	EncryptedDhpk []byte
	Sgn           []byte
}
