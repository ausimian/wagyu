package main

// A WireGuard handshake transcript from fixed keys, computed step by step as
// section 5.4 of the WireGuard whitepaper describes it, with the primitives
// wireguard-go itself uses. It shares no code with Decibel or Wagyu, so it
// checks Wagyu's framing and Noise parameters independently.

import (
	"crypto/hmac"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	construction   = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
	identifier     = "WireGuard v1 zx2c4 Jason@zx2c4.com"
	labelMAC1      = "mac1----"
	initiatorIndex = 0x11223344
	responderIndex = 0x55667788
)

type vector struct {
	name  string
	value []byte
}

func printVectors(w io.Writer) {
	for _, v := range transcript() {
		fmt.Fprintf(w, "%s %s\n", v.name, hex.EncodeToString(v.value))
	}
}

func transcript() []vector {
	initiatorPrivate, initiatorPublic := keypair("initiator static")
	initiatorEphemeralPrivate, initiatorEphemeral := keypair("initiator ephemeral")
	responderPrivate, responderPublic := keypair("responder static")
	responderEphemeralPrivate, responderEphemeral := keypair("responder ephemeral")

	// TAI64N: the label 2^62 + 10 + Unix seconds, then nanoseconds, which
	// WireGuard rounds down to a multiple of 2^24.
	timestamp := make([]byte, 12)
	binary.BigEndian.PutUint64(timestamp, 0x400000000000000a+1_700_000_000)
	binary.BigEndian.PutUint32(timestamp[8:], 5<<24)

	// Initiation.
	chain := hashOf([]byte(construction))
	h := hashOf(chain, []byte(identifier))
	h = hashOf(h, responderPublic)

	chain = kdf(1, chain, initiatorEphemeral)[0]
	h = hashOf(h, initiatorEphemeral)
	keys := kdf(2, chain, dh(initiatorEphemeralPrivate, responderPublic))
	chain = keys[0]
	encryptedStatic := aead(keys[1], 0, initiatorPublic, h)
	h = hashOf(h, encryptedStatic)
	keys = kdf(2, chain, dh(initiatorPrivate, responderPublic))
	chain = keys[0]
	encryptedTimestamp := aead(keys[1], 0, timestamp, h)
	h = hashOf(h, encryptedTimestamp)

	initiation := header(1)
	initiation = binary.LittleEndian.AppendUint32(initiation, initiatorIndex)
	initiation = append(initiation, initiatorEphemeral...)
	initiation = append(initiation, encryptedStatic...)
	initiation = append(initiation, encryptedTimestamp...)
	initiation = appendMACs(initiation, responderPublic)

	// Response, with the literal zero preshared key.
	chain = kdf(1, chain, responderEphemeral)[0]
	h = hashOf(h, responderEphemeral)
	chain = kdf(1, chain, dh(responderEphemeralPrivate, initiatorEphemeral))[0]
	chain = kdf(1, chain, dh(responderEphemeralPrivate, initiatorPublic))[0]
	keys = kdf(3, chain, make([]byte, 32))
	chain = keys[0]
	h = hashOf(h, keys[1])
	encryptedNothing := aead(keys[2], 0, nil, h)

	response := header(2)
	response = binary.LittleEndian.AppendUint32(response, responderIndex)
	response = binary.LittleEndian.AppendUint32(response, initiatorIndex)
	response = append(response, responderEphemeral...)
	response = append(response, encryptedNothing...)
	response = appendMACs(response, initiatorPublic)

	// Transport keys, and the first message each side sends: an empty
	// keepalive with counter 0, addressed by the other side's index.
	keys = kdf(2, chain, nil)
	initiatorSend, responderSend := keys[0], keys[1]

	return []vector{
		{"initiator_private", initiatorPrivate},
		{"initiator_public", initiatorPublic},
		{"initiator_ephemeral_private", initiatorEphemeralPrivate},
		{"responder_private", responderPrivate},
		{"responder_public", responderPublic},
		{"responder_ephemeral_private", responderEphemeralPrivate},
		{"timestamp", timestamp},
		{"initiation", initiation},
		{"response", response},
		{"initiator_keepalive", keepalive(responderIndex, initiatorSend)},
		{"responder_keepalive", keepalive(initiatorIndex, responderSend)},
	}
}

// A clamped X25519 key pair derived from a label.
func keypair(label string) (private, public []byte) {
	key := blake2s.Sum256([]byte("wagyu golden vector " + label))
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
	public, err := curve25519.X25519(key[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	return key[:], public
}

func dh(private, public []byte) []byte {
	shared, err := curve25519.X25519(private, public)
	if err != nil {
		panic(err)
	}
	return shared
}

func hashOf(parts ...[]byte) []byte {
	h, _ := blake2s.New256(nil)
	for _, part := range parts {
		h.Write(part)
	}
	return h.Sum(nil)
}

func hmacOf(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(func() hash.Hash { h, _ := blake2s.New256(nil); return h }, key)
	for _, part := range parts {
		mac.Write(part)
	}
	return mac.Sum(nil)
}

// KDF_n from the whitepaper: HKDF over HMAC-BLAKE2s.
func kdf(n int, key, input []byte) [][]byte {
	prk := hmacOf(key, input)
	outputs := make([][]byte, 0, n)
	previous := []byte{}
	for i := 1; i <= n; i++ {
		previous = hmacOf(prk, previous, []byte{byte(i)})
		outputs = append(outputs, previous)
	}
	return outputs
}

// ChaCha20-Poly1305 with the 64-bit little-endian counter after four zero bytes.
func aead(key []byte, counter uint64, plaintext, additional []byte) []byte {
	cipher, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	return cipher.Seal(nil, nonce, plaintext, additional)
}

func header(messageType byte) []byte { return []byte{messageType, 0, 0, 0} }

// MAC1 is keyed BLAKE2s-128 over everything before it, keyed with
// HASH("mac1----" || the receiver's public key). MAC2 is zero without a cookie.
func appendMACs(message, receiverPublic []byte) []byte {
	mac, _ := blake2s.New128(hashOf([]byte(labelMAC1), receiverPublic))
	mac.Write(message)
	message = mac.Sum(message)
	return append(message, make([]byte, 16)...)
}

func keepalive(receiver uint32, key []byte) []byte {
	message := header(4)
	message = binary.LittleEndian.AppendUint32(message, receiver)
	message = binary.LittleEndian.AppendUint64(message, 0)
	return append(message, aead(key, 0, nil, nil)...)
}
