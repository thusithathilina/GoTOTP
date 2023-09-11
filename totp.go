package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("You need to pass the secret key as the 1st argument.")
		fmt.Println("e.g. totp <secretkey>")
		return
	}
	var key = os.Args[1]
	var timeStep int64 = 30
	var digits int8 = 6

	print(totp(key, timeStep, digits))
}

func totp(key string, timeStep int64, digits int8) string {
	var counter = time.Now().Unix() / timeStep
	return hotp(key, counter, digits)
}

func hotp(key string, count int64, digits int8) string {
	decodeKey, err := base32.StdEncoding.DecodeString(key)
	if err != nil {
		return ""
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(count))

	h := hmac.New(sha1.New, decodeKey)
	h.Write(b)
	var macByte = h.Sum(nil)
	var offset = macByte[len(macByte)-1] & 0x0F

	value := int32(binary.BigEndian.Uint32(macByte[offset:offset+4])) & 0x7FFFFFFF

	stringVal := strconv.Itoa(int(value))
	return stringVal[len(stringVal)-int(digits):]
}
