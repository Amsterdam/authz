package handler

import "math/rand"

// Characters used for random request identifiers.
const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// Create an opaque token that can be used to store / fetch request params.
func NewRequestId() string {
	reqId := make([]byte, 16)
	for i := range reqId {
		reqId[i] = letters[rand.Int63()%int64(len(letters))]
	}
	return string(reqId)
}
