package storage

type Transient interface {
	Set(key []byte, value []byte, expireIn int) error
	Get(key []byte) ([]byte, error)
}
