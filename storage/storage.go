package storage

type Transient interface {
	Set(key string, value string, expireIn int) error
	Get(key string) (string, error)
}
