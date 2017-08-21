package transientstorage

// AuthorizationParams are used throughout the authorization request sequence.
type AuthorizationParams struct {
	// All authorization request params
	ClientId     string
	RedirectURI  string
	ResponseType string
	Scope        []string
	State        string
}

type TransientStorage interface {
	SetAuthorizationParams(id string, params *AuthorizationParams) error
	GetAuthorizationParams(id string) (*AuthorizationParams, error)
	StorageForIdP(idp string) TransientStorageIdP
}

type TransientStorageIdP interface {
	Set(key []byte, value []byte) error
	Get(key []byte) ([]byte, error)
}
