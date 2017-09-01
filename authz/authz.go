package authz

import (
	"errors"
	"log"
)

type User struct {
	Uid   string
	Roles []string
}

type ScopeSet interface {
	ValidScope(scope ...string) bool
}

type Provider interface {
	ScopeSet
	ScopeSetFor(u *User) ScopeSet
}

type Config map[string]interface{}

type ProviderConfig map[string]interface{}

func Load(config Config) (Provider, error) {
	if len(config) > 1 {
		return nil, errors.New("You may enable no more than one authorization provider.")
	}
	for provider, providerConfig := range config {
		switch provider {
		case "datapunt":
			return NewDatapuntProvider(providerConfig)
		case "":
			log.Println("WARNING: using empty authorization provider")
		default:
			log.Printf("WARNING: unknown authorization provider: %s\n", provider)
		}
	}
	return &EmptyProvider{}, nil
}
