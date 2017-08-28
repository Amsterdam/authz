package scope

import (
	"errors"
	"log"
)

type Set interface {
	Includes(scope string) bool
}

type RemoteSet interface {
	Set
	Close()
}

type ScopeConfig map[string]interface{}

func Load(config ScopeConfig) (Set, error) {
	if len(config) > 1 {
		return nil, errors.New("Only one scope source may be enabled at once")
	}
	for source, _ := range config {
		switch source {
		case "datapunt":
			return NewDatapuntScopeSet(), nil
		default:
			log.Printf("WARNING: ignoring unknown scope source: %s\n", source)
		}
	}
	log.Println("WARNING: Using fake scope source")
	return NewFakeScopeSet(), nil
}
