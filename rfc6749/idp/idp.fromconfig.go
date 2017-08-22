package idp

import (
	"errors"
	"log"
)

// IdPConfig stores configuration indexed by idp_id.
type IdPConfig map[string]interface{}

type IdPMapFromConfig map[string]IdP

func NewIdPMapFromConfig(config IdPConfig) (IdPMapFromConfig, error) {
	cache := make(IdPMapFromConfig)
	var err error
	for idp, idpConfig := range config {
		switch idp {
		case "datapunt":
			cache[idp], err = NewDatapuntIdP(idpConfig)
			if err != nil {
				return nil, err
			}
			log.Println("Added Datapunt IdP")
		default:
			log.Printf("WARNING: Unknown IdP in config: %s\n", idp)
		}
	}
	return cache, nil
}

func (i IdPMapFromConfig) Get(idpId string) (IdP, error) {
	if idp, ok := i[idpId]; ok {
		return idp, nil
	}
	return nil, errors.New("IdP ID not found")
}
