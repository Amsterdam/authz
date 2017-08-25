package idp

import (
	"errors"
	"log"
)

// IdPConfig stores configuration indexed by idp_id.
type IdPConfig map[string]interface{}

type IdPMap map[string]IdP

func NewIdPMap(config IdPConfig) (IdPMap, error) {
	cache := make(IdPMap)
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

func (i IdPMap) Get(idpId string) (IdP, error) {
	if idp, ok := i[idpId]; ok {
		return idp, nil
	}
	return nil, errors.New("IdP ID not found")
}
