package client

type OAuth20ClientData struct {
	Id        string
	Redirects []string
	Secret    string
}

type OAuth20ClientMap interface {
	Get(id string) (*OAuth20ClientData, error)
}
