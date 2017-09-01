package authz

type EmptyProvider struct {
	ScopeSet
}

func NewEmptyProvider() *EmptyProvider {
	return &EmptyProvider{
		&EmptyScopeSet{},
	}
}

func (p *EmptyProvider) ScopeSetFor(u *User) ScopeSet {
	return p
}

type EmptyScopeSet struct{}

func (s *EmptyScopeSet) ValidScope(scope ...string) bool {
	return false
}
