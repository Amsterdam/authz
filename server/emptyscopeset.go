package server

// emptyScopeSet contains no scopes.
type emptyScopeSet struct{}

// emptyScopeSet returns a refernce to itself for all users.
func (p *emptyScopeSet) ScopeSetFor(u *User) ScopeSet {
	return p
}

// emptyScopeSet contains no valid scopes.
func (s *emptyScopeSet) ValidScope(scope ...string) bool {
	return false
}
