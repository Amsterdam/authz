package scope

type FakeScopeSet map[string]struct{}

func NewFakeScopeSet() FakeScopeSet {
	return FakeScopeSet{
		"testA.1": {},
		"testA.2": {},
		"testB.1": {},
		"testB.2": {},
	}
}

func (s FakeScopeSet) Includes(scope string) bool {
	_, ok := s[scope]
	return ok
}
