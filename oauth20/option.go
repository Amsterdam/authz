package oauth20

import "time"

// Option is a handler settings that can be passed to Handler().
type Option func(*oauth20Handler) error

// StateStorage is an option that sets the transient storage for the handler
// instance.
func StateStorage(engine StateKeeper, lifetime time.Duration) Option {
	return func(s *oauth20Handler) error {
		s.stateStore = newStateStorage(engine, lifetime)
		return nil
	}
}

// Clients is an option that sets the given client mapping for the handler
// instance.
func Clients(m ClientMap) Option {
	return func(s *oauth20Handler) error {
		s.clientMap = m
		return nil
	}
}

// AuthzProvider is an option that sets the given authorization provider for
// the handler instance.
func AuthzProvider(p Authz) Option {
	return func(s *oauth20Handler) error {
		s.authz = p
		return nil
	}
}

// AccessTokenConfig is an option that configures access token JWTs.
func AccessTokenConfig(secret []byte, lifetime int64, issuer string) Option {
	return func(s *oauth20Handler) error {
		s.accessTokenEnc = newAccessTokenEncoder(secret, lifetime, issuer)
		return nil
	}
}

// IdProvider is an option that adds the given IdP to this handler. If the IdP was
// already registered it will be silently overwritten.
func IDProvider(i IDP) Option {
	return func(s *oauth20Handler) error {
		s.idps[i.ID()] = i
		return nil
	}
}
