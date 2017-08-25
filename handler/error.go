package handler

import "fmt"

// Error codes
const (
	ERRCODE_INVALID_REQUEST           = "invalid_request"
	ERRCODE_UNAUTHORIZED_CLIENT       = "unauthorized_client"
	ERRCODE_ACCESS_DENIED             = "access_denied"
	ERRCODE_UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type"
	ERRCODE_INVALID_SCOPE             = "invalid_scope"
	ERRCODE_SERVER_ERROR              = "server_error"
	ERRCODE_TEMPORARILY_UNAVAILABLE   = "temporarily_unavailable"
)

type OAuth20Error struct {
	Code        string
	Description string
}

func (e *OAuth20Error) Error() string {
	return fmt.Sprintf("OAuth 2.0 error: %s - %s", e.Code, e.Description)
}
