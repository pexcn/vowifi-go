// Package e911 implements the observed AT&T TS43 emergency-address bootstrap.
// It obtains a carrier websheet; successful return does not confirm an address.
package e911

import (
	"context"
	"errors"
	"strings"

	"github.com/iniwex5/vowifi-go/engine/sim"
	"github.com/iniwex5/vowifi-go/runtimehost/carrier"
)

var (
	ErrUnsupportedProvider     = errors.New("unsupported e911 provider")
	ErrChallengeNotImplemented = errors.New("e911 cellular challenge unavailable or unsupported")
	ErrWebsheetUnavailable     = errors.New("e911 websheet unavailable")
	ErrIdentityUnavailable     = errors.New("e911 identity unavailable")
)

type HeaderPair struct{ Key, Value string }
type HTTPRequest struct {
	Method, URL string
	Headers     []HeaderPair
	Body        []byte
	// Context carries the operation deadline through HTTPClient adapters. Legacy
	// adapters must preserve it when copying a request.
	Context context.Context
}
type HTTPResponse struct {
	StatusCode int
	Headers    []HeaderPair
	Body       []byte
}
type HTTPClient interface {
	Do(*HTTPRequest) (*HTTPResponse, error)
}

// ContextHTTPClient optionally provides cancellation without request copying.
type ContextHTTPClient interface {
	DoContext(context.Context, *HTTPRequest) (*HTTPResponse, error)
}
type TraceSink interface {
	Request(*HTTPRequest)
	Response(*HTTPRequest, *HTTPResponse)
	Error(*HTTPRequest, error)
}
type Identity struct{ IMSI, IMEI, MCC, MNC, SIPUsername, DisplayName, CachedToken string }
type Request struct {
	Carrier     carrier.EffectiveCarrierConfig
	Identity    Identity
	AKAProvider sim.AKAProvider
	Client      HTTPClient
	Trace       TraceSink
}
type WebsheetRequest struct{ URL, UserData, ContentType, Title string }

func StartEmergencyAddressUpdate(ctx context.Context, req Request) (WebsheetRequest, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return WebsheetRequest{}, err
	}
	cfg := req.Carrier.E911
	// The shipped presets name T-Mobile, but this target contains only an AT&T
	// provider. Do not treat a configured URL as completed entitlement.
	if !cfg.Enabled || strings.TrimSpace(cfg.Provider) != "att_entitlement" {
		return WebsheetRequest{}, ErrUnsupportedProvider
	}
	return startATT(ctx, req)
}
