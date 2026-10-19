package swu

import "errors"

const DataplaneModeUserspace = "userspace"

var (
	ErrEPDGAddressMissing = errors.New("epdg address missing")
	ErrEPDGResolveFailed  = errors.New("epdg resolve failed")
	ErrProxyConnectFailed = errors.New("epdg proxy connect failed")
)

type ProxyConfig struct {
	ID       string
	Type     string
	Addr     string
	Address  string
	Username string
	Password string
	Enabled  bool
}
