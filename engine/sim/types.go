package sim

import "errors"

var ErrSyncFailure = errors.New("aka sync failure")

type AKAResult struct {
	RES  []byte
	CK   []byte
	IK   []byte
	AUTS []byte
}

type AKAProvider interface {
	CalculateAKA(rand, autn []byte) (AKAResult, error)
}

type IMSIProvider interface {
	GetIMSI() (string, error)
}

type CloseProvider interface {
	Close() error
}

type ISIMAKAProvider interface {
	CalculateISIMAKA(rand, autn []byte) (AKAResult, error)
}

type AKAWithPreferenceProvider interface {
	CalculateAKAWithPreference(rand, autn []byte, preference string) (AKAResult, error)
}
