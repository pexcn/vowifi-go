package messaging

import "time"

// Subscription identifies the SIM that owns a session, even after a card switch.
type Subscription struct{ DeviceID, IMSI string }

type TPReport struct {
	Reference                            int
	Recipient                            string
	Status                               int
	ServiceCentreTime, DischargeTime, At time.Time
}

// ReliabilityStore is optional. ReserveSMSPart must durably reserve a TP-MR
// before transmission, scoped to the subscription and recipient. SIP results
// must not overwrite later RP/TP evidence. An ambiguous report must not match.
// No method may resend a submission whose outcome is unknown.
type ReliabilityStore interface {
	ReserveSMSPart(Subscription, string, int, string, int, time.Time) (int, error)
	RecordSMSSIPResult(string, int, int, string, time.Time) error
	RecordSMSRPReport(Subscription, string, int, string, int, time.Time) error
	RecordSMSTPReport(Subscription, TPReport) error
}

// TPStatusState preserves the distinction between a confirmed delivery and
// other completed transactions (TS 23.040, TP-Status).
func TPStatusState(status int) string {
	switch {
	case status == 0:
		return "delivered"
	case status > 0 && status <= 2:
		return "completed_unconfirmed"
	case status >= 0x20 && status <= 0x3f:
		return "retrying"
	case status >= 0x40 && status <= 0x7f:
		return "delivery_failed"
	default:
		return "unknown"
	}
}

type InboundFragment struct {
	Key               string
	PartNo, Total     int
	TPDU              []byte
	ServiceCentreTime time.Time
	At                time.Time
}

type InboundAssembly struct {
	ID        string
	Total     int
	Parts     [][]byte // ascending sequence, nil entries are missing parts
	Committed bool
}

// InboundStore must isolate subscriptions, bound stored data, reject conflicting
// duplicates, and retain completed tombstones. CommitInboundSMS atomically saves
// the decoded SMS to host history and marks the assembly committed. Returning
// false means it was already committed. Positive network acknowledgement occurs
// only after these operations succeed. Notification delivery is best effort.
type InboundStore interface {
	SaveInboundFragment(Subscription, InboundFragment) (InboundAssembly, error)
	LoadPendingInboundSMS(Subscription) ([]InboundAssembly, error)
	CommitInboundSMS(Subscription, string, string, string, time.Time) (bool, error)
}
