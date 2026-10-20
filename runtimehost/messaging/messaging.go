package messaging

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrSendNotAttempted proves no submission bytes were written. Only this
// classification can be replayed automatically, with an idempotency key.
var ErrSendNotAttempted = errors.New("SMS submission was not attempted")

var ErrDeliveryNotFound = errors.New("sms delivery not found")

// ErrSendOutcomeUnknown means the submission may have reached the network.
// Query its message ID before retrying; automatic replay can duplicate SMS.
var ErrSendOutcomeUnknown = errors.New("SMS submission outcome unknown; query delivery status before retrying")

type SendOptions struct {
	Encoding string `json:"encoding"`
}

type SendOutcome struct {
	MessageID     string `json:"message_id"`
	PartsTotal    int    `json:"parts_total"`
	State         string `json:"state"`
	DeliveryState string `json:"delivery_state"`
}

type USSDResult struct {
	Status    int    `json:"status"`
	RawXML    string `json:"raw_xml,omitempty"`
	DCS       int    `json:"dcs"`
	SessionID string `json:"session_id"`
	Text      string `json:"text"`
	Done      bool   `json:"done"`
}

type DeliveryPartMatch struct {
	MessageID string `json:"message_id"`
	PartNo    int    `json:"part_no"`
	State     string `json:"state"`
}

type DeliveryPartStatus struct {
	TPMR              *int       `json:"tp_mr,omitempty"`
	TPState           string     `json:"tp_state,omitempty"`
	TPStatus          *int       `json:"tp_status,omitempty"`
	ServiceCentreTime *time.Time `json:"service_centre_time,omitempty"`
	DischargeTime     *time.Time `json:"discharge_time,omitempty"`
	PartNo            int        `json:"part_no"`
	CallID            string     `json:"call_id"`
	InReplyTo         string     `json:"in_reply_to"`
	RPMR              int        `json:"rp_mr"`
	State             string     `json:"state"`
	SIPCode           int        `json:"sip_code"`
	RPCause           int        `json:"rp_cause"`
	RPCauseText       string     `json:"rp_cause_text"`
	ErrorText         string     `json:"error_text"`
	SentAt            time.Time  `json:"sent_at"`
	ReportAt          *time.Time `json:"report_at"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type DeliveryStatus struct {
	DeliveryState string               `json:"delivery_state"`
	Delivered     int                  `json:"delivered"`
	ICCID         string               `json:"iccid"`
	MessageID     string               `json:"message_id"`
	IMSI          string               `json:"imsi"`
	DeviceID      string               `json:"device_id"`
	Peer          string               `json:"peer"`
	Content       string               `json:"content"`
	PartsTotal    int                  `json:"parts_total"`
	Acks          int                  `json:"acks"`
	State         string               `json:"state"`
	LastError     string               `json:"last_error"`
	CreatedAt     time.Time            `json:"created_at"`
	UpdatedAt     time.Time            `json:"updated_at"`
	Parts         []DeliveryPartStatus `json:"parts"`
}

type DeliveryStore interface {
	CreateSMSDelivery(messageID, imsi, deviceID, peer, content string, partsTotal int, at time.Time) error
	UpsertSMSDeliveryPart(messageID string, partNo int, callID string, rpMR int, state string, sentAt time.Time) error
	MarkSMSDeliveryPartReport(inReplyTo, callID, deviceID string, rpMR int, state string, sipCode int, rpCause int, errText string, at time.Time) (DeliveryPartMatch, error)
	RecomputeSMSDelivery(messageID string, at time.Time) error
	UpdateSMSDeliveryState(messageID, state, lastError string, acks int, at time.Time) error
	GetSMSDeliveryStatus(messageID string) (*DeliveryStatus, error)
}

func RPCauseText(cause int) string {
	switch cause {
	case 0:
		return ""
	case 1:
		return "unassigned number"
	case 8:
		return "operator determined barring"
	case 10:
		return "call barred"
	case 21:
		return "short message transfer rejected"
	case 27:
		return "destination out of service"
	case 28:
		return "unidentified subscriber"
	case 38:
		return "network out of order"
	case 41:
		return "temporary failure"
	case 42:
		return "congestion"
	case 95:
		return "semantically incorrect message"
	case 96:
		return "invalid mandatory information"
	case 111:
		return "protocol error"
	default:
		return fmt.Sprintf("RP cause %d", cause)
	}
}

type suppressSendTGSuccessKey struct{}

func WithSuppressSendTGSuccess(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, suppressSendTGSuccessKey{}, true)
}

func SuppressSendTGSuccess(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(suppressSendTGSuccessKey{}).(bool)
	return v
}
