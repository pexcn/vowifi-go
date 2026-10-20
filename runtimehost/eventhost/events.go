package eventhost

import (
	"context"
	"time"
)

type Event interface{}

type Dispatcher interface {
	Dispatch(context.Context, Event)
}

type SMSReceived struct {
	EventID   string // stable durable assembly ID, when available
	IMSI      string
	Persisted bool // host history was committed before network acknowledgement

	DevID   string
	Sender  string
	Content string
	Time    time.Time
}

type SMSSent struct {
	IMSI string

	DevID      string
	TargetURI  string
	Content    string
	Time       time.Time
	TotalParts int
}

type LocalNumberLearned struct {
	DevID  string
	IMSI   string
	Number string
	Source string
	Time   time.Time
}

type LogNotify struct {
	DevID   string
	Message string
	Time    time.Time
}

type ModuleEvent struct {
	DevID   string
	Module  string
	Name    string
	Message string
	Time    time.Time
}
