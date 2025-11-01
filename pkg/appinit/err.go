package appinit

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"time"
)

/*
Using structured logging to report errors is very common and provides rich
information.

Using typical Go 'error' - far less.

This file attempts to bridge the two, by providing a way to create
a structured	error using the same pattern - and objects as slog.

Ideally, slog would provide a way to log this directly - right now it is
calling String().

*/

// NewSlogError returns a structured error - a slog.Record wrapped in an error.
// It can be treated as a record error and pushed to a LogHandler, or used
// directly.
func NewSlogError(kind string, args ...any) error {
	var pcs [1]uintptr
	runtime.Callers(2, pcs[:]) // skip [Callers, Infof]
	r := slog.NewRecord(time.Now(), slog.LevelError, kind, pcs[0])
	r.Add(args...)
	return &RecordError{Record: r}
}

// SlogError is a list of errors, represented as slog.Record objects.
// It implements the 'error' interface, returning a Json Array in the same format as JsonHandler.
// It can also be sent to a LongHandler or slog.Logger directly, resulting on each Record getting
// sent.
type RecordError struct {
	Record slog.Record
}

type RecordList struct {
	Records []slog.Record
}

func (e *RecordError) Unwrap() error {
	return nil
}

func (e *RecordList) Unwrap() []error {
	return nil
}

func (e RecordError) Error() string {
	return fmt.Sprintf("%v", ErrorToMap(&e))
}

func (e *RecordError) Log(logger *slog.Logger) {
	logger.Handler().Handle(context.Background(), e.Record)
}

func (e *RecordList) Log(logger *slog.Logger) {
	for _, r := range e.Records {
		logger.Handler().Handle(context.Background(), r)
	}
}

func (e *RecordError) LogHandle(logger slog.Handler) {
	logger.Handle(context.Background(), e.Record)
}

func (e *RecordList) LogHandle(logger slog.Handler) {
	for _, r := range e.Records {
		logger.Handle(context.Background(), r)
	}
}

func Append(err1 error, err2 error) error {
	return err1
}

func (e *RecordList) Handle(ctx context.Context, r slog.Record) error {
	e.Records = append(e.Records, r)
	return nil
}

func ErrorToMap(err error) map[string]any {
	if r, ok := err.(*RecordError); ok {
		return RecordToMap(&r.Record)
	}
	return map[string]any{"message": err.Error(), "time": time.Now()}
}

func RecordToMap(record *slog.Record) map[string]any {
	attrs := make(map[string]any, record.NumAttrs())
	record.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	attrs["message"] = record.Message
	attrs["time"] = record.Time
	attrs["level"] = record.Level.String()

	if record.PC != 0 {
		// according to comments - must not be passed to runtime.FuncForPC
		f, _ := runtime.CallersFrames([]uintptr{record.PC}).Next()
		attrs["file"] = f.File
		attrs["fun"] = f.Function
	}

	return attrs
}
