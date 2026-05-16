// Package audit writes a structured, append-only operator log.
//
// Every meaningful action (command spawned, file written, IMDS hit,
// dry-run gate skipped) MUST be recorded here. The audit log is the
// primary mechanism that makes IR runs reproducible and reviewable.
//
// Output format is one JSON object per line (NDJSON / JSONL).
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Event is a single audit record.
type Event struct {
	Timestamp time.Time              `json:"ts"`
	Level     string                 `json:"level"`
	Action    string                 `json:"action"`
	Message   string                 `json:"message,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// Logger serializes Events to an io.Writer.
type Logger struct {
	mu       sync.Mutex
	w        io.Writer
	closeFn  func() error
	mirror   io.Writer // optional stderr mirror for human view
}

// NewFileLogger opens path for append and writes JSONL.
// If path is empty, returns a logger that writes only to stderr.
func NewFileLogger(path string, mirrorToStderr bool) (*Logger, error) {
	l := &Logger{}
	if mirrorToStderr {
		l.mirror = os.Stderr
	}
	if path == "" {
		l.w = io.Discard
		return l, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	l.w = f
	l.closeFn = f.Close
	return l, nil
}

func (l *Logger) Close() error {
	if l.closeFn != nil {
		return l.closeFn()
	}
	return nil
}

func (l *Logger) write(level, action, msg string, fields map[string]interface{}) {
	ev := Event{
		Timestamp: time.Now().UTC(),
		Level:     level,
		Action:    action,
		Message:   msg,
		Fields:    fields,
	}
	b, err := json.Marshal(ev)
	if err != nil {
		// Fall back to a synthetic line; never panic from the audit path.
		b = []byte(fmt.Sprintf(`{"ts":%q,"level":"error","action":"audit.marshal","message":%q}`,
			ev.Timestamp.Format(time.RFC3339Nano), err.Error()))
	}
	b = append(b, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = l.w.Write(b)
	if l.mirror != nil {
		_, _ = l.mirror.Write(b)
	}
}

func (l *Logger) Info(action, msg string, fields map[string]interface{}) {
	l.write("info", action, msg, fields)
}

func (l *Logger) Warn(action, msg string, fields map[string]interface{}) {
	l.write("warn", action, msg, fields)
}

func (l *Logger) Error(action, msg string, fields map[string]interface{}) {
	l.write("error", action, msg, fields)
}
