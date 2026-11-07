package accountmail

import (
	"context"
	"errors"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

type fakeData struct {
	writeErr error
	closeErr error
	short    bool
	closed   bool
}

func TestSMTPValidationBeforeDial(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*SMTP, *string, *string, *string)
	}{
		{"empty address", func(s *SMTP, _, _, _ *string) { s.Addr = "" }},
		{"missing port", func(s *SMTP, _, _, _ *string) { s.Addr = "localhost" }},
		{"missing host", func(s *SMTP, _, _, _ *string) { s.Addr = ":25" }},
		{"missing sender", func(s *SMTP, _, _, _ *string) { s.From = "" }},
		{"sender display", func(s *SMTP, _, _, _ *string) { s.From = "Name <sender@example.org>" }},
		{"sender injection", func(s *SMTP, _, _, _ *string) { s.From += "\r\nBcc: thief@example.org" }},
		{"sender control", func(s *SMTP, _, _, _ *string) { s.From = "a\x00@example.org" }},
		{"bad sender", func(s *SMTP, _, _, _ *string) { s.From = "bad" }},
		{"recipient display", func(_ *SMTP, to, _, _ *string) { *to = "Name <recipient@example.org>" }},
		{"recipient injection", func(_ *SMTP, to, _, _ *string) { *to += "\nBcc: thief@example.org" }},
		{"recipient control", func(_ *SMTP, to, _, _ *string) { *to = "a\t@example.org" }},
		{"bad recipient", func(_ *SMTP, to, _, _ *string) { *to = "bad" }},
		{"empty subject", func(_ *SMTP, _, subject, _ *string) { *subject = "" }},
		{"long subject", func(_ *SMTP, _, subject, _ *string) { *subject = strings.Repeat("я", 201) }},
		{"invalid subject", func(_ *SMTP, _, subject, _ *string) { *subject = "\xff" }},
		{"subject CR", func(_ *SMTP, _, subject, _ *string) { *subject = "one\rtwo" }},
		{"subject LF", func(_ *SMTP, _, subject, _ *string) { *subject = "one\ntwo" }},
		{"subject NUL", func(_ *SMTP, _, subject, _ *string) { *subject = "one\x00two" }},
		{"invalid body", func(_ *SMTP, _, _, body *string) { *body = "\xff" }},
		{"long body", func(_ *SMTP, _, _, body *string) { *body = strings.Repeat("x", 65537) }},
		{"missing password", func(s *SMTP, _, _, _ *string) { s.User = "user" }},
		{"missing user", func(s *SMTP, _, _, _ *string) { s.Password = "password" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s := SMTP{Addr: "localhost:25", From: "sender@example.org"}
			to, subject, body := "recipient@example.org", "Код", "123456"
			tt.change(&s, &to, &subject, &body)
			err := s.Send(context.Background(), to, subject, body)
			var delivery *DeliveryError
			if !errors.As(err, &delivery) || delivery.Stage != "config" || Uncertain(err) {
				t.Fatalf("expected definite validation error: %v", err)
			}
		})
	}
}

func TestMessageMIME(t *testing.T) {
	s := SMTP{Addr: "smtp.example.org:587", From: "sender@example.org"}
	subject, body := strings.Repeat("я", 200), strings.Repeat("я", 32768)
	host, message, err := s.prepare("recipient@example.org", subject, body)
	if err != nil || host != "smtp.example.org" {
		t.Fatalf("prepare: %q %v", host, err)
	}
	m, err := mail.ReadMessage(strings.NewReader(string(message)))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := new(mime.WordDecoder).DecodeHeader(m.Header.Get("Subject"))
	if err != nil || decoded != subject {
		t.Fatalf("subject: %v", err)
	}
	if _, err := time.Parse(time.RFC1123Z, m.Header.Get("Date")); err != nil {
		t.Fatal(err)
	}
	if m.Header.Get("Content-Type") != "text/plain; charset=UTF-8" || m.Header.Get("MIME-Version") != "1.0" {
		t.Fatal("missing MIME headers")
	}
	decodedBody, err := io.ReadAll(quotedprintable.NewReader(m.Body))
	if err != nil || string(decodedBody) != body {
		t.Fatalf("body round trip: %v", err)
	}
}

func TestErrorSanitization(t *testing.T) {
	cause := errors.New("password recipient@example.org")
	for _, stage := range []string{"config", "connect", "greet", "tls", "auth", "mail", "recipient", "data", "write", "accept", "recipient@example.org"} {
		err := &DeliveryError{Stage: stage, cause: cause}
		if strings.Contains(err.Error(), "@") || strings.Contains(err.Error(), "password") {
			t.Fatal("unsafe error")
		}
		if !errors.Is(err, cause) {
			t.Fatal("cause lost")
		}
	}
	if Uncertain(nil) || !Uncertain(cause) {
		t.Fatal("unknown/nil classification")
	}
}

func (d *fakeData) Write(p []byte) (int, error) {
	if d.writeErr != nil || d.short {
		return 1, d.writeErr
	}
	return len(p), nil
}
func (d *fakeData) Close() error { d.closed = true; return d.closeErr }

type fakeSubmission struct {
	data                               fakeData
	mailErr, rcptErr, dataErr, quitErr error
	closed, quit                       bool
}

func (s *fakeSubmission) Mail(string) error             { return s.mailErr }
func (s *fakeSubmission) Rcpt(string) error             { return s.rcptErr }
func (s *fakeSubmission) Data() (io.WriteCloser, error) { return &s.data, s.dataErr }
func (s *fakeSubmission) Quit() error                   { s.quit = true; return s.quitErr }
func (s *fakeSubmission) Close() error                  { s.closed = true; return nil }

func TestSubmissionDeliveryBoundary(t *testing.T) {
	rejected := &textproto.Error{Code: 550, Msg: "secret provider recipient"}
	for _, tt := range []struct {
		name                        string
		s                           fakeSubmission
		stage                       string
		uncertain, dataClosed, quit bool
	}{
		{name: "accepted", dataClosed: true, quit: true},
		{name: "quit does not undo acceptance", s: fakeSubmission{quitErr: io.EOF}, dataClosed: true, quit: true},
		{name: "mail", s: fakeSubmission{mailErr: rejected}, stage: "mail"},
		{name: "recipient", s: fakeSubmission{rcptErr: rejected}, stage: "recipient"},
		{name: "data start", s: fakeSubmission{dataErr: io.EOF}, stage: "data"},
		{name: "partial write", s: fakeSubmission{data: fakeData{writeErr: io.ErrClosedPipe}}, stage: "write", uncertain: true},
		{name: "write rejection", s: fakeSubmission{data: fakeData{writeErr: rejected}}, stage: "write"},
		{name: "short write", s: fakeSubmission{data: fakeData{short: true}}, stage: "write", uncertain: true},
		{name: "final EOF", s: fakeSubmission{data: fakeData{closeErr: io.EOF}}, stage: "accept", uncertain: true, dataClosed: true},
		{name: "final rejection", s: fakeSubmission{data: fakeData{closeErr: rejected}}, stage: "accept", dataClosed: true},
		{name: "temporary rejection", s: fakeSubmission{data: fakeData{closeErr: &textproto.Error{Code: 451, Msg: "secret"}}}, stage: "accept", dataClosed: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := submit(&tt.s, "sender@example.org", "recipient@example.org", []byte("message"))
			if tt.stage == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				var delivery *DeliveryError
				if !errors.As(err, &delivery) || delivery.Stage != tt.stage {
					t.Fatalf("unexpected error: %v", err)
				}
			}
			if Uncertain(err) != tt.uncertain {
				t.Fatalf("uncertain: %v", err)
			}
			if tt.s.data.closed != tt.dataClosed || tt.s.quit != tt.quit || !tt.s.closed {
				t.Fatalf("cleanup: %+v", tt.s)
			}
			if tt.name == "short write" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatal("short write cause lost")
			}
			if tt.name == "mail" && !errors.Is(err, rejected) {
				t.Fatal("cause lost")
			}
		})
	}
}
